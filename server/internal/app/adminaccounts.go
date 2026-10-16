package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/domain/user"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// AdminAccounts follows the administrator accounts of an organization to the identity provider (worker round
// admin-accounts, plan M8s decision 22): an account whose role group changed takes the new role, an account without
// a role or with a deactivated user is disabled; either way every portal session of it ends.
type AdminAccounts struct {
	runner   *ActionRunner
	org      *db.OrgPool
	platform *db.PlatformPool
	dir      ports.UserDirectory
	sessions AccountSessions
}

// AccountSessions counts and ends the portal sessions of an account (sessions.Store).
type AccountSessions interface {
	SessionRevoker
	CountAccount(ctx context.Context, accountID uuid.UUID) (int, error)
}

// NewAdminAccounts creates the use case.
func NewAdminAccounts(runner *ActionRunner, org *db.OrgPool, platform *db.PlatformPool, dir ports.UserDirectory,
	sessions AccountSessions) *AdminAccounts {
	return &AdminAccounts{runner: runner, org: org, platform: platform, dir: dir, sessions: sessions}
}

// ErrDirectoryEmpty fails a round whose role group listings are all empty while accounts are enabled.
var ErrDirectoryEmpty = errors.New("app: empty role group listings")

// directoryUser is what the role group listings say about one user.
type directoryUser struct {
	pk     string
	groups []string
	active bool
	// ambiguous marks a username that two directory users share once normalized: neither decides the account.
	ambiguous bool
}

// Reconcile compares every account of the caller's organization that is not disabled with the members of the
// organization's three role groups (one listing each, never one call per account) and records one
// admin.sessions_revoked per changed account. A failing listing, a missing role group or three empty listings while
// the organization has enabled accounts change nothing and fail the organization's round: a renamed group or a
// service token that may no longer see users must not disable every administrator.
func (a *AdminAccounts) Reconcile(ctx context.Context) error {
	var o pgstore.Organization
	var accounts []pgstore.AdminAccount
	err := a.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		if o, err = q.GetOrganization(ctx, mustOrg(ctx)); err != nil {
			return err
		}
		accounts, err = q.ListAdminAccounts(ctx)
		return err
	})
	if err != nil || o.Status != organization.StatusActive || len(accounts) == 0 {
		return err
	}
	users := map[string]*directoryUser{}
	listed := 0
	for _, g := range []organization.GroupRole{organization.GroupAdmins, organization.GroupOperators, organization.GroupAuditors} {
		name := organization.RoleGroup(o.Slug, g)
		members, err := a.dir.RoleGroupUsers(ctx, name)
		if err != nil {
			return fmt.Errorf("role group %s: %w", name, err)
		}
		listed += len(members)
		// Only the username identifies a member (plan M8s decision 22): users may change their own e-mail address.
		for _, m := range members {
			key := user.NormalizeUsername(m.Username)
			if key == "" {
				continue
			}
			u := users[key]
			switch {
			case u == nil:
				users[key] = &directoryUser{pk: m.PK, groups: []string{name}, active: m.Active}
			case u.pk != m.PK:
				u.ambiguous = true
			default:
				u.groups = append(u.groups, name)
			}
		}
	}
	if listed == 0 {
		return fmt.Errorf("%w: the role groups of %s list no members while %d accounts are enabled", ErrDirectoryEmpty, o.Slug, len(accounts))
	}
	var errs []error
	for _, acc := range accounts {
		u := users[user.NormalizeUsername(acc.Username)]
		if u != nil && u.ambiguous {
			slog.WarnContext(ctx, "administrator account left unchanged: two directory users share its username",
				"account_id", acc.ID)
			continue
		}
		reason, newRole := change(acc, u)
		if reason == "" {
			continue
		}
		spec := ActionSpec{Code: audit.CodeAdminSessionsRevoked, Target: &audit.Target{Type: "admin_account", ID: acc.ID.String()}}
		if err := a.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
			return revokeAccount(ctx, q, rec, a.sessions, acc.ID, reason, newRole)
		}); err != nil {
			errs = append(errs, fmt.Errorf("account %s: %w", acc.ID, err))
		}
	}
	return errors.Join(errs...)
}

// change returns the reason to revoke the sessions of acc and its new role ("" disables it); reason is empty when the
// directory still grants the account's role.
func change(acc pgstore.AdminAccount, u *directoryUser) (reason string, newRole principal.Role) {
	switch {
	case u == nil:
		return RevokeReasonRemoved, ""
	case !u.active:
		return RevokeReasonDeactivated, ""
	}
	res := organization.ResolveRole(u.groups)
	switch {
	case res.Denied || res.Role == "":
		return RevokeReasonRemoved, ""
	case string(res.Role) != acc.Role:
		return RevokeReasonRoleChanged, res.Role
	}
	return "", ""
}

// ReconcilePlatform ends the portal sessions of every platform administrator whom the directory no longer lists, active,
// in paddock.platform.admins (PDK-185). A platform administrator has no account state to change: the next login is
// refused by the groups claim. One admin.sessions_revoked is recorded in the platform pseudo-organization when sessions
// were ended, none when there were none, so a removed administrator is recorded once. A failing listing, a missing
// group or an empty listing while platform administrators exist change nothing.
func (a *AdminAccounts) ReconcilePlatform(ctx context.Context) error {
	var admins []pgstore.PlatformAdmin
	if err := a.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		admins, err = q.ListPlatformAdmins(ctx)
		return err
	}); err != nil || len(admins) == 0 {
		return err
	}
	group := organization.PlatformAdminsGroup()
	members, err := a.dir.RoleGroupUsers(ctx, group)
	if err != nil {
		return fmt.Errorf("role group %s: %w", group, err)
	}
	if len(members) == 0 {
		return fmt.Errorf("%w: %s lists no members while %d platform administrators exist", ErrDirectoryEmpty, group, len(admins))
	}
	users := map[string]*directoryUser{}
	for _, m := range members {
		key := user.NormalizeUsername(m.Username)
		switch u := users[key]; {
		case key == "":
		case u == nil:
			users[key] = &directoryUser{pk: m.PK, groups: []string{group}, active: m.Active}
		case u.pk != m.PK:
			u.ambiguous = true
		}
	}
	var errs []error
	for _, adm := range admins {
		u := users[user.NormalizeUsername(adm.Username)]
		var reason string
		switch {
		case u != nil && u.ambiguous:
			slog.WarnContext(ctx, "platform administrator left unchanged: two directory users share its username", "account_id", adm.ID)
			continue
		case u == nil:
			reason = RevokeReasonRemoved
		case !u.active:
			reason = RevokeReasonDeactivated
		default:
			continue
		}
		if err := a.revokePlatformAdmin(ctx, adm, reason); err != nil {
			errs = append(errs, fmt.Errorf("platform administrator %s: %w", adm.ID, err))
		}
	}
	return errors.Join(errs...)
}

// revokePlatformAdmin ends the sessions of adm and records them; with no session to end nothing is recorded, so a
// removed administrator is recorded once.
func (a *AdminAccounts) revokePlatformAdmin(ctx context.Context, adm pgstore.PlatformAdmin, reason string) error {
	open, err := a.sessions.CountAccount(ctx, adm.ID)
	if err != nil || open == 0 {
		return err
	}
	spec := ActionSpec{
		Code:   audit.CodeAdminSessionsRevoked,
		Target: &audit.Target{Type: "platform_admin", ID: adm.ID.String(), Display: adm.Username},
		Params: map[string]any{"reason": reason, "old_role": string(principal.RolePlatform), "new_role": ""},
	}
	return a.runner.RunTx(ctx, ScopePlatform, spec, func(ctx context.Context, _ *pgstore.Queries, rec Recorder) error {
		// The sessions end inside the event's transaction, as on the organization path: a failing revocation fails the
		// transaction and records the failure, and the next round counts the sessions again and retries. A commit that
		// fails after the revocation leaves the sessions ended (fail safe) and the round reports the error.
		n, err := a.sessions.RevokeAccount(ctx, adm.ID)
		if err != nil {
			return fmt.Errorf("revoke sessions: %w", err)
		}
		rec.SetParam("sessions", n)
		return nil
	})
}
