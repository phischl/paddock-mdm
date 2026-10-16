package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

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
	dir      ports.UserDirectory
	sessions SessionRevoker
}

// NewAdminAccounts creates the use case.
func NewAdminAccounts(runner *ActionRunner, org *db.OrgPool, dir ports.UserDirectory, sessions SessionRevoker) *AdminAccounts {
	return &AdminAccounts{runner: runner, org: org, dir: dir, sessions: sessions}
}

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
// admin.sessions_revoked per changed account. A failing listing changes nothing.
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
	for _, g := range []organization.GroupRole{organization.GroupAdmins, organization.GroupOperators, organization.GroupAuditors} {
		name := organization.RoleGroup(o.Slug, g)
		members, err := a.dir.RoleGroupUsers(ctx, name)
		if err != nil {
			return fmt.Errorf("role group %s: %w", name, err)
		}
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
