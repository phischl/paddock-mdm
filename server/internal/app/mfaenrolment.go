package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/ports"
)

// MFADirectory reads the portal role groups and the second factors of identity provider users and marks them
// (authentik.Client).
type MFADirectory interface {
	// PortalRoleGroupNames lists every group whose direct members hold a portal role by the group's name
	// (organization.IsAdministratorGroup).
	PortalRoleGroupNames(ctx context.Context) ([]string, error)
	// UserAuthenticators reports the kinds of second factor of each user pks, keyed by pk; a user the identity
	// provider does not know is absent.
	UserAuthenticators(ctx context.Context, pks []string) (map[string]ports.Authenticators, error)
	// SetUserAttribute sets the user attribute key to value; nil removes it.
	SetUserAttribute(ctx context.Context, pk, key string, value any) error
}

// MFAEnrolment marks the administrators who may enrol a passkey at their next portal sign-in (ADR 0053 decision 4 as
// amended, plan M12h-2 decision 7 and amendments c and d). Every other administrator without a passkey is denied by the
// sign-in and enrols through a one-time link. Each round that writes a mark is recorded through the ActionRunner as the
// system actor in the platform pseudo-organization.
type MFAEnrolment struct {
	runner   *ActionRunner
	platform *db.PlatformPool
	dir      ports.UserDirectory
	idp      MFADirectory
	now      func() time.Time
}

// NewMFAEnrolment creates the use case.
func NewMFAEnrolment(runner *ActionRunner, platform *db.PlatformPool, dir ports.UserDirectory, idp MFADirectory) *MFAEnrolment {
	return &MFAEnrolment{runner: runner, platform: platform, dir: dir, idp: idp, now: time.Now}
}

// Seed marks every administrator without a passkey with paddock_mfa_enrol_at_login, once.
//
//   - An administrator is a direct member of a group that grants a portal role by its name, the predicate of the
//     sign-in policy paddock-admin-login-webauthn-administrator (organization.IsAdministratorGroup), whether or not an
//     organization of that slug exists. Accounts with only TOTP are marked too: the sign-in's passkey stage denies them
//     otherwise (amendment c point 2).
//   - Only accounts the identity provider created before the first attempt are marked, so a seed repeated after a
//     failed attempt never marks an administrator added after the upgrade.
//   - The seed is recorded as done once the listings and the authenticator reads have succeeded, before the first
//     mark: a mark that fails is not repeated, and that administrator fails closed (denied; a sign-in setup link
//     helps). A failed listing or read records nothing and the next round tries again.
//   - Listings that are all empty count only when the directory probe proves them real (PDK-424); otherwise the seed
//     fails with ErrDirectoryEmpty instead of recording a seed that marked no one.
func (m *MFAEnrolment) Seed(ctx context.Context) error {
	var seeded *time.Time
	if err := m.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		seeded, err = q.GetMfaEnrolmentSeededAt(ctx)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}); err != nil {
		return fmt.Errorf("mfa enrolment seed: %w", err)
	}
	if seeded != nil {
		return nil
	}
	var cutoff time.Time
	if err := m.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		row, err := q.StartMfaEnrolmentSeed(ctx, m.now())
		cutoff = row.FirstAttemptAt
		return err
	}); err != nil {
		return fmt.Errorf("mfa enrolment seed: %w", err)
	}
	admins, orgs, err := m.administrators(ctx)
	if err != nil {
		return fmt.Errorf("mfa enrolment seed: %w", err)
	}
	var candidates []string
	for pk, u := range admins {
		if !u.MFAEnrolAtLogin && !u.Joined.IsZero() && u.Joined.Before(cutoff) {
			candidates = append(candidates, pk)
		}
	}
	slices.Sort(candidates)
	auths, err := m.idp.UserAuthenticators(ctx, candidates)
	if err != nil {
		return fmt.Errorf("mfa enrolment seed: %w", err)
	}
	if err := m.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		return q.MarkMfaEnrolmentSeeded(ctx, m.now())
	}); err != nil {
		return fmt.Errorf("mfa enrolment seed: %w", err)
	}
	marked, totpOnly := 0, 0
	markedOrgs := map[string]bool{}
	var errs []error
	for _, pk := range candidates {
		a, ok := auths[pk]
		if !ok || a.WebAuthn {
			continue
		}
		if err := m.idp.SetUserAttribute(ctx, pk, ports.AttrMFAEnrolAtLogin, true); err != nil {
			slog.WarnContext(ctx, "an administrator without a passkey was not marked and needs a sign-in setup link",
				"username", admins[pk].Username, "error", err)
			errs = append(errs, err)
			continue
		}
		marked++
		if a.TOTP {
			totpOnly++
		}
		for slug := range orgs[pk] {
			markedOrgs[slug] = true
		}
	}
	slog.InfoContext(ctx, "administrators without a passkey marked to enrol one at their next sign-in", "marked", marked,
		"failed", len(errs), "administrators", len(admins))
	failed := errors.Join(errs...)
	if marked > 0 {
		spec := ActionSpec{Code: audit.CodePlatformMFAEnrolMarksSeeded,
			Params: map[string]any{"marked": marked, "totp_only": totpOnly, "organizations": len(markedOrgs)}}
		if err := m.runner.RunTx(ctx, ScopePlatform, spec, func(context.Context, *pgstore.Queries, Recorder) error {
			return failed
		}); err != nil && failed == nil {
			return fmt.Errorf("mfa enrolment seed: %w", err)
		}
	}
	if failed != nil {
		return fmt.Errorf("mfa enrolment seed: %d of %d marks failed: %w", len(errs), marked+len(errs), failed)
	}
	return nil
}

// administrators lists the direct members of every portal role group, keyed by pk, with the slugs of the
// organizations whose role groups they are in.
func (m *MFAEnrolment) administrators(ctx context.Context) (map[string]ports.IdentityUser, map[string]map[string]bool, error) {
	names, err := m.idp.PortalRoleGroupNames(ctx)
	if err != nil {
		return nil, nil, err
	}
	groups := ListRoleGroups(ctx, m.dir, names...)
	admins := map[string]ports.IdentityUser{}
	orgs := map[string]map[string]bool{}
	for _, name := range names {
		members, err := groups.Members(name)
		switch {
		case errors.Is(err, ports.ErrGroupNotFound):
			continue
		case err != nil:
			return nil, nil, err
		}
		slug, _, isOrg := organization.ParseRoleGroup(name)
		for _, u := range members {
			admins[u.PK] = u
			if isOrg {
				if orgs[u.PK] == nil {
					orgs[u.PK] = map[string]bool{}
				}
				orgs[u.PK][slug] = true
			}
		}
	}
	if len(admins) == 0 {
		visible, err := groups.DirectoryVisible(ctx)
		if err != nil {
			return nil, nil, err
		}
		if !visible {
			return nil, nil, ErrDirectoryEmpty
		}
	}
	return admins, orgs, nil
}

// Clear removes paddock_mfa_enrol_at_login from every marked account of members that has a passkey. Unmarked members
// cost no request, so a round without marked administrators reads no devices. A round that removed a mark is recorded;
// a removal that failed is retried by the next round.
func (m *MFAEnrolment) Clear(ctx context.Context, members []ports.IdentityUser) error {
	marked := map[string]ports.IdentityUser{}
	for _, u := range members {
		if u.MFAEnrolAtLogin {
			marked[u.PK] = u
		}
	}
	if len(marked) == 0 {
		return nil
	}
	pks := slices.Sorted(maps.Keys(marked))
	auths, err := m.idp.UserAuthenticators(ctx, pks)
	if err != nil {
		return fmt.Errorf("mfa enrolment clear: %w", err)
	}
	cleared := 0
	var errs []error
	for _, pk := range pks {
		if !auths[pk].WebAuthn {
			continue
		}
		if err := m.idp.SetUserAttribute(ctx, pk, ports.AttrMFAEnrolAtLogin, nil); err != nil {
			errs = append(errs, fmt.Errorf("user %s: %w", marked[pk].Username, err))
			continue
		}
		cleared++
	}
	failed := errors.Join(errs...)
	if cleared > 0 {
		slog.InfoContext(ctx, "enrolment marks of administrators with a passkey removed", "cleared", cleared)
		spec := ActionSpec{Code: audit.CodePlatformMFAEnrolMarksCleared, Params: map[string]any{"cleared": cleared}}
		if err := m.runner.RunTx(ctx, ScopePlatform, spec, func(context.Context, *pgstore.Queries, Recorder) error {
			return failed
		}); err != nil && failed == nil {
			return fmt.Errorf("mfa enrolment clear: %w", err)
		}
	}
	if failed != nil {
		return fmt.Errorf("mfa enrolment clear: %w", failed)
	}
	return nil
}
