package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// SessionEnder ends every portal session of the installation (sessions.Store).
type SessionEnder interface {
	EndAll(ctx context.Context) (int64, error)
}

// IdentitySessionEnder ends the identity provider's browser sessions of users (Authentik authenticated sessions).
type IdentitySessionEnder interface {
	// CountUserSessions counts the identity provider's browser sessions of users.
	CountUserSessions(ctx context.Context, userPKs []string) (int, error)
	EndUserSessions(ctx context.Context, userPKs []string) (int, error)
}

// PortalUserLister lists the identity provider's users who hold a portal role: the platform admins group and the
// three role groups of every organization (ports.UserDirectory.RoleGroupUsers for each).
type PortalUserLister interface {
	PortalUsers(ctx context.Context) ([]ports.IdentityUser, error)
}

// Privileged actions of the portal sessions (plan M8s decision 16).
var (
	SpecSessionsEndAll    = ActionSpec{Code: audit.CodePlatformSessionsEnded, AllowedRoles: RolesPlatform, RequiresStepUp: true}
	specSessionsEndAllCLI = ActionSpec{Code: audit.CodePlatformSessionsEnded, Actor: &adminActor}
)

// identitySessionChunk is the number of users per bulk delete of identity-provider sessions (plan M8f decision 16).
const identitySessionChunk = 50

// identitySessionBudget bounds the identity-provider part of end all sessions: the HTTP server's write timeout is
// 120 s, and the runner's final transaction may take up to 30 s after it.
const identitySessionBudget = 80 * time.Second

// identitySessionCountBudget bounds the count of the identity-provider sessions before they are ended; the bulk
// deletes get the time the count took on top of identitySessionBudget, so 80 + 5 + 30 s stay below the 120 s write
// timeout (PDK-342).
const identitySessionCountBudget = 5 * time.Second

// Sessions ends portal sessions.
type Sessions struct {
	runner   *ActionRunner
	store    SessionEnder
	users    PortalUserLister
	identity IdentitySessionEnder
	// countBudget is identitySessionCountBudget; tests shorten it.
	countBudget time.Duration
}

// NewSessions creates the use case.
func NewSessions(runner *ActionRunner, store SessionEnder, users PortalUserLister, identity IdentitySessionEnder) *Sessions {
	return &Sessions{runner: runner, store: store, users: users, identity: identity, countBudget: identitySessionCountBudget}
}

// EndAll ends every portal session, the caller's own with its next request, and every identity-provider browser
// session of every portal user, and returns the new generation (audited: platform.sessions_ended, platform
// administrators with a step-up only).
func (s *Sessions) EndAll(ctx context.Context) (int64, error) {
	return s.endAll(ctx, SpecSessionsEndAll)
}

// EndAllCLI is EndAll for paddock-server admin end-sessions: a system principal, for when the portal is not usable.
func (s *Sessions) EndAllCLI(ctx context.Context) (int64, error) {
	return s.endAll(systemPlatform(ctx), specSessionsEndAllCLI)
}

func (s *Sessions) endAll(ctx context.Context, spec ActionSpec) (int64, error) {
	var (
		gen               int64
		genSet            bool
		users, identities = -1, -1
	)
	// The calls to Valkey and Authentik run outside any transaction (RunExternal): the started action is committed
	// first, so a crash in between leaves an action the reaper records as unknown, and no transaction stays open for
	// 1 + 3 × organizations directory calls (plan M8f decision 16, amended 2026-10-18).
	err := s.runner.RunExternal(ctx, ScopePlatform, spec,
		func(context.Context, *pgstore.Queries, Recorder) error { return nil },
		func(ctx context.Context) error {
			var err error
			if gen, err = s.store.EndAll(ctx); err != nil {
				return fmt.Errorf("end sessions: %w", err)
			}
			genSet = true
			// The Paddock sessions are ended already when the identity provider fails (RR-35): the action records the
			// failure and the operator repeats it, which ends the remaining identity-provider sessions.
			if users, identities, err = s.endIdentitySessions(ctx); err != nil {
				return fmt.Errorf("%w: %w", problem.UpstreamUnavailable.WithDetail(
					"the identity provider's sessions could not be ended; end all sessions again"), err)
			}
			return nil
		},
		func(_ context.Context, _ *pgstore.Queries, rec Recorder, _ error) error {
			if genSet {
				rec.SetParam("generation", gen)
			}
			if users >= 0 {
				rec.SetParam("identity_users", users)
			}
			if identities >= 0 {
				rec.SetParam("identity_sessions_ended", identities)
			}
			return nil
		})
	return gen, err
}

// endIdentitySessions ends the identity provider's browser sessions of every portal user, in chunks, within
// identitySessionBudget, and returns the number of listed users (-1 when the listing failed) and of the sessions
// ended so far.
//
// When every chunk is ended, the sessions ended are the larger of the users' sessions counted before and the sum the
// bulk deletes report: a bulk delete repeated after a timeout reports only what its last attempt found left
// (PDK-342). A session that ends between the count and the delete (a logout, an expiry, a concurrent end all) is an
// accepted over-count. The count is best-effort and never takes time from the deletes: it has its own bound, and the
// deletes' deadline moves by the time it took.
func (s *Sessions) endIdentitySessions(ctx context.Context) (users, ended int, err error) {
	deadline := time.Now().Add(identitySessionBudget)
	listCtx, cancelList := context.WithDeadline(ctx, deadline)
	defer cancelList()
	listed, err := s.users.PortalUsers(listCtx)
	if err != nil {
		return -1, -1, fmt.Errorf("list portal users: %w", err)
	}
	pks := make([]string, len(listed))
	for i, u := range listed {
		pks[i] = u.PK
	}
	began := time.Now()
	counted := s.countIdentitySessions(ctx, pks)
	deleteCtx, cancelDelete := context.WithDeadline(ctx, deadline.Add(time.Since(began)))
	defer cancelDelete()
	for start := 0; start < len(pks); start += identitySessionChunk {
		n, err := s.identity.EndUserSessions(deleteCtx, pks[start:min(start+identitySessionChunk, len(pks))])
		ended += n
		if err != nil {
			return len(listed), ended, fmt.Errorf("end identity-provider sessions: %w", err)
		}
	}
	return len(listed), max(counted, ended), nil
}

// countIdentitySessions counts the identity provider's sessions of the users pks within countBudget, 0 when the count
// fails.
func (s *Sessions) countIdentitySessions(ctx context.Context, pks []string) int {
	if len(pks) == 0 {
		return 0
	}
	ctx, cancel := context.WithTimeout(ctx, s.countBudget)
	defer cancel()
	n, err := s.identity.CountUserSessions(ctx, pks)
	if err != nil {
		slog.WarnContext(ctx, "counting the identity provider's sessions before ending them failed; the deletes' count is recorded", "error", err)
		return 0
	}
	return n
}

// PortalUsers lists the identity provider's portal users: the members of the platform admins group and of the role
// groups of every organization, each user once.
type PortalUsers struct {
	platform *db.PlatformPool
	dir      ports.UserDirectory
}

// NewPortalUsers creates the lister.
func NewPortalUsers(platform *db.PlatformPool, dir ports.UserDirectory) *PortalUsers {
	return &PortalUsers{platform: platform, dir: dir}
}

// PortalUsers implements PortalUserLister. A role group that does not exist (an organization whose groups are not
// provisioned yet) is skipped.
func (p *PortalUsers) PortalUsers(ctx context.Context) ([]ports.IdentityUser, error) {
	var slugs []string
	err := p.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		slugs, err = q.ListOrganizationSlugs(ctx)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list organizations: %w", err)
	}
	return portalUsers(ctx, p.dir, slugs)
}

// portalUsers lists the members of the platform admins group and of the role groups of the organizations slugs.
func portalUsers(ctx context.Context, dir ports.UserDirectory, slugs []string) ([]ports.IdentityUser, error) {
	groups := []string{organization.PlatformAdminsGroup()}
	for _, slug := range slugs {
		for _, g := range []organization.GroupRole{organization.GroupAdmins, organization.GroupOperators, organization.GroupAuditors} {
			groups = append(groups, organization.RoleGroup(slug, g))
		}
	}
	seen := map[string]bool{}
	var out []ports.IdentityUser
	for _, g := range groups {
		members, err := dir.RoleGroupUsers(ctx, g)
		if errors.Is(err, ports.ErrGroupNotFound) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("role group %s: %w", g, err)
		}
		for _, m := range members {
			if !seen[m.PK] {
				seen[m.PK] = true
				out = append(out, m)
			}
		}
	}
	return out, nil
}
