package app

import (
	"context"
	"errors"
	"fmt"

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

// Sessions ends portal sessions.
type Sessions struct {
	runner   *ActionRunner
	store    SessionEnder
	users    PortalUserLister
	identity IdentitySessionEnder
}

// NewSessions creates the use case.
func NewSessions(runner *ActionRunner, store SessionEnder, users PortalUserLister, identity IdentitySessionEnder) *Sessions {
	return &Sessions{runner: runner, store: store, users: users, identity: identity}
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
	var gen int64
	err := s.runner.RunTx(ctx, ScopePlatform, spec, func(ctx context.Context, _ *pgstore.Queries, rec Recorder) error {
		var err error
		if gen, err = s.store.EndAll(ctx); err != nil {
			return fmt.Errorf("end sessions: %w", err)
		}
		rec.SetParam("generation", gen)
		// The Paddock sessions are ended already when the identity provider fails (RR-35): the action records the
		// failure and the operator repeats it, which ends the remaining identity-provider sessions.
		if err := s.endIdentitySessions(ctx, rec); err != nil {
			return fmt.Errorf("%w: %w", problem.UpstreamUnavailable.WithDetail(
				"the identity provider's sessions could not be ended; end all sessions again"), err)
		}
		return nil
	})
	return gen, err
}

// endIdentitySessions ends the identity provider's browser sessions of every portal user, in chunks.
func (s *Sessions) endIdentitySessions(ctx context.Context, rec Recorder) error {
	users, err := s.users.PortalUsers(ctx)
	if err != nil {
		return fmt.Errorf("list portal users: %w", err)
	}
	rec.SetParam("identity_users", len(users))
	pks := make([]string, len(users))
	for i, u := range users {
		pks[i] = u.PK
	}
	ended := 0
	for start := 0; start < len(pks); start += identitySessionChunk {
		n, err := s.identity.EndUserSessions(ctx, pks[start:min(start+identitySessionChunk, len(pks))])
		ended += n
		rec.SetParam("identity_sessions_ended", ended)
		if err != nil {
			return fmt.Errorf("end identity-provider sessions: %w", err)
		}
	}
	rec.SetParam("identity_sessions_ended", ended)
	return nil
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
