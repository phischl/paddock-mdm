package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sync"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// RoleGroups is one round's listing of role groups. The rounds admin-accounts and platform-admins list each group once
// and hand the listing to every consumer (AdminAccounts, RoleMembership), so a group is not polled twice per round
// (PDK-111).
type RoleGroups struct {
	dir    ports.UserDirectory
	listed map[string]roleGroupListing
	// probed holds the round's directory probe once it ran, so its consumers ask the identity provider once.
	probed *directoryProbe
}

type directoryProbe struct {
	visible bool
	err     error
}

type roleGroupListing struct {
	members []ports.IdentityUser
	err     error
}

// ListRoleGroups lists every group of names once (ports.UserDirectory.RoleGroupUsers); a failing listing is kept as
// that group's error and does not stop the others.
func ListRoleGroups(ctx context.Context, dir ports.UserDirectory, names ...string) *RoleGroups {
	g := &RoleGroups{dir: dir, listed: make(map[string]roleGroupListing, len(names))}
	for _, name := range names {
		members, err := dir.RoleGroupUsers(ctx, name)
		g.listed[name] = roleGroupListing{members: members, err: err}
	}
	return g
}

// Members returns the listed members of the group name or the error of its listing; a group the round did not list
// is an error, never an empty group.
func (g *RoleGroups) Members(name string) ([]ports.IdentityUser, error) {
	l, ok := g.listed[name]
	if !ok {
		return nil, fmt.Errorf("app: role group %s was not listed this round", name)
	}
	return l.members, l.err
}

// DirectoryVisible proves that listings of the round that came back empty are real (PDK-424, architect decision
// 2026-10-29): every group the round listed without an error is readable by name, and a user listing returns at least
// one user who is not a service account. A service token that lost its view permissions passes the group filter of
// a listing and gets an empty answer, not an error; it fails this probe. The probe runs once per round; a failed read
// is returned as error and proves nothing.
func (g *RoleGroups) DirectoryVisible(ctx context.Context) (bool, error) {
	if g.probed == nil {
		visible, err := g.probe(ctx)
		g.probed = &directoryProbe{visible: visible, err: err}
	}
	return g.probed.visible, g.probed.err
}

func (g *RoleGroups) probe(ctx context.Context) (bool, error) {
	names := slices.Sorted(maps.Keys(g.listed))
	for _, name := range names {
		if g.listed[name].err != nil {
			continue
		}
		readable, err := g.dir.GroupReadable(ctx, name)
		if err != nil {
			return false, fmt.Errorf("probe: read role group %s: %w", name, err)
		}
		if !readable {
			return false, nil
		}
	}
	visible, err := g.dir.UsersVisible(ctx)
	if err != nil {
		return false, fmt.Errorf("probe: list users: %w", err)
	}
	return visible, nil
}

// organizationRoles maps the roles of an organization to the suffixes of the role groups that grant them.
var organizationRoles = []struct {
	role  principal.Role
	group organization.GroupRole
}{
	{principal.RoleOrgAdmin, organization.GroupAdmins},
	{principal.RoleOrgOperator, organization.GroupOperators},
	{principal.RoleOrgAuditor, organization.GroupAuditors},
}

// RoleSuperuser is the role of the identity provider's superusers, who see every organization.
const RoleSuperuser = "authentik_superuser"

// RoleMembership records who holds a Paddock role in the identity provider (plan M8b decision 35, PDK-111): it keeps
// the members of every role group and the superusers as last seen and records every difference as admin.role_granted
// or admin.role_revoked. The first successful comparison of each role records its members as baseline. A read error
// must never look like a revocation: a listing that fails changes nothing for its role; listings that are all empty
// while members are recorded change nothing in the scope unless the directory probe proves them real (an
// organization's role groups, RoleGroups.DirectoryVisible) — an empty superuser listing on the platform is never real;
// and a member is revoked only when two consecutive successful listings miss it (a paged listing can skip a member
// whose page shifted).
type RoleMembership struct {
	runner   *ActionRunner
	org      *db.OrgPool
	platform *db.PlatformPool
	dir      ports.UserDirectory

	mu sync.Mutex
	// unmarked holds the roles ("scope/role") whose last mark transaction failed: a member that reappeared may still be
	// marked missing, so the next miss is not a confirmed one (PDK-423). It lives in this process only; a restart or
	// another worker replica taking the next round does not know it.
	unmarked map[string]bool
}

// NewRoleMembership creates the use case.
func NewRoleMembership(runner *ActionRunner, org *db.OrgPool, platform *db.PlatformPool, dir ports.UserDirectory) *RoleMembership {
	return &RoleMembership{runner: runner, org: org, platform: platform, dir: dir, unmarked: map[string]bool{}}
}

// OrganizationRoleGroups lists the three role groups of the caller's organization; nil when the organization is not
// active, whose role groups are neither followed nor recorded.
func (r *RoleMembership) OrganizationRoleGroups(ctx context.Context) (*RoleGroups, error) {
	var o pgstore.Organization
	if err := r.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		o, err = q.GetOrganization(ctx, mustOrg(ctx))
		return err
	}); err != nil || o.Status != organization.StatusActive {
		return nil, err
	}
	names := make([]string, 0, len(organizationRoles))
	for _, ro := range organizationRoles {
		names = append(names, organization.RoleGroup(o.Slug, ro.group))
	}
	return ListRoleGroups(ctx, r.dir, names...), nil
}

// PlatformRoleGroups lists paddock.platform.admins.
func (r *RoleMembership) PlatformRoleGroups(ctx context.Context) *RoleGroups {
	return ListRoleGroups(ctx, r.dir, organization.PlatformAdminsGroup())
}

// SyncOrganization records the changes of the caller's organization's role groups as listed in groups (active
// organizations only). A missing role group is skipped with a warning; a failing listing skips its role, keeps its rows
// and fails the round. When every listing read is empty while members of those roles are recorded, the directory probe
// (RoleGroups.DirectoryVisible) decides: when it proves the token sees the groups and users, the organization really
// lost its last role holders and the listings are compared as usual, so each one is revoked once two rounds miss it
// (PDK-424); otherwise nothing is recorded and the round fails with ErrDirectoryEmpty (as AdminAccounts.Reconcile). A
// single emptied role is compared as usual. Each role's baseline ends with its own first successful comparison.
func (r *RoleMembership) SyncOrganization(ctx context.Context, groups *RoleGroups) error {
	var o pgstore.Organization
	var stored []pgstore.OrganizationRoleMember
	var taken []string
	if err := r.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		if o, err = q.GetOrganization(ctx, mustOrg(ctx)); err != nil {
			return err
		}
		if stored, err = q.ListOrganizationRoleMembers(ctx); err != nil {
			return err
		}
		taken, err = q.ListOrganizationRoleSnapshots(ctx)
		return err
	}); err != nil || o.Status != organization.StatusActive {
		return err
	}
	scope := roleScope{
		scope: ScopeOrg,
		key:   o.ID.String(),
		tx:    r.org.InOrg,
		write: func(ctx context.Context, q *pgstore.Queries, role string, m roleMember, granted bool) error {
			if granted {
				return q.InsertOrganizationRoleMember(ctx, pgstore.InsertOrganizationRoleMemberParams{
					OrganizationID: o.ID, Role: role, AuthentikPk: m.pk, Username: m.username})
			}
			return q.DeleteOrganizationRoleMember(ctx, pgstore.DeleteOrganizationRoleMemberParams{Role: role, AuthentikPk: m.pk})
		},
		mark: func(ctx context.Context, q *pgstore.Queries, role, pk string, missing bool) error {
			return q.SetOrganizationRoleMemberMissing(ctx, pgstore.SetOrganizationRoleMemberMissingParams{Missing: missing, Role: role, AuthentikPk: pk})
		},
		snapshot: func(ctx context.Context, q *pgstore.Queries, role string) error {
			return q.InsertOrganizationRoleSnapshot(ctx, pgstore.InsertOrganizationRoleSnapshotParams{OrganizationID: o.ID, Role: role})
		},
	}
	listings := make([]roleListing, 0, len(organizationRoles))
	for _, ro := range organizationRoles {
		role, name := string(ro.role), organization.RoleGroup(o.Slug, ro.group)
		l := roleListing{role: role, group: name, baseline: !slices.Contains(taken, role)}
		l.members, l.err = groups.Members(name)
		for _, m := range stored {
			if m.Role == role {
				l.stored = append(l.stored, roleMember{pk: m.AuthentikPk, username: m.Username, missing: m.MissingSince != nil})
			}
		}
		listings = append(listings, l)
	}
	if read, recorded := emptyReads(listings); read > 0 && recorded > 0 {
		visible, err := groups.DirectoryVisible(ctx)
		if err != nil {
			return fmt.Errorf("the role groups of %s list no members while %d are recorded: %w", o.Slug, recorded, err)
		}
		if !visible {
			return fmt.Errorf("%w: the role groups of %s list no members while %d are recorded, and the directory probe "+
				"does not show that the service token sees them", ErrDirectoryEmpty, o.Slug, recorded)
		}
	}
	return r.compareAll(ctx, scope, listings)
}

// roleListing is one role's listing in a round with its stored members.
type roleListing struct {
	role, group string
	members     []ports.IdentityUser
	err         error
	stored      []roleMember
	baseline    bool
}

// emptyReads counts the listings read without error and, when every one of them is empty, the members recorded for
// them; recorded is 0 when any listing read has a member.
func emptyReads(listings []roleListing) (read, recorded int) {
	for _, l := range listings {
		if l.err != nil {
			continue
		}
		if len(l.members) > 0 {
			return read + 1, 0
		}
		read++
		recorded += len(l.stored)
	}
	return read, recorded
}

// compareAll compares every listing; a failing role does not stop the others.
func (r *RoleMembership) compareAll(ctx context.Context, scope roleScope, listings []roleListing) error {
	var errs []error
	for _, l := range listings {
		if ctx.Err() != nil {
			return errors.Join(append(errs, ctx.Err())...)
		}
		errs = append(errs, r.compare(ctx, scope, l))
	}
	return errors.Join(errs...)
}

// SyncPlatform records the changes of paddock.platform.admins as listed in groups (role platform_admin) and of the
// identity provider's superusers (role authentik_superuser, no group) in the platform pseudo-organization; the rules of
// SyncOrganization apply, except that the scope is refused when the superuser listing is empty: an Authentik always
// has a superuser, and an empty answer means the service token can no longer see users.
func (r *RoleMembership) SyncPlatform(ctx context.Context, groups *RoleGroups) error {
	var stored []pgstore.PlatformRoleMember
	var taken []string
	if err := r.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		if stored, err = q.ListPlatformRoleMembers(ctx); err != nil {
			return err
		}
		taken, err = q.ListPlatformRoleSnapshots(ctx)
		return err
	}); err != nil {
		return err
	}
	scope := roleScope{
		scope: ScopePlatform,
		key:   "platform",
		tx:    r.platform.InPlatform,
		write: func(ctx context.Context, q *pgstore.Queries, role string, m roleMember, granted bool) error {
			if granted {
				return q.InsertPlatformRoleMember(ctx, pgstore.InsertPlatformRoleMemberParams{Role: role, AuthentikPk: m.pk, Username: m.username})
			}
			return q.DeletePlatformRoleMember(ctx, pgstore.DeletePlatformRoleMemberParams{Role: role, AuthentikPk: m.pk})
		},
		mark: func(ctx context.Context, q *pgstore.Queries, role, pk string, missing bool) error {
			return q.SetPlatformRoleMemberMissing(ctx, pgstore.SetPlatformRoleMemberMissingParams{Missing: missing, Role: role, AuthentikPk: pk})
		},
		snapshot: func(ctx context.Context, q *pgstore.Queries, role string) error {
			return q.InsertPlatformRoleSnapshot(ctx, role)
		},
	}
	group := organization.PlatformAdminsGroup()
	admins := roleListing{role: string(principal.RolePlatform), group: group, baseline: !slices.Contains(taken, string(principal.RolePlatform))}
	admins.members, admins.err = groups.Members(group)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	supers := roleListing{role: RoleSuperuser, baseline: !slices.Contains(taken, RoleSuperuser)}
	supers.members, supers.err = r.dir.Superusers(ctx)
	if supers.err == nil && len(supers.members) == 0 {
		return fmt.Errorf("%w: the identity provider lists no superuser", ErrDirectoryEmpty)
	}
	listings := []roleListing{admins, supers}
	for i := range listings {
		for _, m := range stored {
			if m.Role == listings[i].role {
				listings[i].stored = append(listings[i].stored, roleMember{pk: m.AuthentikPk, username: m.Username, missing: m.MissingSince != nil})
			}
		}
	}
	return r.compareAll(ctx, scope, listings)
}

// roleMember is a holder of a role as stored; missing is set when the previous successful listing missed it.
type roleMember struct {
	pk, username string
	missing      bool
}

// roleScope is where the members of a role are stored: the organization through the worker pool or the platform
// through the platform pool.
type roleScope struct {
	scope Scope
	// key names the scope's roles in RoleMembership.unmarked.
	key string
	tx  func(ctx context.Context, fn func(ctx context.Context, q *pgstore.Queries) error) error
	// write inserts (granted) or deletes the row of m.
	write    func(ctx context.Context, q *pgstore.Queries, role string, m roleMember, granted bool) error
	mark     func(ctx context.Context, q *pgstore.Queries, role, pk string, missing bool) error
	snapshot func(ctx context.Context, q *pgstore.Queries, role string) error
}

// compare compares the listing of one role with the stored members and records each difference in its own
// transaction: admin.role_granted for a listed user not stored; a stored user the listing misses is marked first and
// admin.role_revoked follows only when the next successful listing misses it again. Users are identified by their pk;
// a renamed user keeps its role and its stored username. A missing group is skipped with a warning; a failing listing
// changes nothing and is returned as error. After a comparison without error the role's snapshot is taken, which ends
// its baseline. When the role's previous mark transaction failed, a stored mark may be stale (the member reappeared
// but its mark was not cleared), so no member is revoked this round; members missed again stay marked.
func (r *RoleMembership) compare(ctx context.Context, s roleScope, l roleListing) error {
	role, group, listed, stored, baseline := l.role, l.group, l.members, l.stored, l.baseline
	switch {
	case errors.Is(l.err, ports.ErrGroupNotFound):
		slog.WarnContext(ctx, "a role group is missing; its membership is not recorded this round", "group", group)
		return nil
	case l.err != nil:
		return fmt.Errorf("role %s: %w", role, l.err)
	}
	have := make(map[string]bool, len(stored))
	for _, m := range stored {
		have[m.pk] = true
	}
	upstream := make(map[string]bool, len(listed))
	var errs []error
	change := func(m roleMember, granted bool) {
		spec := ActionSpec{Code: audit.CodeAdminRoleRevoked, Target: &audit.Target{Type: "identity_user", ID: m.pk, Display: m.username},
			Params: map[string]any{"role": role, "username": m.username, "authentik_pk": m.pk, "group": group}}
		if granted {
			spec.Code = audit.CodeAdminRoleGranted
			spec.Params["baseline"] = baseline
		}
		if err := r.runner.RunTx(ctx, s.scope, spec, func(ctx context.Context, q *pgstore.Queries, _ Recorder) error {
			return s.write(ctx, q, role, m, granted)
		}); err != nil {
			errs = append(errs, fmt.Errorf("%s %s of %s: %w", spec.Code, role, m.pk, err))
		}
	}
	for _, u := range listed {
		if upstream[u.PK] {
			continue
		}
		upstream[u.PK] = true
		if have[u.PK] {
			continue
		}
		// A change not attempted because the round ends must not be recorded as a failed one.
		if ctx.Err() != nil {
			return errors.Join(append(errs, ctx.Err())...)
		}
		change(roleMember{pk: u.PK, username: u.Username}, true)
	}
	key := s.key + "/" + role
	stale := r.unmarkedRole(key)
	var marks []roleMember
	var revoke []roleMember
	for _, m := range stored {
		switch {
		case upstream[m.pk] && m.missing, !upstream[m.pk] && !m.missing:
			marks = append(marks, m)
		case !upstream[m.pk] && !stale:
			revoke = append(revoke, m)
		}
	}
	var markErr error
	if len(marks) > 0 {
		markErr = s.tx(ctx, func(ctx context.Context, q *pgstore.Queries) error {
			for _, m := range marks {
				if err := s.mark(ctx, q, role, m.pk, !m.missing); err != nil {
					return err
				}
			}
			return nil
		})
		if markErr != nil {
			errs = append(errs, fmt.Errorf("role %s: mark missing members: %w", role, markErr))
		}
	}
	r.setUnmarkedRole(key, markErr != nil)
	for _, m := range revoke {
		if ctx.Err() != nil {
			return errors.Join(append(errs, ctx.Err())...)
		}
		change(m, false)
	}
	if err := errors.Join(errs...); err != nil || !baseline {
		return err
	}
	return s.tx(ctx, func(ctx context.Context, q *pgstore.Queries) error { return s.snapshot(ctx, q, role) })
}

func (r *RoleMembership) unmarkedRole(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.unmarked[key]
}

func (r *RoleMembership) setUnmarkedRole(key string, failed bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if failed {
		r.unmarked[key] = true
	} else {
		delete(r.unmarked, key)
	}
}
