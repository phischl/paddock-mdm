package app

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/device"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/domain/statechange"
	"github.com/phischl/paddock-mdm/server/internal/domain/user"
	"github.com/phischl/paddock-mdm/server/internal/domain/usergroup"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// IdentitySync keeps Paddock and Authentik in step for the worker (plan M3a decisions 2, 3, 5 and 9): synced users
// and mirrored group members every sync round, the organization's Authentik objects and the per-device login
// groups every reconcile round. The context carries a system principal of the organization.
type IdentitySync struct {
	runner *ActionRunner
	org    *db.OrgPool
	idp    ports.IdentityProvider
	users  ports.UserDirectory
	groups ports.GroupDirectory
	// revision is the identity provider's ensure revision; empty disables the ensure cache (every round ensures).
	revision string
}

// NewIdentitySync creates the use cases.
func NewIdentitySync(runner *ActionRunner, org *db.OrgPool, idp ports.IdentityProvider, users ports.UserDirectory,
	groups ports.GroupDirectory) *IdentitySync {
	return &IdentitySync{runner: runner, org: org, idp: idp, users: users, groups: groups}
}

// WithEnsureRevision enables the ensure cache of the reconcile round (plan M17 decision 20) with the revision of what
// the identity provider's EnsureOrganization creates or corrects (authentik.EnsureRevision).
func (s *IdentitySync) WithEnsureRevision(revision string) *IdentitySync {
	s.revision = revision
	return s
}

// IdentityFullEnsureInterval is how long a successful ensure of an organization's identity provider objects stands
// before the reconcile round checks them in full again, plus the organization's IdentityEnsureJitter (plan M17
// decision 20).
const IdentityFullEnsureInterval = 6 * time.Hour

// IdentityEnsureJitter is the organization's fixed share of the hour over which the full checks of all organizations
// spread: the first eight bytes of its ID as uint64 modulo 3600, in seconds.
func IdentityEnsureJitter(id uuid.UUID) time.Duration {
	return time.Duration(binary.BigEndian.Uint64(id[:8])%3600) * time.Second
}

// IdentityEnsureDue reports whether the reconcile round has to ensure the organization's identity provider objects at
// now: when they were never ensured or the mark was cleared (creation, domain change, error), when they were ensured
// by another revision, or when the last ensure is IdentityFullEnsureInterval plus the jitter ago. An empty revision
// means no cache: always due.
func IdentityEnsureDue(o pgstore.Organization, revision string, now time.Time) bool {
	return revision == "" || o.IdpEnsuredAt == nil || o.IdpEnsureRevision == nil || *o.IdpEnsureRevision != revision ||
		now.Sub(*o.IdpEnsuredAt) >= IdentityFullEnsureInterval+IdentityEnsureJitter(o.ID)
}

// Specs of the synchronization events (actor: system).
var (
	SpecUserSyncedAdded   = ActionSpec{Code: audit.CodeUserSyncedAdded}
	SpecUserSyncedRemoved = ActionSpec{Code: audit.CodeUserSyncedRemoved}
)

// ErrUsernameConflict means a synced user's username is already used by a user of another organization; the user is
// skipped (the caller should not retry it every round).
var ErrUsernameConflict = errors.New("app: synced username belongs to another organization")

// activeOrganization returns the organization of ctx if it is active.
func (s *IdentitySync) activeOrganization(ctx context.Context) (pgstore.Organization, bool, error) {
	var o pgstore.Organization
	err := s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		o, err = q.GetOrganization(ctx, mustOrg(ctx))
		return err
	})
	return o, err == nil && o.Status == organization.StatusActive, err
}

// SyncUsers mirrors the synced users of the organization: direct members of paddock.<slug> without
// paddock_managed. New ones are added (user.synced_added), vanished ones removed with their memberships and
// assignments (user.synced_removed), upstream attribute changes copied. skip reports usernames to leave out (known
// conflicts); conflicts found now are returned.
func (s *IdentitySync) SyncUsers(ctx context.Context, skip func(username string) bool) (conflicts []string, err error) {
	o, active, err := s.activeOrganization(ctx)
	if err != nil || !active {
		return nil, err
	}
	upstream, err := s.users.OrganizationUsers(ctx, o.Slug)
	if err != nil {
		if o.IdpEnsuredAt != nil {
			err = errors.Join(err, s.forgetEnsured(ctx, o.ID))
		}
		return nil, err
	}
	var known []pgstore.AppUser
	if err := s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		known, err = q.ListAllAppUsers(ctx)
		return err
	}); err != nil {
		return nil, err
	}
	byPK := map[string]pgstore.AppUser{}
	for _, u := range known {
		byPK[u.AuthentikPk] = u
	}
	seen := map[string]bool{}
	var errs []error
	for _, iu := range upstream {
		if iu.Managed {
			continue
		}
		seen[iu.PK] = true
		username := user.NormalizeUsername(iu.Username)
		cur, ok := byPK[iu.PK]
		switch {
		case ok && cur.Source == user.SourceSynced && (cur.Username != username || cur.DisplayName != iu.Name || cur.Email != iu.Email):
			errs = append(errs, s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
				// The username is the natural key of the user's assignments in the declarative document.
				if err := q.LockConfigApply(ctx); err != nil {
					return err
				}
				return q.UpdateSyncedAppUser(ctx, pgstore.UpdateSyncedAppUserParams{ID: cur.ID, Username: username, DisplayName: iu.Name, Email: iu.Email})
			}))
		case !ok && !skip(username):
			err := s.addSynced(ctx, o.ID, iu, username)
			if errors.Is(err, ErrUsernameConflict) {
				conflicts = append(conflicts, username)
				continue
			}
			errs = append(errs, err)
		}
	}
	for _, u := range known {
		if u.Source == user.SourceSynced && !seen[u.AuthentikPk] {
			errs = append(errs, s.removeSynced(ctx, u))
		}
	}
	return conflicts, errors.Join(errs...)
}

// addSynced records a new synced user. A username that a user of another organization already has (invisible here,
// RLS) fails as username_taken; the failure is audited and reported as ErrUsernameConflict.
func (s *IdentitySync) addSynced(ctx context.Context, org uuid.UUID, iu ports.IdentityUser, username string) error {
	spec := SpecUserSyncedAdded
	spec.Params = map[string]any{"username": username}
	err := s.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		u, err := q.InsertAppUser(ctx, pgstore.InsertAppUserParams{
			ID: uuid.Must(uuid.NewV7()), OrganizationID: org, AuthentikPk: iu.PK, Username: username,
			DisplayName: iu.Name, Email: iu.Email, Source: user.SourceSynced,
		})
		if db.IsUniqueViolation(err, "") {
			return problem.UsernameTaken.WithDetail("the username belongs to a user of another organization")
		}
		if err != nil {
			return err
		}
		rec.SetTarget(audit.Target{Type: "user", ID: u.ID.String(), Display: username})
		rec.StateChanged(statechange.ScopeOrg, org)
		return nil
	})
	if errors.Is(err, problem.UsernameTaken) {
		slog.WarnContext(ctx, "synced user skipped: the username exists in another organization", "username", username)
		return ErrUsernameConflict
	}
	return err
}

func (s *IdentitySync) removeSynced(ctx context.Context, u pgstore.AppUser) error {
	spec := SpecUserSyncedRemoved
	spec.Target = &audit.Target{Type: "user", ID: u.ID.String(), Display: u.Username}
	spec.Params = map[string]any{"username": u.Username}
	return s.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		return removeUser(ctx, q, rec, u.ID)
	})
}

// SyncGroupMirrors copies the members of every imported upstream group that are users of the organization into its
// mirror group, in Paddock (user_group.member_added/removed, actor system) and in Authentik.
func (s *IdentitySync) SyncGroupMirrors(ctx context.Context) error {
	if _, active, err := s.activeOrganization(ctx); err != nil || !active {
		return err
	}
	var groups []pgstore.UserGroup
	var users map[string]uuid.UUID
	err := s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		if groups, err = q.ListAllUserGroups(ctx); err != nil {
			return err
		}
		users, err = usersByAuthentikPK(ctx, q)
		return err
	})
	if err != nil {
		return err
	}
	var errs []error
	for _, g := range groups {
		if g.Source == usergroup.SourceSynced && g.UpstreamAuthentikPk != nil && g.AuthentikPk != "" {
			errs = append(errs, s.mirror(ctx, g, users))
		}
	}
	return errors.Join(errs...)
}

func (s *IdentitySync) mirror(ctx context.Context, g pgstore.UserGroup, users map[string]uuid.UUID) error {
	pks, err := s.groups.GroupMembers(ctx, *g.UpstreamAuthentikPk)
	if err != nil {
		return fmt.Errorf("group %s: %w", g.Slug, err)
	}
	var want []uuid.UUID
	var wantPKs []string
	for _, pk := range pks {
		if u, ok := users[pk]; ok {
			want = append(want, u)
			wantPKs = append(wantPKs, pk)
		}
	}
	var have []uuid.UUID
	if err := s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		have, err = q.ListUserGroupMemberIDs(ctx, g.ID)
		return err
	}); err != nil {
		return err
	}
	var errs []error
	for _, u := range want {
		if !slices.Contains(have, u) {
			errs = append(errs, s.mirrorChange(ctx, SpecUserGroupMemberAdd, g, u, true))
		}
	}
	for _, u := range have {
		if !slices.Contains(want, u) {
			errs = append(errs, s.mirrorChange(ctx, SpecUserGroupMemberRemove, g, u, false))
		}
	}
	errs = append(errs, SyncMembers(ctx, s.groups, g.AuthentikPk, wantPKs))
	return errors.Join(errs...)
}

func (s *IdentitySync) mirrorChange(ctx context.Context, spec ActionSpec, g pgstore.UserGroup, userID uuid.UUID, add bool) error {
	spec.Target = &audit.Target{Type: "user_group", ID: g.ID.String(), Display: g.Name}
	return s.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		u, err := q.GetAppUser(ctx, userID)
		if err != nil {
			return err
		}
		rec.SetParam("group", g.Slug)
		rec.SetParam("user", u.Username)
		if err := recordMembershipChange(ctx, q, rec, g, userID, add); err != nil {
			return err
		}
		rec.StateChanged(statechange.ScopeOrg, g.OrganizationID)
		return nil
	})
}

// Reconcile re-creates or corrects the organization's Authentik objects (groups, device login application) when
// IdentityEnsureDue, and the per-device login groups every round: members equal to the directly assigned users,
// deleted for devices without them and for retired devices. A failed round clears the ensure mark.
func (s *IdentitySync) Reconcile(ctx context.Context) error {
	o, active, err := s.activeOrganization(ctx)
	if err != nil || !active {
		return err
	}
	if err := s.reconcile(ctx, o); err != nil {
		if s.revision == "" {
			return err
		}
		// The failure may come from an object the mark vouches for (drift, an Authentik restored from a backup), so
		// the next round checks everything again. The round may have set the mark itself, hence no check of o.
		return errors.Join(err, s.forgetEnsured(ctx, o.ID))
	}
	return nil
}

// forgetEnsured clears the organization's ensure mark, so the next reconcile round ensures its objects.
func (s *IdentitySync) forgetEnsured(ctx context.Context, org uuid.UUID) error {
	err := s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		return q.ClearOrganizationIdentityEnsured(ctx, org)
	})
	if err != nil {
		return fmt.Errorf("clear the identity ensure mark: %w", err)
	}
	return nil
}

func (s *IdentitySync) reconcile(ctx context.Context, o pgstore.Organization) error {
	if IdentityEnsureDue(o, s.revision, time.Now()) {
		if _, err := s.idp.EnsureOrganization(ctx, o.Slug); err != nil {
			return err
		}
		if s.revision != "" {
			if err := s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
				return q.MarkOrganizationIdentityEnsured(ctx, pgstore.MarkOrganizationIdentityEnsuredParams{
					ID: o.ID, Revision: &s.revision, SeenUpdatedAt: o.UpdatedAt})
			}); err != nil {
				return fmt.Errorf("mark the identity objects ensured: %w", err)
			}
		}
	}
	type target struct {
		device  uuid.UUID
		members []string
	}
	var targets []target
	err := s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		id, err := LoadIdentity(ctx, q)
		if err != nil {
			return err
		}
		devices := map[uuid.UUID]bool{}
		for _, a := range id.allLoginDevices() {
			devices[a] = true
		}
		for d := range devices {
			dev, err := q.GetDevice(ctx, d)
			if err != nil {
				return err
			}
			users, _ := id.LoginAssignment(d)
			t := target{device: d}
			if dev.State != device.StateRetired && dev.State != device.StateRejected {
				for _, u := range users {
					t.members = append(t.members, id.Users[u].AuthentikPk)
				}
			}
			targets = append(targets, t)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return nil
	}
	// One listing of every device login group replaces a lookup and a member listing per device (PDK-570). A listing
	// that fails changes no group: a partial view must never read as members to remove.
	listed, err := s.groups.DeviceLoginGroups(ctx, o.Slug)
	if err != nil {
		return fmt.Errorf("list the device login groups: %w", err)
	}
	var errs []error
	for _, t := range targets {
		errs = append(errs, syncListedDeviceLoginGroup(ctx, s.groups, o.Slug, t.device, t.members, listed))
	}
	return errors.Join(errs...)
}

// syncListedDeviceLoginGroup is SyncDeviceLoginGroup with the group as listed: a listed group is compared with its
// listed members and deleted by its pk; a group the listing does not have does not exist, so it is created as before
// when the device has members and left alone otherwise.
func syncListedDeviceLoginGroup(ctx context.Context, dir ports.GroupDirectory, slug string, deviceID uuid.UUID, members []string,
	listed map[string]ports.IdentityGroupMembers) error {
	g, ok := listed[organization.DeviceLoginGroup(slug, deviceID)]
	switch {
	case !ok && len(members) == 0:
		return nil
	case !ok:
		return SyncDeviceLoginGroup(ctx, dir, slug, deviceID, members)
	case len(members) == 0:
		return dir.DeleteGroup(ctx, g.PK)
	}
	return applyMembers(ctx, dir, g.PK, g.Members, members)
}

// allLoginDevices returns every device with a login assignment.
func (id *Identity) allLoginDevices() []uuid.UUID {
	out := make([]uuid.UUID, 0, len(id.logins))
	for d := range id.logins {
		out = append(out, d)
	}
	return out
}
