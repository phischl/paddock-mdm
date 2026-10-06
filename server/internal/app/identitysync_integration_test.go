package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// directory is an in-memory identity provider (organization users, groups and members).
type directory struct {
	mu      sync.Mutex
	users   []ports.IdentityUser
	groups  map[string]string   // pk → name
	members map[string][]string // group pk → user pks
	fail    error
}

func newDirectory() *directory {
	return &directory{groups: map[string]string{}, members: map[string][]string{}}
}

func (d *directory) EnsureOrganization(context.Context, string) (ports.OrgIdentityRefs, error) {
	return ports.OrgIdentityRefs{}, d.fail
}
func (d *directory) CreateUser(context.Context, string, ports.NewIdentityUser) (string, error) {
	return "", errors.New("not used")
}
func (d *directory) UpdateUser(context.Context, string, string, string) error { return nil }
func (d *directory) DeleteUser(context.Context, string) error                 { return nil }
func (d *directory) RecoveryLink(context.Context, string) (string, error)     { return "", nil }
func (d *directory) UserActive(context.Context, string) (bool, error)         { return true, d.fail }
func (d *directory) LockUser(context.Context, string, string, bool) error     { return d.fail }
func (d *directory) UnlockUser(context.Context, string, string, bool) error   { return d.fail }
func (d *directory) OrganizationUsers(context.Context, string) ([]ports.IdentityUser, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.users), d.fail
}
func (d *directory) EnsureGroup(_ context.Context, _, name string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for pk, n := range d.groups {
		if n == name {
			return pk, nil
		}
	}
	pk := "g-" + uuid.NewString()
	d.groups[pk] = name
	return pk, nil
}
func (d *directory) FindGroup(_ context.Context, name string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for pk, n := range d.groups {
		if n == name {
			return pk, nil
		}
	}
	return "", nil
}
func (d *directory) DeleteGroup(_ context.Context, pk string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.groups, pk)
	delete(d.members, pk)
	return nil
}
func (d *directory) AddMember(_ context.Context, g, u string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !slices.Contains(d.members[g], u) {
		d.members[g] = append(d.members[g], u)
	}
	return nil
}
func (d *directory) RemoveMember(_ context.Context, g, u string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.members[g] = slices.DeleteFunc(d.members[g], func(x string) bool { return x == u })
	return nil
}
func (d *directory) GroupMembers(_ context.Context, g string) ([]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.members[g]), nil
}
func (d *directory) UpstreamGroups(context.Context, string) ([]ports.IdentityGroup, error) {
	return nil, nil
}

// syncHarness runs the identity sync with the worker's database role, as the worker does.
type syncHarness struct {
	harness
	sync *app.IdentitySync
	dir  *directory
	slug string
}

func newSyncHarness(t *testing.T) syncHarness {
	t.Helper()
	h := newHarness(t)
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	worker, err := db.NewOrgPool(ctx, env.Worker, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(worker.Close)
	platform, err := db.NewPlatformPool(ctx, env.Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	runner := app.NewActionRunner(worker, platform, func(context.Context) string { return "corr-" + t.Name() })
	dir := newDirectory()
	s := syncHarness{harness: h, sync: app.NewIdentitySync(runner, worker, dir, dir, dir), dir: dir}
	if err := h.super.QueryRow(ctx, "SELECT slug FROM organization WHERE id = $1", h.org).Scan(&s.slug); err != nil {
		t.Fatal(err)
	}
	return s
}

func (s syncHarness) system() context.Context {
	return principal.With(context.Background(), principal.Principal{Kind: principal.KindSystem, Display: "worker", OrganizationID: s.org})
}

func (s syncHarness) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := s.super.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (s syncHarness) events(t *testing.T, code string) []string {
	t.Helper()
	rows, err := s.super.Query(context.Background(),
		"SELECT outcome || ':' || coalesce(error_code, '') || ':' || (actor->>'type') FROM action WHERE organization_id = $1 AND code = $2 ORDER BY started_at",
		s.org, code)
	if err != nil {
		t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSyncUsers(t *testing.T) {
	s := newSyncHarness(t)
	suffix := s.org.String()[24:]
	erin := ports.IdentityUser{PK: "e" + suffix, Username: "Erin@up-" + suffix + ".test", Name: "Erin"}
	frank := ports.IdentityUser{PK: "f" + suffix, Username: "frank@up-" + suffix + ".test", Name: "Frank"}
	managed := ports.IdentityUser{PK: "m" + suffix, Username: "dave@up-" + suffix + ".test", Managed: true}
	s.dir.users = []ports.IdentityUser{erin, frank, managed}
	none := func(string) bool { return false }

	if conflicts, err := s.sync.SyncUsers(s.system(), none); err != nil || len(conflicts) != 0 {
		t.Fatalf("first round: %v %v", conflicts, err)
	}
	if n := s.count(t, "SELECT count(*) FROM app_user WHERE organization_id = $1 AND source = 'synced'", s.org); n != 2 {
		t.Fatalf("%d synced users, want 2 (managed users are not synced)", n)
	}
	if got := s.events(t, "user.synced_added"); !slices.Equal(got, []string{"success::system", "success::system"}) {
		t.Fatalf("events %v", got)
	}
	if n := s.count(t, "SELECT count(*) FROM app_user WHERE username = $1", strings.ToLower(erin.Username)); n != 1 {
		t.Fatal("username not lowercased")
	}

	// frank leaves upstream and takes his assignments along; erin's name changes upstream.
	var frankID uuid.UUID
	if err := s.super.QueryRow(context.Background(), "SELECT id FROM app_user WHERE authentik_pk = $1", frank.PK).Scan(&frankID); err != nil {
		t.Fatal(err)
	}
	profile := uuid.Must(uuid.NewV7())
	if _, err := s.super.Exec(context.Background(), `
		INSERT INTO permission_profile (id, organization_id, name, class) VALUES ($1, $2, 'p', 'full');
		`, profile, s.org); err != nil {
		t.Fatal(err)
	}
	if _, err := s.super.Exec(context.Background(), `INSERT INTO profile_assignment (id, organization_id, profile_id, subject_type, subject_id)
		VALUES ($1, $2, $3, 'user', $4)`, uuid.Must(uuid.NewV7()), s.org, profile, frankID); err != nil {
		t.Fatal(err)
	}
	erin.Name = "Erin E."
	s.dir.users = []ports.IdentityUser{erin, managed}
	if _, err := s.sync.SyncUsers(s.system(), none); err != nil {
		t.Fatal(err)
	}
	if n := s.count(t, "SELECT count(*) FROM app_user WHERE id = $1", frankID); n != 0 {
		t.Fatal("removed synced user still present")
	}
	if n := s.count(t, "SELECT count(*) FROM profile_assignment WHERE subject_id = $1", frankID); n != 0 {
		t.Fatal("assignment of a removed user kept")
	}
	if n := s.count(t, "SELECT count(*) FROM app_user WHERE authentik_pk = $1 AND display_name = 'Erin E.'", erin.PK); n != 1 {
		t.Fatal("upstream attribute change not copied")
	}
	if got := s.events(t, "user.synced_removed"); !slices.Equal(got, []string{"success::system"}) {
		t.Fatalf("removal events %v", got)
	}
}

func TestSyncUsersUsernameOfAnotherOrganization(t *testing.T) {
	s := newSyncHarness(t)
	other := newHarness(t)
	username := "zed-" + s.org.String()[24:] + "@shared.test"
	if _, err := s.super.Exec(context.Background(), `INSERT INTO app_user (id, organization_id, authentik_pk, username, source)
		VALUES ($1, $2, $3, $4, 'synced')`, uuid.Must(uuid.NewV7()), other.org, "o"+s.org.String()[24:], username); err != nil {
		t.Fatal(err)
	}
	s.dir.users = []ports.IdentityUser{{PK: "z" + s.org.String()[24:], Username: username}}
	conflicts, err := s.sync.SyncUsers(s.system(), func(string) bool { return false })
	if err != nil || !slices.Equal(conflicts, []string{username}) {
		t.Fatalf("conflicts %v, %v", conflicts, err)
	}
	if got := s.events(t, "user.synced_added"); !slices.Equal(got, []string{"failure:username_taken:system"}) {
		t.Fatalf("events %v", got)
	}
	// A skipped username is not tried again.
	if _, err := s.sync.SyncUsers(s.system(), func(u string) bool { return u == username }); err != nil {
		t.Fatal(err)
	}
	if got := s.events(t, "user.synced_added"); len(got) != 1 {
		t.Fatalf("skipped user retried: %v", got)
	}
}

func TestSyncGroupMirrorsAndReconcile(t *testing.T) {
	s := newSyncHarness(t)
	ctx := context.Background()
	suffix := s.org.String()[24:]
	erin := ports.IdentityUser{PK: "e" + suffix, Username: "erin@m-" + suffix + ".test", Name: "Erin"}
	s.dir.users = []ports.IdentityUser{erin}
	if _, err := s.sync.SyncUsers(s.system(), func(string) bool { return false }); err != nil {
		t.Fatal(err)
	}
	mirrorPK, _ := s.dir.EnsureGroup(ctx, s.slug, organization.SyncedUserGroup(s.slug, "sales"))
	group := uuid.Must(uuid.NewV7())
	if _, err := s.super.Exec(ctx, `INSERT INTO user_group (id, organization_id, slug, name, source, upstream_authentik_pk, authentik_pk)
		VALUES ($1, $2, 'sales', 'Sales', 'synced', 'up-1', $3)`, group, s.org, mirrorPK); err != nil {
		t.Fatal(err)
	}
	s.dir.members["up-1"] = []string{erin.PK, "outsider"}
	if err := s.sync.SyncGroupMirrors(s.system()); err != nil {
		t.Fatal(err)
	}
	if n := s.count(t, "SELECT count(*) FROM user_group_member WHERE group_id = $1", group); n != 1 {
		t.Fatalf("%d mirrored members, want 1 (only users of the organization)", n)
	}
	if !slices.Equal(s.dir.members[mirrorPK], []string{erin.PK}) {
		t.Fatalf("Authentik mirror members %v", s.dir.members[mirrorPK])
	}
	if got := s.events(t, "user_group.member_added"); !slices.Equal(got, []string{"success::system"}) {
		t.Fatalf("events %v", got)
	}
	s.dir.members["up-1"] = nil
	if err := s.sync.SyncGroupMirrors(s.system()); err != nil {
		t.Fatal(err)
	}
	if n := s.count(t, "SELECT count(*) FROM user_group_member WHERE group_id = $1", group); n != 0 || len(s.dir.members[mirrorPK]) != 0 {
		t.Fatal("member not removed from the mirror")
	}

	// Reconcile: a directly assigned user is a member of the per-device group; a retired device loses its group.
	var erinID uuid.UUID
	if err := s.super.QueryRow(ctx, "SELECT id FROM app_user WHERE authentik_pk = $1", erin.PK).Scan(&erinID); err != nil {
		t.Fatal(err)
	}
	device := uuid.Must(uuid.NewV7())
	if _, err := s.super.Exec(ctx, `INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'kiosk', 'active');
		`, device, s.org); err != nil {
		t.Fatal(err)
	}
	if _, err := s.super.Exec(ctx, `INSERT INTO device_login_assignment (organization_id, device_id, subject_type, subject_id)
		VALUES ($1, $2, 'user', $3)`, s.org, device, erinID); err != nil {
		t.Fatal(err)
	}
	if err := s.sync.Reconcile(s.system()); err != nil {
		t.Fatal(err)
	}
	perDevice, _ := s.dir.FindGroup(ctx, organization.DeviceLoginGroup(s.slug, device))
	if perDevice == "" || !slices.Equal(s.dir.members[perDevice], []string{erin.PK}) {
		t.Fatalf("per-device group %q members %v", perDevice, s.dir.members[perDevice])
	}
	if _, err := s.super.Exec(ctx, "UPDATE device SET state = 'retired' WHERE id = $1", device); err != nil {
		t.Fatal(err)
	}
	if err := s.sync.Reconcile(s.system()); err != nil {
		t.Fatal(err)
	}
	if pk, _ := s.dir.FindGroup(ctx, organization.DeviceLoginGroup(s.slug, device)); pk != "" {
		t.Fatal("per-device group of a retired device kept")
	}
}

// TestLockReachesDevicesWithoutAuthentik: the state change of a lock is written before the Authentik call, so a
// failing Authentik does not hold back the devices (plan M3a decision 7).
func TestLockReachesDevicesWithoutAuthentik(t *testing.T) {
	h := newHarness(t)
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	orgPool, err := db.NewOrgPool(ctx, env.API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(orgPool.Close)
	user := uuid.Must(uuid.NewV7())
	if _, err := h.super.Exec(ctx, `INSERT INTO app_user (id, organization_id, authentik_pk, username, source)
		VALUES ($1, $2, $3, $4, 'local')`, user, h.org, "l"+user.String()[24:], "lock-"+user.String()[24:]+"@x.test"); err != nil {
		t.Fatal(err)
	}
	dir := newDirectory()
	dir.fail = problem.UpstreamUnavailable
	_, err = app.NewUsers(h.runner, orgPool, dir).Lock(h.admin(principal.RoleOrgAdmin), user)
	if !errors.Is(err, problem.UpstreamUnavailable) {
		t.Fatalf("lock: %v", err)
	}
	var locked bool
	var changes int
	if err := h.super.QueryRow(ctx, "SELECT locked FROM app_user WHERE id = $1", user).Scan(&locked); err != nil {
		t.Fatal(err)
	}
	if err := h.super.QueryRow(ctx, "SELECT count(*) FROM outbox WHERE subject = $1 AND payload->>'id' = $2 AND (payload->>'priority')::boolean",
		"state.priority."+h.org.String(), user.String()).Scan(&changes); err != nil {
		t.Fatal(err)
	}
	if !locked || changes != 1 {
		t.Fatalf("locked %v, priority state changes %d", locked, changes)
	}
}

// TestSessionLoginIsNotAudited: session.login only updates device_user_seen (plan M3a decision 10).
func TestSessionLoginIsNotAudited(t *testing.T) {
	s := newSyncHarness(t)
	ctx := context.Background()
	env := pgtest.SharedPaddock(t)
	worker, err := db.NewOrgPool(ctx, env.Worker, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(worker.Close)
	device := uuid.Must(uuid.NewV7())
	if _, err := s.super.Exec(ctx, "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'ws', 'active')", device, s.org); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 4, 8, 0, 0, 0, time.UTC)
	reports := app.NewDeviceReports(s.runner, worker)
	for i, data := range []string{`{"username":"Dave@Acme.test","at":"2026-10-04T08:00:00Z"}`, `{"username":"dave@acme.test"}`, `not json`} {
		ev := protocol.Event{EventSeq: int64(i + 1), Type: protocol.EventSessionLogin, OccurredAt: at.Add(time.Duration(i) * time.Hour), Data: json.RawMessage(data)}
		if _, err := reports.RecordEvent(s.system(), device, ev); err != nil {
			t.Fatal(err)
		}
	}
	var seen time.Time
	if err := s.super.QueryRow(ctx, "SELECT last_seen_at FROM device_user_seen WHERE device_id = $1 AND username = 'dave@acme.test'", device).Scan(&seen); err != nil {
		t.Fatal(err)
	}
	if !seen.Equal(at.Add(time.Hour)) {
		t.Fatalf("last seen %s", seen)
	}
	if n := s.count(t, "SELECT count(*) FROM action WHERE organization_id = $1", s.org); n != 0 {
		t.Fatalf("%d audit events for logins", n)
	}
}
