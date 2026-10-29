package app_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// roleWorld is a role membership use case over the shared database with an in-memory directory.
type roleWorld struct {
	super *pgx.Conn
	dir   *directory
	roles *app.RoleMembership
}

func newRoleWorld(t *testing.T) *roleWorld {
	t.Helper()
	return newRoleWorldWith(t, func(context.Context) string { return "corr-roles" })
}

// newRoleWorldWith is newRoleWorld with the runner's correlation function, which runs once per recorded change.
func newRoleWorldWith(t *testing.T, correlation func(context.Context) string) *roleWorld {
	t.Helper()
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
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	dir := newDirectory()
	dir.roleGroups = map[string][]ports.IdentityUser{}
	return &roleWorld{super: super, dir: dir,
		roles: app.NewRoleMembership(app.NewActionRunner(worker, platform, correlation), worker, platform, dir)}
}

// roleEvents lists the role events of org as "code outcome role username pk [group] baseline target actor" in the
// order they were recorded.
func (w *roleWorld) roleEvents(t *testing.T, org uuid.UUID, pkPrefix string) []string {
	t.Helper()
	rows, err := w.super.Query(context.Background(), `SELECT code || ' ' || outcome || ' ' || (params->>'role') || ' ' ||
		(params->>'username') || ' ' || (params->>'authentik_pk') || ' [' || (params->>'group') || '] ' ||
		coalesce(params->>'baseline', '-') || ' ' || (target->>'type') || '/' || (target->>'id') || '/' || (target->>'display') ||
		' ' || (actor->>'type')
		FROM action WHERE code IN ('admin.role_granted', 'admin.role_revoked') AND organization_id = $1
		  AND params->>'authentik_pk' LIKE $2 || '%' ORDER BY started_at, id`, org, pkPrefix)
	if err != nil {
		t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// members lists the stored members as "role:username", with "?" appended to a member marked missing.
func (w *roleWorld) members(t *testing.T, table, where string, arg any) []string {
	t.Helper()
	rows, err := w.super.Query(context.Background(), "SELECT role || ':' || username || CASE WHEN missing_since IS NULL THEN '' ELSE '?' END FROM "+
		table+" WHERE "+where+" ORDER BY 1", arg)
	if err != nil {
		t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (w *roleWorld) organization(t *testing.T, prefix string) (uuid.UUID, string, context.Context) {
	t.Helper()
	org := uuid.Must(uuid.NewV7())
	slug := prefix + org.String()[25:]
	if _, err := w.super.Exec(context.Background(), "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'Roles', 'active')", org, slug); err != nil {
		t.Fatal(err)
	}
	return org, slug, principal.With(context.Background(), principal.Principal{Kind: principal.KindSystem, Display: "worker", OrganizationID: org})
}

// syncOrganization runs one round of the organization: the listing, then the comparison.
func (w *roleWorld) syncOrganization(ctx context.Context) error {
	groups, err := w.roles.OrganizationRoleGroups(ctx)
	if err != nil || groups == nil {
		return err
	}
	return w.roles.SyncOrganization(ctx, groups)
}

// orgEvents formats the expected events of an organization test (pk is the test's pk prefix).
type orgEvents struct{ pk string }

func (e orgEvents) granted(role, u, group, baseline string) string {
	return fmt.Sprintf("admin.role_granted success %s %s %s%s [%s] %s identity_user/%s%s/%s system", role, u, e.pk, u, group, baseline, e.pk, u, u)
}

func (e orgEvents) revoked(role, u, group string) string {
	return fmt.Sprintf("admin.role_revoked success %s %s %s%s [%s] - identity_user/%s%s/%s system", role, u, e.pk, u, group, e.pk, u, u)
}

// TestRoleMembershipOrganization covers plan M8b decision 35 with the amendment of 2026-10-25: the first comparison of
// each role records its members as baseline, the next round nothing, later changes one event each with the user and
// the group; a member is revoked only when two consecutive listings miss it; a failing listing keeps its rows and
// records nothing for its role while the others sync; a missing group is skipped; an organization that is not active
// records nothing.
func TestRoleMembershipOrganization(t *testing.T) {
	w := newRoleWorld(t)
	org, slug, ctx := w.organization(t, "rm")
	pk := org.String()[:8] + "-"
	ev := orgEvents{pk: pk}
	admins := organization.RoleGroup(slug, organization.GroupAdmins)
	operators := organization.RoleGroup(slug, organization.GroupOperators)
	auditors := organization.RoleGroup(slug, organization.GroupAuditors)
	user := func(name string) ports.IdentityUser {
		return ports.IdentityUser{PK: pk + name, Username: name, UID: "uid-" + name, Active: true}
	}
	alice, bob, carol, dave := user("alice"), user("bob"), user("carol"), user("dave")
	w.dir.roleGroups[admins] = []ports.IdentityUser{alice}
	w.dir.roleGroups[operators] = []ports.IdentityUser{bob}
	expect := func(step string, want ...string) {
		t.Helper()
		if got := w.roleEvents(t, org, pk); !slices.Equal(got, want) {
			t.Fatalf("%s: events\n%s\nwant\n%s", step, got, want)
		}
	}
	rows := func(where string) []string {
		return w.members(t, "organization_role_member", "organization_id = $1"+where, org)
	}

	if err := w.syncOrganization(ctx); err != nil {
		t.Fatal(err)
	}
	events := []string{ev.granted("org_admin", "alice", admins, "true"), ev.granted("org_operator", "bob", operators, "true")}
	expect("first snapshot", events...)
	if n := countRows(t, w.super, "SELECT count(*) FROM organization_role_snapshot WHERE organization_id = $1", org); n != 3 {
		t.Fatalf("%d role snapshots after the first complete comparison, want 3", n)
	}
	if got := rows(""); !slices.Equal(got, []string{"org_admin:alice", "org_operator:bob"}) {
		t.Fatalf("rows %v", got)
	}
	if err := w.syncOrganization(ctx); err != nil {
		t.Fatal(err)
	}
	expect("unchanged round", events...)

	w.dir.roleGroups[auditors] = []ports.IdentityUser{carol}
	if err := w.syncOrganization(ctx); err != nil {
		t.Fatal(err)
	}
	events = append(events, ev.granted("org_auditor", "carol", auditors, "false"))
	expect("carol joins the auditors", events...)

	// The operators cannot be read while bob left them: his row stays unmarked, nothing is recorded for the operators,
	// and the administrators still sync.
	w.dir.roleGroups[operators] = nil
	w.dir.roleGroups[admins] = []ports.IdentityUser{alice, dave}
	w.dir.roleGroupFail = map[string]error{operators: errors.New("authentik: HTTP 503")}
	if err := w.syncOrganization(ctx); err == nil {
		t.Fatal("a failing listing did not fail the round")
	}
	events = append(events, ev.granted("org_admin", "dave", admins, "false"))
	expect("operators unreadable", events...)
	if got := rows(" AND role = 'org_operator'"); !slices.Equal(got, []string{"org_operator:bob"}) {
		t.Fatalf("operator rows after a failed listing: %v", got)
	}

	// bob, the last operator, left: the operators listing is empty while the other roles list members. The first
	// listing missing him only marks him, the second records the revocation.
	w.dir.roleGroupFail = nil
	if err := w.syncOrganization(ctx); err != nil {
		t.Fatal(err)
	}
	expect("bob missed once", events...)
	if got := rows(" AND role = 'org_operator'"); !slices.Equal(got, []string{"org_operator:bob?"}) {
		t.Fatalf("operator rows after one missing listing: %v", got)
	}
	if err := w.syncOrganization(ctx); err != nil {
		t.Fatal(err)
	}
	events = append(events, ev.revoked("org_operator", "bob", operators))
	expect("bob missed twice", events...)
	if got := rows(" AND role = 'org_operator'"); len(got) != 0 {
		t.Fatalf("operator rows after the revocation: %v", got)
	}

	// A missing group is skipped: carol is neither marked nor revoked, and the round succeeds.
	w.dir.roleGroupFail = map[string]error{auditors: fmt.Errorf("%s: %w", auditors, ports.ErrGroupNotFound)}
	for range 2 {
		if err := w.syncOrganization(ctx); err != nil {
			t.Fatalf("a missing group failed the round: %v", err)
		}
	}
	expect("missing auditors group", events...)
	if got := rows(" AND role = 'org_auditor'"); !slices.Equal(got, []string{"org_auditor:carol"}) {
		t.Fatalf("auditor rows after a missing group: %v", got)
	}
	w.dir.roleGroupFail = nil

	// A suspended organization's role groups are neither listed nor recorded.
	if _, err := w.super.Exec(context.Background(), "UPDATE organization SET status = 'suspended' WHERE id = $1", org); err != nil {
		t.Fatal(err)
	}
	w.dir.roleGroups[admins] = []ports.IdentityUser{alice}
	w.dir.roleGroupCalls = 0
	if groups, err := w.roles.OrganizationRoleGroups(ctx); err != nil || groups != nil || w.dir.roleGroupCalls != 0 {
		t.Fatalf("suspended organization listed: %v %v, %d listings", groups, err, w.dir.roleGroupCalls)
	}
	for range 2 {
		if err := w.roles.SyncOrganization(ctx, app.ListRoleGroups(ctx, w.dir, admins, operators, auditors)); err != nil {
			t.Fatal(err)
		}
	}
	expect("suspended organization", events...)
}

// TestRoleMembershipPageShift (review 1, B2): a settled paged listing can still miss a member whose page shifted when
// one member left and another joined between two pages; one such listing marks the member and records nothing, the
// next listing that shows it clears the mark.
func TestRoleMembershipPageShift(t *testing.T) {
	w := newRoleWorld(t)
	org, slug, ctx := w.organization(t, "rp")
	pk := org.String()[:8] + "-"
	admins := organization.RoleGroup(slug, organization.GroupAdmins)
	zoe := ports.IdentityUser{PK: pk + "zoe", Username: "zoe", UID: "uid-zoe"}
	w.dir.roleGroups[admins] = []ports.IdentityUser{{PK: pk + "amy", Username: "amy", UID: "uid-amy"}, zoe}
	if err := w.syncOrganization(ctx); err != nil {
		t.Fatal(err)
	}
	w.dir.unlisted = map[string]bool{"uid-zoe": true}
	if err := w.syncOrganization(ctx); err != nil {
		t.Fatal(err)
	}
	w.dir.unlisted = nil
	if err := w.syncOrganization(ctx); err != nil {
		t.Fatal(err)
	}
	if got := w.roleEvents(t, org, pk); len(got) != 2 || slices.ContainsFunc(got, func(e string) bool { return e[:18] == "admin.role_revoked" }) {
		t.Fatalf("events %v, want only the two baseline grants", got)
	}
	if got := w.members(t, "organization_role_member", "organization_id = $1", org); !slices.Equal(got, []string{"org_admin:amy", "org_admin:zoe"}) {
		t.Fatalf("rows %v, want zoe kept and unmarked", got)
	}
}

// TestRoleMembershipFailedClear (PDK-423): when the transaction that clears the mark of a reappeared member fails, the
// stale mark must not turn the next miss into a revocation; only two consecutive misses after it revoke the member.
func TestRoleMembershipFailedClear(t *testing.T) {
	w := newRoleWorld(t)
	// Injected failure: clearing the mark of a member named fail-clear raises.
	if _, err := w.super.Exec(context.Background(), `
		CREATE OR REPLACE FUNCTION fail_role_member_clear() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
		  IF NEW.username = 'fail-clear' AND OLD.missing_since IS NOT NULL AND NEW.missing_since IS NULL THEN
		    RAISE EXCEPTION 'injected clear failure';
		  END IF;
		  RETURN NEW;
		END $$;
		CREATE OR REPLACE TRIGGER fail_role_member_clear BEFORE UPDATE ON organization_role_member
		  FOR EACH ROW EXECUTE FUNCTION fail_role_member_clear();`); err != nil {
		t.Fatal(err)
	}
	org, slug, ctx := w.organization(t, "rf")
	pk := org.String()[:8] + "-"
	e := orgEvents{pk: pk}
	admins := organization.RoleGroup(slug, organization.GroupAdmins)
	zoe := ports.IdentityUser{PK: pk + "fail-clear", Username: "fail-clear", UID: "uid-fail-clear"}
	w.dir.roleGroups[admins] = []ports.IdentityUser{{PK: pk + "amy", Username: "amy", UID: "uid-amy"}, zoe}
	round := func(name string, unlisted bool, wantErr bool, want ...string) {
		t.Helper()
		w.dir.unlisted = nil
		if unlisted {
			w.dir.unlisted = map[string]bool{"uid-fail-clear": true}
		}
		if err := w.syncOrganization(ctx); (err != nil) != wantErr {
			t.Fatalf("%s: round error %v, want error %v", name, err, wantErr)
		}
		if got := w.members(t, "organization_role_member", "organization_id = $1", org); !slices.Equal(got, want) {
			t.Fatalf("%s: rows %v, want %v", name, got, want)
		}
	}
	round("baseline", false, false, "org_admin:amy", "org_admin:fail-clear")
	round("first miss", true, false, "org_admin:amy", "org_admin:fail-clear?")
	round("shown, clear fails", false, true, "org_admin:amy", "org_admin:fail-clear?")
	round("miss after the failed clear", true, false, "org_admin:amy", "org_admin:fail-clear?")
	baseline := []string{e.granted("org_admin", "amy", admins, "true"), e.granted("org_admin", "fail-clear", admins, "true")}
	if got := w.roleEvents(t, org, pk); !slices.Equal(got, baseline) {
		t.Fatalf("events %v, want only the baseline %v", got, baseline)
	}
	round("second consecutive miss", true, false, "org_admin:amy")
	if got := w.roleEvents(t, org, pk); !slices.Equal(got, append(baseline, e.revoked("org_admin", "fail-clear", admins))) {
		t.Fatalf("events %v, want the baseline and one revocation", got)
	}
}

// TestRoleMembershipEmptyListings (reviews 1 and 2): when every role listing of an organization comes back empty
// without an error while members are recorded (a service token that may no longer see users), nothing is recorded,
// the rows stay unmarked, and the round fails with ErrDirectoryEmpty, however often it repeats.
func TestRoleMembershipEmptyListings(t *testing.T) {
	w := newRoleWorld(t)
	org, slug, ctx := w.organization(t, "re")
	pk := org.String()[:8] + "-"
	for i, g := range []organization.GroupRole{organization.GroupAdmins, organization.GroupOperators, organization.GroupAuditors} {
		w.dir.roleGroups[organization.RoleGroup(slug, g)] = []ports.IdentityUser{{PK: fmt.Sprintf("%s%d", pk, i), Username: fmt.Sprintf("u%d", i)}}
	}
	if err := w.syncOrganization(ctx); err != nil {
		t.Fatal(err)
	}
	full := w.dir.roleGroups
	w.dir.roleGroups = map[string][]ports.IdentityUser{}
	for range 3 {
		if err := w.syncOrganization(ctx); !errors.Is(err, app.ErrDirectoryEmpty) {
			t.Fatalf("empty listings: %v, want ErrDirectoryEmpty", err)
		}
	}
	if got := w.roleEvents(t, org, pk); len(got) != 3 {
		t.Fatalf("events %v, want only the three baseline grants", got)
	}
	if got := w.members(t, "organization_role_member", "organization_id = $1", org); !slices.Equal(got, []string{"org_admin:u0", "org_auditor:u2", "org_operator:u1"}) {
		t.Fatalf("rows %v, want all kept and unmarked", got)
	}
	w.dir.roleGroups = full
	if err := w.syncOrganization(ctx); err != nil {
		t.Fatal(err)
	}
}

// TestRoleMembershipBaselinePerRole (review 1, M3): each role's baseline ends with its own first successful
// comparison; a role that keeps failing neither keeps the other roles in baseline nor is relabelled by them.
func TestRoleMembershipBaselinePerRole(t *testing.T) {
	w := newRoleWorld(t)
	org, slug, ctx := w.organization(t, "rb")
	pk := org.String()[:8] + "-"
	ev := orgEvents{pk: pk}
	admins := organization.RoleGroup(slug, organization.GroupAdmins)
	operators := organization.RoleGroup(slug, organization.GroupOperators)
	w.dir.roleGroups[admins] = []ports.IdentityUser{{PK: pk + "ann", Username: "ann"}}
	w.dir.roleGroups[operators] = []ports.IdentityUser{{PK: pk + "otto", Username: "otto"}}
	w.dir.roleGroupFail = map[string]error{operators: errors.New("authentik: HTTP 503")}
	if err := w.syncOrganization(ctx); err == nil {
		t.Fatal("a failing listing did not fail the round")
	}
	w.dir.roleGroups[admins] = append(w.dir.roleGroups[admins], ports.IdentityUser{PK: pk + "carol", Username: "carol"})
	if err := w.syncOrganization(ctx); err == nil {
		t.Fatal("a failing listing did not fail the round")
	}
	w.dir.roleGroupFail = nil
	if err := w.syncOrganization(ctx); err != nil {
		t.Fatal(err)
	}
	want := []string{ev.granted("org_admin", "ann", admins, "true"), ev.granted("org_admin", "carol", admins, "false"),
		ev.granted("org_operator", "otto", operators, "true")}
	if got := w.roleEvents(t, org, pk); !slices.Equal(got, want) {
		t.Fatalf("events\n%s\nwant\n%s", got, want)
	}
}

// TestRoleMembershipStopsWithTheRound (review 1, minor 4): when the round's context ends, the changes not attempted yet
// are not recorded as failed.
func TestRoleMembershipStopsWithTheRound(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changes := 0
	w := newRoleWorldWith(t, func(context.Context) string {
		changes++
		cancel()
		return "corr-stop"
	})
	org, slug, sys := w.organization(t, "rs")
	pk := org.String()[:8] + "-"
	admins := organization.RoleGroup(slug, organization.GroupAdmins)
	for _, n := range []string{"a", "b", "c"} {
		w.dir.roleGroups[admins] = append(w.dir.roleGroups[admins], ports.IdentityUser{PK: pk + n, Username: n})
	}
	groups, err := w.roles.OrganizationRoleGroups(sys)
	if err != nil {
		t.Fatal(err)
	}
	sys = principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker", OrganizationID: org})
	if err := w.roles.SyncOrganization(sys, groups); err == nil {
		t.Fatal("a canceled round succeeded")
	}
	var failed int
	if err := w.super.QueryRow(context.Background(), `SELECT count(*) FILTER (WHERE outcome <> 'success') FROM action
		WHERE organization_id = $1 AND code = 'admin.role_granted'`, org).Scan(&failed); err != nil {
		t.Fatal(err)
	}
	if changes > 1 || failed > 1 {
		t.Fatalf("%d changes attempted, %d failure events after the round ended, want at most the one in progress", changes, failed)
	}
}

// TestRoleMembershipPlatform covers plan M8b decision 35: platform administrators and Authentik superusers are recorded
// in the platform pseudo-organization through the platform pool; a failing listing keeps its rows, an empty superuser
// listing refuses the scope; a member, also the last platform administrator, is revoked when two consecutive listings
// miss it.
func TestRoleMembershipPlatform(t *testing.T) {
	w := newRoleWorld(t)
	bg := context.Background()
	// Only this test writes the platform tables: it starts from an installation without a platform snapshot.
	if _, err := w.super.Exec(bg, "DELETE FROM platform_role_member; DELETE FROM platform_role_snapshot"); err != nil {
		t.Fatal(err)
	}
	ctx := principal.With(bg, principal.Principal{Kind: principal.KindSystem, Display: "worker"})
	pk := uuid.NewString()[:8] + "-"
	group := organization.PlatformAdminsGroup()
	root, akadmin, ops := ports.IdentityUser{PK: pk + "root", Username: "root"}, ports.IdentityUser{PK: pk + "akadmin", Username: "akadmin"},
		ports.IdentityUser{PK: pk + "ops", Username: "ops"}
	w.dir.roleGroups[group] = []ports.IdentityUser{root}
	w.dir.superusers = []ports.IdentityUser{akadmin}
	sync := func() error { return w.roles.SyncPlatform(ctx, w.roles.PlatformRoleGroups(ctx)) }
	expect := func(step string, want ...string) {
		t.Helper()
		if got := w.roleEvents(t, uuid.Nil, pk); !slices.Equal(got, want) {
			t.Fatalf("%s: events\n%s\nwant\n%s", step, got, want)
		}
	}
	event := func(code, role string, u ports.IdentityUser, group, baseline string) string {
		return fmt.Sprintf("%s success %s %s %s [%s] %s identity_user/%s/%s system", code, role, u.Username, u.PK, group, baseline, u.PK, u.Username)
	}

	if err := sync(); err != nil {
		t.Fatal(err)
	}
	events := []string{event("admin.role_granted", "platform_admin", root, group, "true"),
		event("admin.role_granted", "authentik_superuser", akadmin, "", "true")}
	expect("first snapshot", events...)
	if got := w.members(t, "platform_role_member", "authentik_pk LIKE $1 || '%'", pk); !slices.Equal(got, []string{"authentik_superuser:akadmin", "platform_admin:root"}) {
		t.Fatalf("rows %v", got)
	}
	if err := sync(); err != nil {
		t.Fatal(err)
	}
	expect("unchanged round", events...)

	w.dir.superusers = nil
	w.dir.superFail = errors.New("authentik: HTTP 503")
	w.dir.roleGroups[group] = []ports.IdentityUser{root, ops}
	if err := sync(); err == nil {
		t.Fatal("a failing superuser listing did not fail the round")
	}
	events = append(events, event("admin.role_granted", "platform_admin", ops, group, "false"))
	expect("superusers unreadable", events...)

	// An empty superuser listing refuses the scope: nothing is recorded for either role, however long it lasts, even
	// though the platform administrators changed meanwhile.
	w.dir.superFail = nil
	w.dir.roleGroups[group] = []ports.IdentityUser{root}
	for range 2 {
		if err := sync(); !errors.Is(err, app.ErrDirectoryEmpty) {
			t.Fatalf("empty superuser listing: %v, want ErrDirectoryEmpty", err)
		}
	}
	expect("empty superuser listing", events...)
	if got := w.members(t, "platform_role_member", "authentik_pk LIKE $1 || '%'", pk); !slices.Equal(got,
		[]string{"authentik_superuser:akadmin", "platform_admin:ops", "platform_admin:root"}) {
		t.Fatalf("rows after empty superuser listings %v", got)
	}

	// ops leaves, then root as the last platform administrator while the superusers are listed: each is revoked once,
	// on the second listing missing him.
	w.dir.superusers = []ports.IdentityUser{akadmin}
	for range 2 {
		if err := sync(); err != nil {
			t.Fatal(err)
		}
	}
	events = append(events, event("admin.role_revoked", "platform_admin", ops, group, "-"))
	expect("ops left", events...)
	w.dir.roleGroups[group] = nil
	if err := sync(); err != nil {
		t.Fatal(err)
	}
	expect("root missed once", events...)
	if err := sync(); err != nil {
		t.Fatal(err)
	}
	events = append(events, event("admin.role_revoked", "platform_admin", root, group, "-"))
	expect("the last platform administrator left", events...)

	// akadmin loses superuser rights (another superuser remains): revoked on the second listing missing him.
	w.dir.superusers = []ports.IdentityUser{{PK: pk + "other", Username: "other"}}
	if err := sync(); err != nil {
		t.Fatal(err)
	}
	events = append(events, event("admin.role_granted", "authentik_superuser", ports.IdentityUser{PK: pk + "other", Username: "other"}, "", "false"))
	expect("akadmin missed once", events...)
	if err := sync(); err != nil {
		t.Fatal(err)
	}
	events = append(events, event("admin.role_revoked", "authentik_superuser", akadmin, "", "-"))
	expect("akadmin missed twice", events...)
}

// TestRoleMembershipTablesIsolated: the worker cannot read the platform's role members, the API neither the
// organizations' nor the platform's.
func TestRoleMembershipTablesIsolated(t *testing.T) {
	w := newRoleWorld(t)
	ctx := context.Background()
	for _, c := range []struct{ role, stmt string }{
		{"paddock_worker", "SELECT 1 FROM platform_role_member"},
		{"paddock_worker", "SELECT 1 FROM platform_role_snapshot"},
		{"paddock_api", "SELECT 1 FROM organization_role_member"},
		{"paddock_api", "SELECT 1 FROM organization_role_snapshot"},
		{"paddock_api", "SELECT 1 FROM platform_role_member"},
		{"paddock_platform", "SELECT 1 FROM organization_role_member"},
	} {
		tx, err := w.super.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+c.role); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, "SELECT set_config('paddock.org_id', $1, true)", uuid.NewString()); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, c.stmt)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("%s %q: %v, want permission denied (42501)", c.role, c.stmt, err)
		}
		_ = tx.Rollback(ctx)
	}

	// The worker sees only its own organization's rows.
	org, _, _ := w.organization(t, "ri")
	other, _, _ := w.organization(t, "ri")
	for _, o := range []uuid.UUID{org, other} {
		if _, err := w.super.Exec(ctx, `INSERT INTO organization_role_member (organization_id, role, authentik_pk, username, first_seen_at)
			VALUES ($1, 'org_admin', '1', 'alice', now())`, o); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := w.super.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE paddock_worker"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('paddock.org_id', $1, true)", org.String()); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM organization_role_member WHERE organization_id = ANY($1)", []uuid.UUID{org, other}).Scan(&n); err != nil || n != 1 {
		t.Fatalf("worker sees %d rows (%v), want its own one", n, err)
	}
}
