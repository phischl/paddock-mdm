package app_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// revoker counts the revocations per account; open, when set, is the number of sessions each account has (default 2).
type revoker struct {
	mu      sync.Mutex
	revoked map[uuid.UUID]int
	open    map[uuid.UUID]int
	// failOnce makes the next revocation of an account fail.
	failOnce map[uuid.UUID]bool
}

func (r *revoker) CountAccount(_ context.Context, id uuid.UUID) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.open == nil {
		return 2, nil
	}
	return r.open[id], nil
}

func (r *revoker) RevokeAccount(_ context.Context, id uuid.UUID) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failOnce[id] {
		delete(r.failOnce, id)
		return 0, errors.New("session store down")
	}
	r.revoked[id]++
	if r.open == nil {
		return 2, nil
	}
	n := r.open[id]
	r.open[id] = 0
	return n, nil
}

// TestAdminAccountsReconcile covers plan M8s decision 22: accounts follow their role groups with three listings per
// organization; a changed role, a removed or deactivated user and an ambiguous membership each end the account's
// sessions and record admin.sessions_revoked once; unchanged accounts record nothing; a failing directory changes
// nothing.
func TestAdminAccountsReconcile(t *testing.T) {
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
	org := uuid.Must(uuid.NewV7())
	slug := "aa" + org.String()[25:]
	if _, err := super.Exec(ctx, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'Accounts', 'active')", org, slug); err != nil {
		t.Fatal(err)
	}
	// uid is the directory UID of the user an account was created for: the subject of its login.
	uid := func(username string) string { return "uid-" + username + "-" + org.String()[:8] }
	account := func(username, role string) uuid.UUID {
		id := uuid.Must(uuid.NewV7())
		if _, err := super.Exec(ctx, `INSERT INTO admin_account (id, organization_id, authentik_sub, username, display_name, role)
			VALUES ($1, $2, $3, $4, $4, $5)`, id, org, uid(username), username, role); err != nil {
			t.Fatal(err)
		}
		return id
	}
	unchanged := account("alice@acme.test", "org_admin")
	renamed := account("hank@acme.test", "org_admin")
	skipped := account("kim@acme.test", "org_admin")
	moved := account("dave@acme.test", "org_admin")
	removed := account("erin@acme.test", "org_admin")
	inactive := account("frank@acme.test", "org_auditor")
	twice := account("gina@acme.test", "org_operator")
	admins := organization.RoleGroup(slug, organization.GroupAdmins)
	operators := organization.RoleGroup(slug, organization.GroupOperators)
	auditors := organization.RoleGroup(slug, organization.GroupAuditors)
	dir := newDirectory()
	dir.roleGroups = map[string][]ports.IdentityUser{
		// The UID decides: a renamed user keeps the account, and another user with an admin's username or e-mail
		// address does not decide that account.
		admins: {{UID: uid("alice@acme.test"), Username: "alice@acme.test", Active: true},
			{UID: uid("kim@acme.test"), Username: "kim@acme.test", Active: true},
			{UID: uid("gina@acme.test"), Username: "gina@acme.test", Active: true},
			{UID: uid("hank@acme.test"), Username: "henry@acme.test", Active: true},
			{UID: "uid-impostor", Username: "erin@acme.test", Email: "dave@acme.test", Active: true}},
		operators: {{UID: uid("gina@acme.test"), Username: "gina@acme.test", Active: true},
			{UID: uid("nobody@acme.test"), Username: "nobody@acme.test", Active: true}, {Username: "no-uid@acme.test", Active: true}},
		auditors: {{UID: uid("dave@acme.test"), Username: "dave@acme.test", Active: true},
			{UID: uid("frank@acme.test"), Username: "frank@acme.test", Active: false},
			{UID: "uid-ivy", Username: "ivy@acme.test", Email: "alice@acme.test", Active: true}},
	}

	// The paged listing misses kim, who is still an administrator: the direct read keeps the account.
	dir.unlisted = map[string]bool{uid("kim@acme.test"): true}
	sessions := &revoker{revoked: map[uuid.UUID]int{}}
	corr := "corr-" + t.Name()
	accounts := app.NewAdminAccounts(app.NewActionRunner(worker, platform, func(context.Context) string { return corr }), worker, platform, dir, sessions)
	sys := httpx.WithRequestID(principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker", OrganizationID: org}), corr)

	// Fail safe: a directory that answers with an error, a missing role group or no members at all changes nothing.
	full := dir.roleGroups
	for name, setup := range map[string]func(){
		"directory down":     func() { dir.fail = errors.New("directory down") },
		"missing role group": func() { dir.fail = fmt.Errorf("%s: %w", admins, ports.ErrGroupNotFound) },
		"empty listings":     func() { dir.roleGroups = map[string][]ports.IdentityUser{} },
	} {
		setup()
		err := accounts.Reconcile(sys)
		dir.fail, dir.roleGroups = nil, full
		if err == nil || name == "empty listings" && !errors.Is(err, app.ErrDirectoryEmpty) {
			t.Fatalf("%s: round error %v", name, err)
		}
		if len(sessions.revoked) != 0 || countRows(t, super, "SELECT count(*) FROM admin_account WHERE organization_id = $1 AND disabled_at IS NOT NULL", org) != 0 ||
			countRows(t, super, "SELECT count(*) FROM action WHERE code = 'admin.sessions_revoked' AND organization_id = $1", org) != 0 {
			t.Fatalf("%s: accounts changed", name)
		}
	}
	dir.roleGroupCalls = 0
	if err := accounts.Reconcile(sys); err != nil {
		t.Fatal(err)
	}
	if dir.roleGroupCalls != 3 {
		t.Fatalf("%d directory listings, want 3", dir.roleGroupCalls)
	}
	state := func(id uuid.UUID) (role string, disabled bool) {
		if err := super.QueryRow(ctx, "SELECT role, disabled_at IS NOT NULL FROM admin_account WHERE id = $1", id).Scan(&role, &disabled); err != nil {
			t.Fatal(err)
		}
		return role, disabled
	}
	event := func(id uuid.UUID) []string {
		rows, err := super.Query(ctx, `SELECT outcome || ' ' || (actor->>'type') || ' ' || (params->>'reason') || ' ' ||
			(params->>'sessions') || ' [' || (params->>'old_role') || '] [' || (params->>'new_role') || ']' FROM action
			WHERE code = 'admin.sessions_revoked' AND target->>'id' = $1`, id.String())
		if err != nil {
			t.Fatal(err)
		}
		out, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	for name, c := range map[string]struct {
		id       uuid.UUID
		role     string
		disabled bool
		event    string
	}{
		"unchanged, another user's e-mail is its username": {unchanged, "org_admin", false, ""},
		"renamed in the directory":                         {renamed, "org_admin", false, ""},
		"missed by the listing":                            {skipped, "org_admin", false, ""},
		"moved to auditors":                                {moved, "org_auditor", false, "success system role_changed 2 [org_admin] [org_auditor]"},
		"in no role group, its username used by another":   {removed, "org_admin", true, "success system removed 2 [org_admin] []"},
		"deactivated":                                      {inactive, "org_auditor", true, "success system deactivated 2 [org_auditor] []"},
		"in two role groups":                               {twice, "org_operator", true, "success system removed 2 [org_operator] []"},
	} {
		role, disabled := state(c.id)
		events := event(c.id)
		if role != c.role || disabled != c.disabled {
			t.Errorf("%s: role %s disabled %v, want %s %v", name, role, disabled, c.role, c.disabled)
		}
		if c.event == "" && (len(events) != 0 || sessions.revoked[c.id] != 0) {
			t.Errorf("%s: events %v, %d revocations", name, events, sessions.revoked[c.id])
		}
		if c.event != "" && (len(events) != 1 || events[0] != c.event || sessions.revoked[c.id] != 1) {
			t.Errorf("%s: events %v, %d revocations, want [%s]", name, events, sessions.revoked[c.id], c.event)
		}
	}

	// A second round finds nothing to change: the disabled accounts are no longer listed.
	if err := accounts.Reconcile(sys); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, super, "SELECT count(*) FROM action WHERE code = 'admin.sessions_revoked' AND organization_id = $1", org); n != 4 {
		t.Fatalf("%d events after the second round, want 4", n)
	}
}

// TestAdminAccountsReconcilePlatform covers PDK-185: platform administrators the directory no longer lists, or lists as
// deactivated, lose their sessions once with one event in the platform pseudo-organization; listed ones keep them; a
// directory that cannot be read changes nothing.
func TestAdminAccountsReconcilePlatform(t *testing.T) {
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
	admin := func(username string) uuid.UUID {
		id := uuid.Must(uuid.NewV7())
		if _, err := super.Exec(ctx, `INSERT INTO platform_admin (id, authentik_sub, username, display_name) VALUES ($1, $2, $3, $3)`,
			id, "uid-"+username, username); err != nil {
			t.Fatal(err)
		}
		return id
	}
	suffix := uuid.NewString()[:8]
	kept, removed, inactive, flaky := admin("root-"+suffix), admin("gone-"+suffix), admin("off-"+suffix), admin("flaky-"+suffix)
	missed := admin("missed-" + suffix)
	dir := newDirectory()
	dir.roleGroups = map[string][]ports.IdentityUser{organization.PlatformAdminsGroup(): {
		{UID: "uid-root-" + suffix, Username: "renamed-root", Active: true}, {UID: "uid-off-" + suffix, Username: "off-" + suffix, Active: false},
		{UID: "uid-other", Username: "gone-" + suffix, Active: true}, {UID: "uid-missed-" + suffix, Username: "missed-" + suffix, Active: true}}}
	dir.unlisted = map[string]bool{"uid-missed-" + suffix: true}
	sessions := &revoker{revoked: map[uuid.UUID]int{}, open: map[uuid.UUID]int{kept: 1, removed: 2, inactive: 1, flaky: 1, missed: 1},
		failOnce: map[uuid.UUID]bool{flaky: true}}
	corr := "corr-" + t.Name()
	accounts := app.NewAdminAccounts(app.NewActionRunner(worker, platform, func(context.Context) string { return corr }), worker, platform, dir, sessions)
	sys := httpx.WithRequestID(principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker"}), corr)

	dir.fail = errors.New("directory down")
	if err := accounts.ReconcilePlatform(sys); err == nil || sessions.revoked[removed] != 0 {
		t.Fatalf("directory down: %v, %d revocations", err, sessions.revoked[removed])
	}
	dir.fail = nil
	// The first round fails to end the flaky administrator's session (recorded as failed); the next round retries.
	if err := accounts.ReconcilePlatform(sys); err == nil {
		t.Fatal("a failing revocation did not fail the round")
	}
	for round := 2; round <= 3; round++ {
		if err := accounts.ReconcilePlatform(sys); err != nil {
			t.Fatal(err)
		}
	}
	event := func(id uuid.UUID) []string {
		rows, err := super.Query(ctx, `SELECT outcome || ' ' || (params->>'reason') || ' ' || coalesce(params->>'sessions', '-') || ' ' ||
			(organization_id = $2)::text FROM action WHERE code = 'admin.sessions_revoked' AND target->>'id' = $1`, id.String(), uuid.Nil)
		if err != nil {
			t.Fatal(err)
		}
		out, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := event(flaky); len(got) != 2 || !slices.Contains(got, "success removed 1 true") || slices.Contains(got, "success removed 0 true") {
		t.Fatalf("flaky administrator: events %v, want the failure and the retried success", got)
	}
	for name, c := range map[string]struct {
		id    uuid.UUID
		event string
	}{"listed": {kept, ""}, "missed by the listing": {missed, ""}, "removed": {removed, "success removed 2 true"}, "deactivated": {inactive, "success deactivated 1 true"}} {
		got := event(c.id)
		if c.event == "" && (len(got) != 0 || sessions.revoked[c.id] != 0) {
			t.Errorf("%s: events %v, %d revocations", name, got, sessions.revoked[c.id])
		}
		if c.event != "" && (len(got) != 1 || got[0] != c.event) {
			t.Errorf("%s: events %v, want [%s]", name, got, c.event)
		}
	}
}
