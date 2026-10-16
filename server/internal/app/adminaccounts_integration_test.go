package app_test

import (
	"context"
	"errors"
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

// revoker counts the sessions it ends per account.
type revoker struct {
	mu      sync.Mutex
	revoked map[uuid.UUID]int
}

func (r *revoker) RevokeAccount(_ context.Context, id uuid.UUID) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revoked[id]++
	return 2, nil
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
	account := func(username, role string) uuid.UUID {
		id := uuid.Must(uuid.NewV7())
		if _, err := super.Exec(ctx, `INSERT INTO admin_account (id, organization_id, authentik_sub, username, display_name, role)
			VALUES ($1, $2, $3, $4, $4, $5)`, id, org, uuid.NewString(), username, role); err != nil {
			t.Fatal(err)
		}
		return id
	}
	unchanged := account("alice@acme.test", "org_admin")
	byMail := account("mail@acme.test", "org_operator")
	moved := account("dave@acme.test", "org_admin")
	removed := account("erin@acme.test", "org_admin")
	inactive := account("frank@acme.test", "org_auditor")
	twice := account("gina@acme.test", "org_operator")
	admins := organization.RoleGroup(slug, organization.GroupAdmins)
	operators := organization.RoleGroup(slug, organization.GroupOperators)
	auditors := organization.RoleGroup(slug, organization.GroupAuditors)
	dir := newDirectory()
	dir.roleGroups = map[string][]ports.IdentityUser{
		admins: {{Username: "Alice@acme.test", Active: true}, {Username: "gina@acme.test", Active: true}},
		operators: {{Username: "m", Email: "mail@acme.test", Active: true}, {Username: "gina@acme.test", Active: true},
			{Username: "nobody@acme.test", Active: true}},
		auditors: {{Username: "dave@acme.test", Active: true}, {Username: "frank@acme.test", Active: false}},
	}
	sessions := &revoker{revoked: map[uuid.UUID]int{}}
	corr := "corr-" + t.Name()
	accounts := app.NewAdminAccounts(app.NewActionRunner(worker, platform, func(context.Context) string { return corr }), worker, dir, sessions)
	sys := httpx.WithRequestID(principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker", OrganizationID: org}), corr)

	dir.fail = errors.New("directory down")
	if err := accounts.Reconcile(sys); err == nil {
		t.Fatal("a failing directory did not fail the round")
	}
	if len(sessions.revoked) != 0 || countRows(t, super, "SELECT count(*) FROM admin_account WHERE organization_id = $1 AND disabled_at IS NOT NULL", org) != 0 {
		t.Fatal("a failing directory changed accounts")
	}
	dir.fail = nil
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
		"unchanged":          {unchanged, "org_admin", false, ""},
		"matched by e-mail":  {byMail, "org_operator", false, ""},
		"moved to auditors":  {moved, "org_auditor", false, "success system role_changed 2 [org_admin] [org_auditor]"},
		"in no role group":   {removed, "org_admin", true, "success system removed 2 [org_admin] []"},
		"deactivated":        {inactive, "org_auditor", true, "success system deactivated 2 [org_auditor] []"},
		"in two role groups": {twice, "org_operator", true, "success system removed 2 [org_operator] []"},
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
