package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// TestLoginEnablesTheAccount: a successful login clears disabled_at, which the step-up check and the worker round set
// when the account lost its role (plan M8s decision 21).
func TestLoginEnablesTheAccount(t *testing.T) {
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	org, err := db.NewOrgPool(ctx, env.API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(org.Close)
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
	orgID := uuid.Must(uuid.NewV7())
	slug := "l" + orgID.String()[24:]
	if _, err := super.Exec(ctx, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'Login', 'active')", orgID, slug); err != nil {
		t.Fatal(err)
	}
	account, subject := uuid.Must(uuid.NewV7()), uuid.NewString()
	if _, err := super.Exec(ctx, `INSERT INTO admin_account (id, organization_id, authentik_sub, username, display_name, role, disabled_at)
		VALUES ($1, $2, $3, 'alice', 'alice', 'org_auditor', now())`, account, orgID, subject); err != nil {
		t.Fatal(err)
	}
	accounts := app.NewAccounts(app.NewActionRunner(org, platform, httpx.RequestID), org, platform, nil)
	res, err := accounts.Login(ctx, app.LoginIdentity{Subject: subject, Username: "alice", IP: "192.0.2.1"},
		app.LoginRole{Slug: slug, Role: principal.RoleOrgAdmin})
	if err != nil || res.Principal.ID != account {
		t.Fatalf("login: %+v %v", res, err)
	}
	var role string
	var disabled bool
	if err := super.QueryRow(ctx, "SELECT role, disabled_at IS NOT NULL FROM admin_account WHERE id = $1", account).Scan(&role, &disabled); err != nil {
		t.Fatal(err)
	}
	if role != "org_admin" || disabled {
		t.Fatalf("after login: role %s, disabled %v", role, disabled)
	}

	// The session opens inside the login's transaction while the account row is locked, so a concurrent revocation
	// (which updates the row first) cannot miss it; a session that cannot be opened fails the login, recorded as failed.
	var locked error
	res, err = accounts.Login(ctx, app.LoginIdentity{Subject: subject, Username: "alice", IP: "192.0.2.1",
		OpenSession: func(context.Context, principal.Principal) error {
			_, locked = super.Exec(ctx, "SELECT 1 FROM admin_account WHERE id = $1 FOR UPDATE NOWAIT", account)
			return nil
		}}, app.LoginRole{Slug: slug, Role: principal.RoleOrgAdmin})
	if err != nil || locked == nil {
		t.Fatalf("login: %v; the account row was not locked while the session opened (%v)", err, locked)
	}
	failing := app.LoginIdentity{Subject: subject, Username: "alice", IP: "192.0.2.1",
		OpenSession: func(context.Context, principal.Principal) error { return errors.New("session store down") }}
	if _, err := accounts.Login(ctx, failing, app.LoginRole{Slug: slug, Role: principal.RoleOrgAdmin}); err == nil {
		t.Fatal("login without a session succeeded")
	}
	var outcome string
	if err := super.QueryRow(ctx, `SELECT outcome FROM action WHERE code = 'admin.login' AND target->>'id' = $1
		ORDER BY started_at DESC, id DESC LIMIT 1`, account.String()).Scan(&outcome); err != nil || outcome != "failure" {
		t.Fatalf("last admin.login outcome %q %v, want failure", outcome, err)
	}
}

// TestLoginRoleSwitch: a LoginRole that still names both roles of a two-role identity is refused before anything is
// recorded or opened, and a switch records previous_role on the admin.login of either scope (ADR 0045 decisions 2, 3).
func TestLoginRoleSwitch(t *testing.T) {
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	org, err := db.NewOrgPool(ctx, env.API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(org.Close)
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
	orgID := uuid.Must(uuid.NewV7())
	slug := "s" + orgID.String()[24:]
	if _, err := super.Exec(ctx, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'Switch', 'active')", orgID, slug); err != nil {
		t.Fatal(err)
	}
	corr := "corr-" + t.Name()
	ctx = httpx.WithRequestID(ctx, corr)
	accounts := app.NewAccounts(app.NewActionRunner(org, platform, httpx.RequestID), org, platform, nil)
	subject := uuid.NewString()
	opened := 0
	id := app.LoginIdentity{Subject: subject, Username: "carol", IP: "192.0.2.1",
		OpenSession: func(context.Context, principal.Principal) error { opened++; return nil }}

	_, err = accounts.Login(ctx, id, app.LoginRole{Platform: true, Slug: slug, Role: principal.RoleOrgAdmin, Slugs: []string{slug}})
	if !errors.Is(err, app.ErrAmbiguousRole) {
		t.Fatalf("login with both roles: %v, want ErrAmbiguousRole", err)
	}
	if n := countRows(t, super, "SELECT count(*) FROM action WHERE correlation_id = $1", corr); n != 0 || opened != 0 {
		t.Fatalf("ambiguous login recorded %d actions and opened %d sessions, want none", n, opened)
	}
	if n := countRows(t, super, "SELECT count(*) FROM admin_account WHERE authentik_sub = $1", subject); n != 0 {
		t.Fatalf("ambiguous login wrote %d accounts", n)
	}

	previousRole := func(scope uuid.UUID) (string, bool) {
		t.Helper()
		var role *string
		if err := super.QueryRow(ctx, `SELECT params->>'previous_role' FROM action WHERE correlation_id = $1
			AND code = 'admin.login' AND organization_id = $2 ORDER BY started_at DESC, id DESC LIMIT 1`, corr, scope).Scan(&role); err != nil {
			t.Fatal(err)
		}
		if role == nil {
			return "", false
		}
		return *role, true
	}
	if _, err := accounts.Login(ctx, id, app.LoginRole{Slug: slug, Role: principal.RoleOrgAdmin}); err != nil {
		t.Fatal(err)
	}
	if role, ok := previousRole(orgID); ok {
		t.Fatalf("plain sign-in recorded previous_role %q", role)
	}
	switched := id
	switched.PreviousRole = principal.RoleOrgAdmin
	res, err := accounts.Login(ctx, switched, app.LoginRole{Platform: true, Role: principal.RolePlatform})
	if err != nil || res.Principal.Kind != principal.KindPlatformAdmin {
		t.Fatalf("switch to platform: %+v %v", res, err)
	}
	if role, _ := previousRole(audit.PlatformOrganizationID); role != "org_admin" {
		t.Fatalf("platform admin.login previous_role %q, want org_admin", role)
	}
	switched.PreviousRole = principal.RolePlatform
	res, err = accounts.Login(ctx, switched, app.LoginRole{Slug: slug, Role: principal.RoleOrgAdmin})
	if err != nil || res.Principal.OrganizationID != orgID {
		t.Fatalf("switch back: %+v %v", res, err)
	}
	if role, _ := previousRole(orgID); role != "platform_admin" {
		t.Fatalf("organization admin.login previous_role %q, want platform_admin", role)
	}
	if opened != 3 {
		t.Fatalf("opened %d sessions, want 3", opened)
	}
}

// TestLoginChannel: admin.login records the channel param, portal without LoginIdentity.Channel and mcp with it, for
// organization and platform sign-ins and for a refused sign-in (ADR 0044 amendment A2).
func TestLoginChannel(t *testing.T) {
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	org, err := db.NewOrgPool(ctx, env.API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(org.Close)
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
	orgID := uuid.Must(uuid.NewV7())
	slug := "c" + orgID.String()[24:]
	if _, err := super.Exec(ctx, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'Channel', 'active')", orgID, slug); err != nil {
		t.Fatal(err)
	}
	accounts := app.NewAccounts(app.NewActionRunner(org, platform, httpx.RequestID), org, platform, nil)
	for _, tc := range []struct {
		name    string
		channel principal.Channel
		role    app.LoginRole
		want    string
		outcome string
	}{
		{"portal organization", "", app.LoginRole{Slug: slug, Role: principal.RoleOrgAdmin}, "portal", "success"},
		{"mcp organization", principal.ChannelMCP, app.LoginRole{Slug: slug, Role: principal.RoleOrgOperator}, "mcp", "success"},
		{"portal platform", "", app.LoginRole{Platform: true, Role: principal.RolePlatform}, "portal", "success"},
		{"mcp platform", principal.ChannelMCP, app.LoginRole{Platform: true, Role: principal.RolePlatform}, "mcp", "success"},
		{"mcp denied", principal.ChannelMCP, app.LoginRole{Denied: true, Slugs: []string{slug}, DenialReason: "no_role"}, "mcp", "denied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			corr := "corr-" + t.Name()
			id := app.LoginIdentity{Subject: uuid.NewString(), Username: "dave", IP: "192.0.2.1", Channel: tc.channel}
			_, err := accounts.Login(httpx.WithRequestID(ctx, corr), id, tc.role)
			if (tc.outcome == "success") != (err == nil) {
				t.Fatalf("login: %v", err)
			}
			var channel, outcome string
			if err := super.QueryRow(ctx, `SELECT coalesce(params->>'channel', ''), outcome FROM action
				WHERE correlation_id = $1 AND code = 'admin.login'`, corr).Scan(&channel, &outcome); err != nil {
				t.Fatal(err)
			}
			if channel != tc.want || outcome != tc.outcome {
				t.Fatalf("admin.login channel %q outcome %q, want %q/%q", channel, outcome, tc.want, tc.outcome)
			}
		})
	}
}

// TestAccountState covers the per-request account check of MCP sessions (plan M14 §3.3 item 14) for both account
// kinds: role, deactivation and write opt-in of the principal's own row; a missing row is unauthenticated.
func TestAccountState(t *testing.T) {
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	org, err := db.NewOrgPool(ctx, env.API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(org.Close)
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
	orgID := uuid.Must(uuid.NewV7())
	if _, err := super.Exec(ctx, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'State', 'active')",
		orgID, "s"+orgID.String()[24:]); err != nil {
		t.Fatal(err)
	}
	accounts := app.NewAccounts(app.NewActionRunner(org, platform, httpx.RequestID), org, platform, nil)

	admin := principal.Principal{Kind: principal.KindAdmin, ID: uuid.Must(uuid.NewV7()), Role: principal.RoleOrgAdmin, OrganizationID: orgID}
	if _, err := super.Exec(ctx, `INSERT INTO admin_account (id, organization_id, authentik_sub, username, display_name, role)
		VALUES ($1, $2, $3, 'erin', 'erin', 'org_operator')`, admin.ID, orgID, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if st, err := accounts.AccountState(ctx, admin); err != nil || st != (app.AccountState{Role: principal.RoleOrgOperator}) {
		t.Fatalf("admin: %+v %v", st, err)
	}
	if _, err := super.Exec(ctx, "UPDATE admin_account SET disabled_at = now(), mcp_write_enabled_at = now() WHERE id = $1", admin.ID); err != nil {
		t.Fatal(err)
	}
	if st, err := accounts.AccountState(ctx, admin); err != nil || !st.Disabled || !st.MCPWriteEnabled {
		t.Fatalf("disabled admin: %+v %v", st, err)
	}
	other := admin
	other.OrganizationID = uuid.Must(uuid.NewV7())
	if _, err := accounts.AccountState(ctx, other); !errors.Is(err, problem.Unauthenticated) {
		t.Fatalf("the row seen from another organization: %v", err)
	}

	root := principal.Principal{Kind: principal.KindPlatformAdmin, ID: uuid.Must(uuid.NewV7()), Role: principal.RolePlatform}
	if _, err := super.Exec(ctx, `INSERT INTO platform_admin (id, authentik_sub, username, display_name, mcp_write_enabled_at)
		VALUES ($1, $2, 'root', 'root', now())`, root.ID, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if st, err := accounts.AccountState(ctx, root); err != nil || st != (app.AccountState{Role: principal.RolePlatform, MCPWriteEnabled: true}) {
		t.Fatalf("platform admin: %+v %v", st, err)
	}
	root.ID = uuid.Must(uuid.NewV7())
	if _, err := accounts.AccountState(ctx, root); !errors.Is(err, problem.Unauthenticated) {
		t.Fatalf("missing platform admin: %v", err)
	}
}
