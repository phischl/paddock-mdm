package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
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
