package app_test

import (
	"context"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// TestMCPSettingsIsolated: an organization's MCP policy is invisible in another organization's context, which keeps
// the default (MCP off), and the api role reads no policy at all without paddock.org_id (CLAUDE.md, organization
// isolation).
func TestMCPSettingsIsolated(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	env := pgtest.SharedPaddock(t)
	orgPool, err := db.NewOrgPool(ctx, env.API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(orgPool.Close)
	platformPool, err := db.NewPlatformPool(ctx, env.Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platformPool.Close)
	settings := app.NewMCPSettings(h.runner, orgPool, platformPool)

	globex := uuid.Must(uuid.NewV7())
	if _, err := h.super.Exec(ctx, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'Globex', 'active')",
		globex, "g"+globex.String()[24:]); err != nil {
		t.Fatal(err)
	}
	if _, err := h.super.Exec(ctx, `INSERT INTO organization_mcp_settings (organization_id, enabled, write_enabled, mode, allowed_operations)
		VALUES ($1, true, true, 'selected', '{listDevices}')`, h.org); err != nil {
		t.Fatal(err)
	}
	acme, err := settings.GetOrg(h.admin(principal.RoleOrgAuditor))
	if err != nil || !acme.Enabled || !acme.WriteEnabled || acme.Mode != "selected" || !slices.Equal(acme.AllowedOperations, []string{"listDevices"}) ||
		acme.UpdatedAt == nil {
		t.Fatalf("acme reads its own policy: %+v %v", acme, err)
	}
	other := principal.With(ctx, principal.Principal{Kind: principal.KindAdmin, ID: uuid.Must(uuid.NewV7()), Role: principal.RoleOrgAdmin,
		OrganizationID: globex})
	got, err := settings.GetOrg(other)
	if err != nil || got.Enabled || got.WriteEnabled || got.Mode != "all" || got.AllowedOperations == nil || len(got.AllowedOperations) != 0 ||
		got.UpdatedAt != nil || got.UpdatedBy != nil {
		t.Fatalf("globex sees %+v %v, want the default", got, err)
	}

	conn, err := pgx.Connect(ctx, env.API)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(ctx) })
	var n int
	if err := conn.QueryRow(ctx, "SELECT count(*) FROM organization_mcp_settings").Scan(&n); err == nil {
		t.Errorf("organization_mcp_settings readable without paddock.org_id (%d rows)", n)
	}
}
