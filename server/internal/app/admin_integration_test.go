package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// adminHarness runs the restore commands with the roles paddock-server admin uses: paddock_worker and
// paddock_platform.
func adminHarness(t *testing.T) (*app.Admin, *pgx.Conn, uuid.UUID) {
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
	org := uuid.Must(uuid.NewV7())
	if _, err := super.Exec(ctx, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'Admin', 'active')", org, "a"+org.String()[24:]); err != nil {
		t.Fatal(err)
	}
	corr := "corr-" + t.Name()
	return app.NewAdmin(app.NewActionRunner(worker, platform, func(context.Context) string { return corr }), worker), super, org
}

func countRows(t *testing.T, conn *pgx.Conn, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := conn.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestAdminBumpBundleSeq(t *testing.T) {
	admin, super, org := adminHarness(t)
	ctx := context.Background()
	dev := uuid.Must(uuid.NewV7())
	if _, err := super.Exec(ctx, "INSERT INTO device (id, organization_id, hostname, state, bundle_seq) VALUES ($1, $2, 'h', 'active', 7)", dev, org); err != nil {
		t.Fatal(err)
	}
	for _, by := range []int64{0, -1, app.MaxBundleSeqBump + 1} {
		if _, err := admin.BumpBundleSeq(ctx, by); !errors.Is(err, app.ErrBumpOutOfRange) {
			t.Errorf("--by %d: %v", by, err)
		}
	}
	devices, err := admin.BumpBundleSeq(ctx, 5)
	if err != nil || devices < 1 {
		t.Fatalf("BumpBundleSeq = %d, %v", devices, err)
	}
	if n := countRows(t, super, "SELECT bundle_seq FROM device WHERE id = $1", dev); n != 12 {
		t.Fatalf("bundle_seq %d, want 12", n)
	}
	if n := countRows(t, super, `SELECT count(*) FROM action WHERE correlation_id = $1 AND code = 'platform.bundle_seq_bumped'
		AND outcome = 'success' AND organization_id = $2 AND (params->>'by')::int = 5`, "corr-"+t.Name(), uuid.Nil); n != 1 {
		t.Fatalf("%d platform.bundle_seq_bumped events", n)
	}
}

// TestAdminBumpFunctionIsPlatformOnly: only paddock_platform may execute paddock_admin_bump_bundle_seq.
func TestAdminBumpFunctionIsPlatformOnly(t *testing.T) {
	env := pgtest.SharedPaddock(t)
	for name, dsn := range map[string]string{"api": env.API, "worker": env.Worker, "compiler": env.Compiler, "relay": env.Relay} {
		conn, err := pgx.Connect(context.Background(), dsn)
		if err != nil {
			t.Fatal(err)
		}
		var n int64
		err = conn.QueryRow(context.Background(), "SELECT paddock_admin_bump_bundle_seq(1)").Scan(&n)
		_ = conn.Close(context.Background())
		if err == nil {
			t.Errorf("%s executed paddock_admin_bump_bundle_seq", name)
		}
	}
}

func TestAdminRecompileAll(t *testing.T) {
	admin, super, org := adminHarness(t)
	total, err := admin.RecompileAll(context.Background())
	if err != nil || total < 1 {
		t.Fatalf("RecompileAll = %d, %v", total, err)
	}
	if n := countRows(t, super, `SELECT count(*) FROM action WHERE correlation_id = $1 AND code = 'organization.recompile_requested'
		AND outcome = 'success' AND organization_id = $2`, "corr-"+t.Name(), org); n != 1 {
		t.Fatalf("%d recompile events of the organization", n)
	}
	if n := countRows(t, super, `SELECT count(*) FROM outbox WHERE organization_id = $1 AND subject = $2 AND (payload->>'force')::boolean`,
		org, "state."+org.String()); n != 1 {
		t.Fatalf("%d forced state changes of the organization", n)
	}
}

func TestAdminRebuildCache(t *testing.T) {
	admin, super, _ := adminHarness(t)
	ran := false
	if _, err := admin.RebuildCache(context.Background(), func(context.Context) error { ran = true; return nil }); err != nil || !ran {
		t.Fatalf("RebuildCache = %v (ran %v)", err, ran)
	}
	boom := errors.New("valkey down")
	if _, err := admin.RebuildCache(context.Background(), func(context.Context) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("failing rebuild = %v", err)
	}
	if n := countRows(t, super, `SELECT count(*) FROM action WHERE correlation_id = $1 AND code = 'platform.cache_rebuilt'`, "corr-"+t.Name()); n != 2 {
		t.Fatalf("%d platform.cache_rebuilt events, want 2", n)
	}
	if n := countRows(t, super, `SELECT count(*) FROM action WHERE correlation_id = $1 AND code = 'platform.cache_rebuilt' AND outcome = 'failure'`,
		"corr-"+t.Name()); n != 1 {
		t.Fatalf("%d failed rebuild events, want 1", n)
	}
}
