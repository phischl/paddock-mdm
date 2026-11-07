package db_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

// TestBundleSeqHighWaterMigration proves migration 00110 (decisions-alpha9 item 68): the backup role reads the highest
// device.bundle_seq of every organization through paddock_backup_bundle_seq_high_water, still reads no device row
// itself, and no other service role may call the function.
func TestBundleSeqHighWaterMigration(t *testing.T) {
	env := sharedPaddock(t)
	ctx := context.Background()
	connect := func(dsn string) *pgx.Conn {
		c, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close(ctx) })
		return c
	}
	super := connect(env.Super)
	orgA, orgB := uuid.New(), uuid.New()
	// Far above anything other tests of the shared database compile, so the highest is this test's.
	const low, high = int64(8_000_000_000_000_000), int64(8_000_000_000_000_007)
	for _, x := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'A', 'active'), ($3, $4, 'B', 'active')",
			[]any{orgA, "ha" + orgA.String()[24:], orgB, "hb" + orgB.String()[24:]}},
		{`INSERT INTO device (id, organization_id, hostname, state, bundle_seq) VALUES ($1, $2, 'a', 'active', $3),
			($4, $5, 'b', 'active', $6)`, []any{uuid.New(), orgA, low, uuid.New(), orgB, high}},
	} {
		if _, err := super.Exec(ctx, x.sql, x.args...); err != nil {
			t.Fatal(err)
		}
	}

	pool, err := db.NewBackupPool(ctx, env.Backup, db.Options{ApplicationName: "test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	got, err := pool.BundleSeqHighWater(ctx)
	if err != nil || got != high {
		t.Fatalf("BundleSeqHighWater = %d, %v; want %d across organizations", got, err, high)
	}

	backup := connect(env.Backup)
	_, err = backup.Exec(ctx, "SELECT bundle_seq FROM device")
	wantDenied(t, "paddock_backup SELECT device", err)
	for name, dsn := range map[string]string{"paddock_api": env.API, "paddock_platform": env.Platform,
		"paddock_worker": env.Worker, "paddock_compiler": env.Compiler, "paddock_relay": env.Relay,
		"paddock_notifier": env.Notifier, "paddock_escrow_reader": env.EscrowReader, "paddock_revocation": env.Revocation} {
		_, err := connect(dsn).Exec(ctx, "SELECT paddock_backup_bundle_seq_high_water()")
		wantDenied(t, name+" paddock_backup_bundle_seq_high_water()", err)
	}
}
