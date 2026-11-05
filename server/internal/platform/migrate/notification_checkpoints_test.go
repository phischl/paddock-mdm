package migrate_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

const notificationCheckpointsVersion = 105

// TestNotificationCheckpointsMigration: migration 00105 replaces the kind check of notification_delivery without losing
// seeded deliveries; afterwards a checkpoint needs its day and only a checkpoint has one, and replay_from is at least 1
// (plan M12 decisions 20 and 21).
func TestNotificationCheckpointsMigration(t *testing.T) {
	ctx := context.Background()
	env := pgtest.SharedPaddock(t)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	name := "paddock_checkpoints_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := super.Exec(ctx, "CREATE DATABASE "+name+" OWNER paddock_owner"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = super.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)")
		_ = super.Close(context.Background())
	})

	provider := paddockProvider(t, withDatabase(t, env.Owner, name))
	if _, err := provider.UpTo(ctx, notificationCheckpointsVersion-1); err != nil {
		t.Fatal(err)
	}
	db, err := pgx.Connect(ctx, withDatabase(t, env.Super, name))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close(ctx) }()
	org, dest := uuid.New(), uuid.New()
	exec := func(stmt string, args ...any) error {
		_, err := db.Exec(ctx, stmt, args...)
		return err
	}
	for _, stmt := range []string{
		`INSERT INTO notification_destination (id, organization_id, type, name, filter_mode, url_ciphertext, url_display,
			secret_ciphertext, created_by) VALUES ($1, $2, 'webhook', 'hook', 'security', 'vault:v1:u', 'https://h/…',
			'vault:v1:s', 'test')`,
		`INSERT INTO notification_destination_state (destination_id, organization_id, forward_seq) VALUES ($1, $2, 7)`,
		`INSERT INTO notification_delivery (id, destination_id, organization_id, kind, forward_from, forward_to, event_count)
			VALUES (gen_random_uuid(), $1, $2, 'events', 1, 7, 7), (gen_random_uuid(), $1, $2, 'heartbeat', NULL, NULL, 0),
			(gen_random_uuid(), $1, $2, 'test', NULL, NULL, 0)`,
	} {
		if err := exec(stmt, dest, org); err != nil {
			t.Fatal(err)
		}
	}
	if err := exec(`INSERT INTO notification_delivery (id, destination_id, organization_id, kind) VALUES
		(gen_random_uuid(), $1, $2, 'checkpoint')`, dest, org); err == nil {
		t.Fatal("checkpoint accepted before the migration")
	}

	if _, err := provider.UpTo(ctx, notificationCheckpointsVersion); err != nil {
		t.Fatal(err)
	}
	var kinds string
	if err := db.QueryRow(ctx, `SELECT string_agg(kind, ',' ORDER BY kind) FROM notification_delivery
		WHERE checkpoint_day IS NULL`).Scan(&kinds); err != nil || kinds != "events,heartbeat,test" {
		t.Fatalf("deliveries after the migration %q (%v)", kinds, err)
	}
	var constraints int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM pg_constraint WHERE conrelid = 'notification_delivery'::regclass
		AND conname = 'notification_delivery_kind_check'`).Scan(&constraints); err != nil || constraints != 1 {
		t.Fatalf("kind check constraints %d (%v)", constraints, err)
	}
	insert := `INSERT INTO notification_delivery (id, destination_id, organization_id, kind, forward_from, forward_to,
		checkpoint_day) VALUES (gen_random_uuid(), $1, $2, $3, 8, 8, $4::date)`
	if err := exec(insert, dest, org, "checkpoint", "2026-11-03"); err != nil {
		t.Fatalf("checkpoint refused: %v", err)
	}
	for _, c := range []struct{ kind, day string }{{"checkpoint", ""}, {"events", "2026-11-03"}, {"bogus", ""}} {
		var day any
		if c.day != "" {
			day = c.day
		}
		if err := exec(insert, dest, org, c.kind, day); err == nil {
			t.Errorf("%s with day %q accepted", c.kind, c.day)
		}
	}
	if err := exec(`UPDATE notification_destination_state SET replay_from = 0 WHERE destination_id = $1`, dest); err == nil {
		t.Error("replay_from 0 accepted")
	}
}
