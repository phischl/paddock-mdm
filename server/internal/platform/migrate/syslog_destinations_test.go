package migrate_test

import (
	"context"
	"io/fs"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
	"github.com/phischl/paddock-mdm/server/migrations"
)

const syslogDestinationsVersion = 101

// TestSyslogDestinationsMigration: migration 00101 replaces the type check of notification_destination without losing
// a seeded webhook or e-mail destination or its state; afterwards syslog is a type, an unknown type and a port outside
// 1–65535 are refused, and checkpoints defaults to false (plan M12 decision 16).
func TestSyslogDestinationsMigration(t *testing.T) {
	ctx := context.Background()
	env := pgtest.SharedPaddock(t)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	name := "paddock_syslog_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := super.Exec(ctx, "CREATE DATABASE "+name+" OWNER paddock_owner"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = super.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)")
		_ = super.Close(context.Background())
	})

	provider := paddockProvider(t, withDatabase(t, env.Owner, name))
	if _, err := provider.UpTo(ctx, syslogDestinationsVersion-1); err != nil {
		t.Fatal(err)
	}
	db, err := pgx.Connect(ctx, withDatabase(t, env.Super, name))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close(ctx) }()
	org := uuid.New()
	webhook, email := uuid.New(), uuid.New()
	for _, x := range []struct {
		stmt string
		args []any
	}{
		{`INSERT INTO notification_destination (id, organization_id, type, name, filter_mode, url_ciphertext, url_display,
			secret_ciphertext, created_by) VALUES ($1, $2, 'webhook', 'hook', 'security', 'vault:v1:u', 'https://h/…',
			'vault:v1:s', 'test')`, []any{webhook, org}},
		{`INSERT INTO notification_destination (id, organization_id, type, name, filter_mode, recipients, created_by)
			VALUES ($1, $2, 'email', 'mail', 'all', '{secops@example.org}', 'test')`, []any{email, org}},
		{`INSERT INTO notification_destination_state (destination_id, organization_id, forward_seq, cursor_commit_seq)
			VALUES ($1, $3, 7, 42), ($2, $3, 3, 40)`, []any{webhook, email, org}},
	} {
		if _, err := db.Exec(ctx, x.stmt, x.args...); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := provider.UpTo(ctx, syslogDestinationsVersion); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(ctx, `SELECT d.type, d.name, d.checkpoints, d.syslog_host IS NULL, s.forward_seq,
		s.cursor_commit_seq, s.last_checkpoint_day IS NULL AND s.replay_from IS NULL
		FROM notification_destination d JOIN notification_destination_state s ON s.destination_id = d.id ORDER BY d.type`)
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		typ, name            string
		checkpoints, noHost  bool
		forward, cursor      int64
		noCheckpointNoReplay bool
	}
	got, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
		var x row
		err := r.Scan(&x.typ, &x.name, &x.checkpoints, &x.noHost, &x.forward, &x.cursor, &x.noCheckpointNoReplay)
		return x, err
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []row{{"email", "mail", false, true, 3, 40, true}, {"webhook", "hook", false, true, 7, 42, true}}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("destinations after the migration %+v, want %+v", got, want)
	}

	var constraints int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM pg_constraint WHERE conrelid = 'notification_destination'::regclass
		AND conname = 'notification_destination_type_check'`).Scan(&constraints); err != nil {
		t.Fatal(err)
	}
	if constraints != 1 {
		t.Errorf("%d constraints named notification_destination_type_check, want 1", constraints)
	}
	insert := func(typ string, port int) error {
		_, err := db.Exec(ctx, `INSERT INTO notification_destination (id, organization_id, type, name, filter_mode,
			syslog_host, syslog_port, created_by) VALUES ($1, $2, $3, $4, 'security', 'siem.example.org', $5, 'test')`,
			uuid.New(), org, typ, uuid.NewString(), port)
		return err
	}
	if err := insert("syslog", 6514); err != nil {
		t.Errorf("syslog destination refused: %v", err)
	}
	if err := insert("sms", 6514); err == nil {
		t.Error("type sms accepted")
	}
	if err := insert("syslog", 70000); err == nil {
		t.Error("port 70000 accepted")
	}
}

func paddockProvider(t *testing.T, dsn string) *goose.Provider {
	t.Helper()
	sub, err := fs.Sub(migrations.Paddock, "paddock")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB := stdlib.OpenDB(*cfg)
	t.Cleanup(func() { _ = sqlDB.Close() })
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, sub)
	if err != nil {
		t.Fatal(err)
	}
	return provider
}
