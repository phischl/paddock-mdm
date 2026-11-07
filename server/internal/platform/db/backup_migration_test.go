package db_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var backupTables = []string{"backup_key", "backup_target", "backup_target_status", "backup_schedule", "backup_run",
	"backup_restore_plan"}

// TestBackupMigration proves the grants and policies of migrations 00100 and 00107 (plan M15 decision 3, §6.6): the api's organization role and
// every other service role reach none of the six backup tables; paddock_platform manages all of them; paddock_backup
// reads the key, the targets and the schedule, updates only the target's host and test columns, writes run, status
// and restore-plan state, and records audit actions in the platform pseudo-organization only.
func TestBackupMigration(t *testing.T) {
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
	platform, backup := connect(env.Platform), connect(env.Backup)

	t.Run("no other role reaches the tables", func(t *testing.T) {
		for name, dsn := range map[string]string{"paddock_api": env.API, "paddock_worker": env.Worker,
			"paddock_compiler": env.Compiler, "paddock_relay": env.Relay, "paddock_notifier": env.Notifier,
			"paddock_escrow_reader": env.EscrowReader, "paddock_revocation": env.Revocation} {
			c := connect(dsn)
			for _, table := range backupTables {
				_, err := c.Exec(ctx, "SELECT * FROM "+table)
				wantDenied(t, name+" SELECT "+table, err)
			}
		}
	})

	bk := "bk-20261104-7f3a9c1e"
	target, plan, run := uuid.New(), uuid.New(), uuid.New()
	t.Run("platform manages every table", func(t *testing.T) {
		for _, x := range []struct {
			stmt string
			args []any
		}{
			{`INSERT INTO backup_key (key_id, state, ciphertext, fingerprint, challenge_positions, challenge_sha256,
				created_by) VALUES ($1, 'unconfirmed', 'vault:v1:x', '0123456789abcdef', '{1,2,3,4,5,6}', '\x00', 'alice')`,
				[]any{bk}},
			{`INSERT INTO backup_target (id, name, type, settings, host_state, created_by)
				VALUES ($1, 'nas', 'local', '{"path":"/srv/backup"}', 'pending_host', 'alice')`, []any{target}},
			{`INSERT INTO backup_target_status (target_id, kind) VALUES ($1, 'postgres')`, []any{target}},
			{`INSERT INTO backup_schedule (updated_by) VALUES ('alice')`, nil},
			{`INSERT INTO backup_run (id, kind, state, requested_by) VALUES ($1, 'openbao', 'requested', 'alice')`,
				[]any{run}},
			{`INSERT INTO backup_restore_plan (id, kind, source, components, state, created_by)
				VALUES ($1, 'components', 'local', '{openbao}', 'approved', 'alice')`, []any{plan}},
			{`UPDATE backup_key SET attempts = 1 WHERE key_id = $1`, []any{bk}},
			{`UPDATE backup_schedule SET retention_full = 20`, nil},
		} {
			if _, err := platform.Exec(ctx, x.stmt, x.args...); err != nil {
				t.Fatalf("%s: %v", x.stmt, err)
			}
		}
		for _, table := range backupTables {
			var n int
			if err := platform.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil || n != 1 {
				t.Errorf("platform reads %d rows of %s (%v), want 1", n, table, err)
			}
		}
	})

	t.Run("backup role grants", func(t *testing.T) {
		for _, table := range backupTables {
			if _, err := backup.Exec(ctx, "SELECT * FROM "+table); err != nil {
				t.Errorf("paddock_backup SELECT %s: %v", table, err)
			}
		}
		for _, x := range []struct {
			stmt string
			args []any
		}{
			{`UPDATE backup_target SET host_state = 'mounted', test_requested_at = NULL, last_test_at = now(),
				last_test_ok = true, last_test_error = NULL WHERE id = $1`, []any{target}},
			{`UPDATE backup_target_status SET last_success_at = now(), bytes = 42 WHERE target_id = $1`, []any{target}},
			{`INSERT INTO backup_target_status (target_id, kind) VALUES ($1, 'escrow')`, []any{target}},
			{`DELETE FROM backup_target_status WHERE target_id = $1 AND kind = 'escrow'`, []any{target}},
			{`UPDATE backup_run SET state = 'finished', outcome = 'succeeded', finished_at = now() WHERE id = $1`,
				[]any{run}},
			{`INSERT INTO backup_run (id, kind, state) VALUES ($1, 'fleet', 'running')`, []any{uuid.New()}},
			{`UPDATE backup_restore_plan SET state = 'running', started_at = now() WHERE id = $1`, []any{plan}},
		} {
			if _, err := backup.Exec(ctx, x.stmt, x.args...); err != nil {
				t.Errorf("paddock_backup %s: %v", x.stmt, err)
			}
		}
		for _, x := range []struct {
			stmt string
			args []any
		}{
			{`UPDATE backup_target SET name = 'other' WHERE id = $1`, []any{target}},
			{`UPDATE backup_target SET settings = '{}' WHERE id = $1`, []any{target}},
			{`UPDATE backup_target SET credentials_ciphertext = 'x' WHERE id = $1`, []any{target}},
			{`UPDATE backup_target SET enabled = false WHERE id = $1`, []any{target}},
			{`INSERT INTO backup_target (id, name, type, settings, host_state, created_by)
				VALUES ($1, 'x', 'local', '{}', 'pending_host', 'backup')`, []any{uuid.New()}},
			{`DELETE FROM backup_target WHERE id = $1`, []any{target}},
			{`UPDATE backup_key SET state = 'confirmed' WHERE key_id = $1`, []any{bk}},
			{`INSERT INTO backup_key (key_id, state, ciphertext, fingerprint, challenge_positions, challenge_sha256,
				created_by) VALUES ('legacy', 'unconfirmed', 'x', 'x', '{1,2,3,4,5,6}', '\x00', 'backup')`, nil},
			{`DELETE FROM backup_key`, nil},
			{`UPDATE backup_schedule SET retention_full = 30`, nil},
			{`DELETE FROM backup_restore_plan WHERE id = $1`, []any{plan}},
		} {
			_, err := backup.Exec(ctx, x.stmt, x.args...)
			wantDenied(t, "paddock_backup "+x.stmt, err)
		}
	})

	t.Run("backup role audits in the platform pseudo-organization only", func(t *testing.T) {
		insert := func(org *uuid.UUID, actionOrg uuid.UUID) error {
			tx, err := backup.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			if org != nil {
				if _, err := tx.Exec(ctx, "SELECT set_config('paddock.org_id', $1, true)", org.String()); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := tx.Exec(ctx, `INSERT INTO action (id, organization_id, code, status, outcome, actor, params,
				correlation_id, started_at, finished_at) VALUES ($1, $2, 'platform.backup_completed', 'finished', 'success',
				'{"kind":"system","id":"paddock-backup"}', '{}', $3, now(), now())`, uuid.New(), actionOrg, uuid.NewString()); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO outbox (organization_id, subject, msg_id, payload)
				VALUES ($1, 'audit.platform', $2, '{}')`, actionOrg, uuid.NewString()); err != nil {
				return err
			}
			return tx.Commit(ctx)
		}
		if err := insert(&uuid.Nil, uuid.Nil); err != nil {
			t.Fatalf("platform audit action refused: %v", err)
		}
		other := uuid.New()
		if err := insert(&other, other); err == nil {
			t.Error("an organization's audit action was written")
		}
		if err := insert(&uuid.Nil, other); err == nil {
			t.Error("an action outside the context was written")
		}
		if err := insert(nil, uuid.Nil); err == nil {
			t.Error("an action without organization context was written")
		}
	})

	// Migration 00107 (PDK-729 review, minor 3): the backup role inserts outbox rows and never reads them; the
	// insert itself is covered by the subtest above.
	t.Run("backup role cannot read the outbox", func(t *testing.T) {
		tx, err := backup.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, "SELECT set_config('paddock.org_id', $1, true)", uuid.Nil.String()); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, "SELECT * FROM outbox")
		wantDenied(t, "paddock_backup SELECT outbox", err)
	})

	// Migration 00107 (plan M15, amendment 2026-11-05, note b; decisions-alpha9 item 29): the backup role reads the
	// Destroy evidence of every organization and nothing else of theirs; no other role gains anything.
	t.Run("backup role reads only finished successful Destroy evidence", func(t *testing.T) {
		super := connect(env.Super)
		org := uuid.New()
		device := uuid.NewString()
		evidence := uuid.New()
		for _, row := range []struct {
			id                    uuid.UUID
			code, status, outcome string
		}{
			{evidence, "device.escrow_destroyed", "finished", "success"},
			{uuid.New(), "device.escrow_destroyed", "finished", "failure"},
			{uuid.New(), "device.escrow_destroyed", "started", ""},
			{uuid.New(), "device.retired", "finished", "success"},
			{uuid.New(), "device.header_downloaded", "finished", "success"},
		} {
			var outcome, finished any
			if row.status == "finished" {
				outcome, finished = row.outcome, "now()"
			}
			_, err := super.Exec(ctx, `INSERT INTO action (id, organization_id, code, status, outcome, actor, target, params,
				correlation_id, started_at, finished_at) VALUES ($1, $2, $3, $4, $5, '{"kind":"system","id":"issuer"}',
				jsonb_build_object('type', 'device', 'id', $6::text), '{}', $7, now(),
				CASE WHEN $8::text IS NULL THEN NULL ELSE now() END)`,
				row.id, org, row.code, row.status, outcome, device, uuid.NewString(), finished)
			if err != nil {
				t.Fatalf("seed %s %s: %v", row.code, row.status, err)
			}
		}
		visible := func(c *pgx.Conn, ctxOrg *uuid.UUID) ([]uuid.UUID, error) {
			tx, err := c.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			if ctxOrg != nil {
				if _, err := tx.Exec(ctx, "SELECT set_config('paddock.org_id', $1, true)", ctxOrg.String()); err != nil {
					t.Fatal(err)
				}
			}
			rows, err := tx.Query(ctx, "SELECT id FROM action WHERE organization_id = $1 ORDER BY id", org)
			if err != nil {
				return nil, err
			}
			return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		}
		got, err := visible(backup, &uuid.Nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0] != evidence {
			t.Errorf("paddock_backup sees %v of the organization's actions, want only the Destroy evidence %v", got, evidence)
		}
		if got, err := visible(backup, &org); err != nil || len(got) != 0 {
			t.Errorf("paddock_backup in the organization's context sees %v (%v), want nothing", got, err)
		}
		if _, err := visible(backup, nil); err == nil {
			t.Error("paddock_backup read actions without an organization context")
		}
		if _, err := backup.Exec(ctx, "UPDATE action SET params = '{}' WHERE id = $1", evidence); err == nil {
			t.Error("paddock_backup updated the Destroy evidence")
		}
		for name, dsn := range map[string]string{"paddock_api": env.API, "paddock_worker": env.Worker,
			"paddock_compiler": env.Compiler, "paddock_notifier": env.Notifier, "paddock_revocation": env.Revocation} {
			got, err := visible(connect(dsn), &uuid.Nil)
			if err != nil || len(got) != 0 {
				t.Errorf("%s in the platform context sees %v (%v) of an organization's actions", name, got, err)
			}
		}
	})

	t.Run("one active and one pending key", func(t *testing.T) {
		super := connect(env.Super)
		_, err := super.Exec(ctx, `INSERT INTO backup_key (key_id, state, ciphertext, fingerprint, challenge_positions,
			challenge_sha256, created_by) VALUES ('legacy', 'unconfirmed', 'x', 'x', '{1,2,3,4,5,6}', '\x00', 'api')`)
		wantSQLState(t, "second unconfirmed key", err, "23505")
		_, err = super.Exec(ctx, `INSERT INTO backup_key (key_id, state, ciphertext, fingerprint, challenge_positions,
			challenge_sha256, created_by) VALUES ('bk-1', 'confirmed', 'x', 'x', '{1,2,3,4,5,6}', '\x00', 'api')`)
		wantSQLState(t, "malformed key ID", err, "23514")
		_, err = super.Exec(ctx, `INSERT INTO backup_restore_plan (id, kind, source, components, state, created_by)
			VALUES ($1, 'fresh_install', 'local', '{}', 'approved', 'alice')`, uuid.New())
		wantSQLState(t, "second open restore plan", err, "23505")
	})
}

func wantDenied(t *testing.T, what string, err error) {
	t.Helper()
	wantSQLState(t, what, err, "42501")
}

func wantSQLState(t *testing.T, what string, err error, code string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code {
		t.Errorf("%s: %v, want SQLSTATE %s", what, err, code)
	}
}
