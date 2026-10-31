package db_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestNotificationsMigration proves the isolation of migration 00085 (plan M9 decision 10, ADR 0031 decisions 10 and
// 11): an organization sees only its own destinations, the platform role only the nil organization's and nothing but
// destinations, the state cursor and fresh test deliveries; the api inserts only fresh test deliveries and unresolved
// pseudonym lookups and writes no state result column; a row naming another organization's destination or delivery
// fails exactly like one naming an unknown ID; the notifier reads destinations but cannot write them, writes state
// results and resolutions, serves the nil organization under its own role and records its audit actions; a missing
// context fails closed.
func TestNotificationsMigration(t *testing.T) {
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
	super, api, platform, notifier := connect(env.Super), connect(env.API), connect(env.Platform), connect(env.Notifier)

	orgA, orgB := uuid.New(), uuid.New()
	destA, destB, destP := uuid.New(), uuid.New(), uuid.New()
	for _, d := range []struct{ id, org uuid.UUID }{{destA, orgA}, {destB, orgB}, {destP, uuid.Nil}} {
		if _, err := super.Exec(ctx, `INSERT INTO notification_destination (id, organization_id, type, name, filter_mode,
			url_ciphertext, url_display, created_by) VALUES ($1, $2, 'webhook', 'siem', 'security', 'vault:v1:x',
			'https://hooks.example.org/…', 'test')`, d.id, d.org); err != nil {
			t.Fatal(err)
		}
	}
	deliveryB := uuid.New()
	for _, x := range []struct {
		stmt string
		args []any
	}{
		{`INSERT INTO notification_destination_state (destination_id, organization_id) VALUES ($1, $2)`,
			[]any{destB, orgB}},
		{`INSERT INTO notification_delivery (id, destination_id, organization_id, kind) VALUES ($1, $2, $3, 'events')`,
			[]any{deliveryB, destB, orgB}},
		{`INSERT INTO notification_delivery_event (destination_id, organization_id, forward_seq, event_id, commit_seq,
			delivery_id) VALUES ($1, $2, 1, gen_random_uuid(), 1, $3)`, []any{destB, orgB, deliveryB}},
		{`INSERT INTO notification_pseudonym_lookup (id, organization_id, pseudonym, requested_by)
			VALUES (gen_random_uuid(), $1, 'u_x', 'admin')`, []any{orgB}},
	} {
		if _, err := super.Exec(ctx, x.stmt, x.args...); err != nil {
			t.Fatal(err)
		}
	}

	// inOrg runs fn in a transaction of conn with paddock.org_id = org and rolls back.
	inOrg := func(conn *pgx.Conn, org uuid.UUID, fn func(tx pgx.Tx) error) error {
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, "SELECT set_config('paddock.org_id', $1, true)", org.String()); err != nil {
			t.Fatal(err)
		}
		return fn(tx)
	}
	ids := func(tx pgx.Tx) []uuid.UUID {
		rows, err := tx.Query(ctx, "SELECT id FROM notification_destination ORDER BY id")
		if err != nil {
			t.Fatal(err)
		}
		out, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	must := func(what string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}
	refused := func(what string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s succeeded; want a refusal", what)
		}
	}

	must("api", inOrg(api, orgA, func(tx pgx.Tx) error {
		if got := ids(tx); len(got) != 1 || got[0] != destA {
			t.Fatalf("api in A sees %v, want only %s", got, destA)
		}
		_, err := tx.Exec(ctx, `INSERT INTO notification_delivery (id, destination_id, organization_id, kind)
			VALUES ($1, $2, $3, 'test')`, uuid.New(), destA, orgA)
		return err
	}))
	refused("api insert into B", inOrg(api, orgA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO notification_destination (id, organization_id, type, name, filter_mode,
			created_by) VALUES ($1, $2, 'email', 'x', 'all', 'test')`, uuid.New(), orgB)
		return err
	}))
	refused("api events delivery", inOrg(api, orgA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO notification_delivery (id, destination_id, organization_id, kind)
			VALUES ($1, $2, $3, 'events')`, uuid.New(), destA, orgA)
		return err
	}))
	must("api delete cascades", inOrg(api, orgA, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO notification_delivery (id, destination_id, organization_id, kind)
			VALUES ($1, $2, $3, 'test')`, uuid.New(), destA, orgA); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, "DELETE FROM notification_destination WHERE id = $1", destA)
		if err == nil && tag.RowsAffected() != 1 {
			t.Fatalf("deleted %d rows", tag.RowsAffected())
		}
		return err
	}))
	for col, value := range map[string]string{
		"delivered_at": "now()", "attempts": "1", "forward_from": "1", "forward_to": "1", "event_count": "1",
		"last_error": "'x'",
	} {
		refused("api test delivery with "+col, inOrg(api, orgA, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO notification_delivery (id, destination_id, organization_id, kind, `+col+
				`) VALUES ($1, $2, $3, 'test', `+value+`)`, uuid.New(), destA, orgA)
			return err
		}))
	}

	// A row of A naming B's destination or delivery fails with the same foreign key violation as one naming an ID that
	// does not exist, even where B already has a row with that key (composite keys and references, so neither a
	// primary key collision nor the reference reveals B's row; PDK-123 maps the violation to 404 not_found).
	sameRefusal := func(what string, stmt string, args func(target uuid.UUID) []any, targetB uuid.UUID) {
		t.Helper()
		for name, target := range map[string]uuid.UUID{"B's": targetB, "an unknown": uuid.New()} {
			err := inOrg(super, orgA, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, stmt, args(target)...)
				return err
			})
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
				t.Errorf("%s naming %s ID: %v, want foreign key violation 23503", what, name, err)
			}
		}
	}
	sameRefusal("state", `INSERT INTO notification_destination_state (destination_id, organization_id) VALUES ($1, $2)`,
		func(target uuid.UUID) []any { return []any{target, orgA} }, destB)
	sameRefusal("delivery", `INSERT INTO notification_delivery (id, destination_id, organization_id, kind)
		VALUES (gen_random_uuid(), $1, $2, 'test')`, func(target uuid.UUID) []any { return []any{target, orgA} }, destB)
	sameRefusal("event of B's destination", `INSERT INTO notification_delivery_event (destination_id, organization_id,
		forward_seq, event_id, commit_seq, delivery_id) VALUES ($1, $2, 1, gen_random_uuid(), 1, $3)`,
		func(target uuid.UUID) []any { return []any{target, orgA, deliveryB} }, destB)
	sameRefusal("event of B's delivery", `INSERT INTO notification_delivery_event (destination_id, organization_id,
		forward_seq, event_id, commit_seq, delivery_id) VALUES ($1, $2, 9, gen_random_uuid(), 1, $3)`,
		func(target uuid.UUID) []any { return []any{destA, orgA, target} }, deliveryB)

	// State columns: the api and the platform role write only the cursor (and the key when creating the row); every
	// result column is the notifier's.
	for _, role := range []struct {
		name string
		conn *pgx.Conn
		org  uuid.UUID
		dest uuid.UUID
	}{{"api", api, orgA, destA}, {"platform", platform, uuid.Nil, destP}} {
		must(role.name+" state cursor", inOrg(role.conn, role.org, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `INSERT INTO notification_destination_state (destination_id, organization_id,
				cursor_commit_seq) VALUES ($1, $2, 42)`, role.dest, role.org); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE notification_destination_state SET cursor_commit_seq = 43
				WHERE destination_id = $1`, role.dest)
			return err
		}))
		for _, col := range []string{
			"status = 'stalled'", "consecutive_failures = 1", "last_test_ok = true", "last_test_at = now()",
			"last_test_error = 'x'", "last_success_at = now()", "forward_seq = 5", "pending_delivery_id = gen_random_uuid()",
			"last_error = 'x'", "next_attempt_at = now()",
		} {
			refused(role.name+" state update "+col, inOrg(role.conn, role.org, func(tx pgx.Tx) error {
				if _, err := tx.Exec(ctx, `INSERT INTO notification_destination_state (destination_id, organization_id)
					VALUES ($1, $2)`, role.dest, role.org); err != nil {
					t.Fatal(err)
				}
				_, err := tx.Exec(ctx, "UPDATE notification_destination_state SET "+col+" WHERE destination_id = $1",
					role.dest)
				return err
			}))
		}
		refused(role.name+" state insert of a result column", inOrg(role.conn, role.org, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO notification_destination_state (destination_id, organization_id, status)
				VALUES ($1, $2, 'stalled')`, role.dest, role.org)
			return err
		}))
		refused(role.name+" state delete", inOrg(role.conn, role.org, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, "DELETE FROM notification_destination_state")
			return err
		}))
	}

	// Pseudonym lookups: the api requests, reads and deletes; it cannot store a resolution.
	must("api lookup request", inOrg(api, orgA, func(tx pgx.Tx) error {
		id := uuid.New()
		if _, err := tx.Exec(ctx, `INSERT INTO notification_pseudonym_lookup (id, organization_id, pseudonym,
			requested_by) VALUES ($1, $2, 'u_x', 'admin')`, id, orgA); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "DELETE FROM notification_pseudonym_lookup WHERE id = $1", id)
		return err
	}))
	for col, value := range map[string]string{"resolved_username": "'alice'", "resolved_at": "now()"} {
		refused("api lookup with "+col, inOrg(api, orgA, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO notification_pseudonym_lookup (id, organization_id, pseudonym,
				requested_by, `+col+`) VALUES ($1, $2, 'u_x', 'admin', `+value+`)`, uuid.New(), orgA)
			return err
		}))
	}
	refused("api lookup update", inOrg(api, orgA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "UPDATE notification_pseudonym_lookup SET resolved_username = 'alice'")
		return err
	}))

	refused("api without organization context", func() error {
		_, err := api.Exec(ctx, "SELECT count(*) FROM notification_destination")
		return err
	}())

	must("platform", inOrg(platform, uuid.Nil, func(tx pgx.Tx) error {
		if got := ids(tx); len(got) != 1 || got[0] != destP {
			t.Fatalf("platform sees %v, want only %s", got, destP)
		}
		return nil
	}))
	must("platform test delivery", inOrg(platform, uuid.Nil, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO notification_delivery (id, destination_id, organization_id, kind,
			requested_by) VALUES ($1, $2, $3, 'test', 'root')`, uuid.New(), destP, uuid.Nil)
		return err
	}))
	for name, stmt := range map[string]string{
		"events delivery": `INSERT INTO notification_delivery (id, destination_id, organization_id, kind)
			VALUES (gen_random_uuid(), '` + destP.String() + `', '` + uuid.Nil.String() + `', 'events')`,
		"delivered test": `INSERT INTO notification_delivery (id, destination_id, organization_id, kind, attempts)
			VALUES (gen_random_uuid(), '` + destP.String() + `', '` + uuid.Nil.String() + `', 'test', 1)`,
		"delivery update":  `UPDATE notification_delivery SET attempts = 1`,
		"delivery event":   `SELECT count(*) FROM notification_delivery_event`,
		"pseudonym key":    `SELECT count(*) FROM notification_pseudonym_key`,
		"pseudonym lookup": `SELECT count(*) FROM notification_pseudonym_lookup`,
	} {
		refused("platform "+name, inOrg(platform, uuid.Nil, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, stmt)
			return err
		}))
	}
	must("notifier in the platform scope", inOrg(notifier, uuid.Nil, func(tx pgx.Tx) error {
		if got := ids(tx); len(got) != 1 || got[0] != destP {
			t.Fatalf("notifier in the nil organization sees %v, want only %s", got, destP)
		}
		_, err := tx.Exec(ctx, `INSERT INTO notification_delivery (id, destination_id, organization_id, kind)
			VALUES ($1, $2, $3, 'heartbeat')`, uuid.New(), destP, uuid.Nil)
		return err
	}))
	refused("platform insert into A", inOrg(platform, uuid.Nil, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO notification_destination (id, organization_id, type, name, filter_mode,
			created_by) VALUES ($1, $2, 'email', 'x', 'all', 'test')`, uuid.New(), orgA)
		return err
	}))

	must("notifier", inOrg(notifier, orgB, func(tx pgx.Tx) error {
		if got := ids(tx); len(got) != 1 || got[0] != destB {
			t.Fatalf("notifier in B sees %v, want only %s", got, destB)
		}
		delivery := uuid.New()
		if _, err := tx.Exec(ctx, `INSERT INTO notification_delivery (id, destination_id, organization_id, kind,
			forward_from, forward_to, event_count) VALUES ($1, $2, $3, 'events', 1, 1, 1)`, delivery, destB, orgB); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO notification_delivery_event (destination_id, organization_id,
			forward_seq, event_id, commit_seq, delivery_id) VALUES ($1, $2, 2, $3, 7, $4)`, destB, orgB, uuid.New(), delivery); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE notification_destination_state SET cursor_commit_seq = 7, forward_seq = 2,
			status = 'stalled', consecutive_failures = 3, last_test_ok = true, last_test_at = now(),
			pending_delivery_id = $3 WHERE destination_id = $1 AND organization_id = $2`, destB, orgB, delivery); err != nil {
			return err
		}
		if tag, err := tx.Exec(ctx, `UPDATE notification_pseudonym_lookup SET resolved_username = 'alice',
			resolved_at = now()`); err != nil || tag.RowsAffected() != 1 {
			t.Fatalf("notifier resolves a lookup: %d rows, %v", tag.RowsAffected(), err)
		}
		action := uuid.New()
		if _, err := tx.Exec(ctx, `INSERT INTO action (id, organization_id, code, status, actor, correlation_id,
			started_at) VALUES ($1, $2, 'notification.destination_stalled', 'started', '{"type":"system"}', 'c', now())`,
			action, orgB); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE action SET status = 'finished', outcome = 'success', finished_at = now()
			WHERE id = $1`, action); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO outbox (organization_id, subject, msg_id, payload)
			VALUES ($1, 'audit.x.system', $2, '{}')`, orgB, uuid.NewString())
		return err
	}))
	refused("notifier writes a destination", inOrg(notifier, orgB, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO notification_destination (id, organization_id, type, name, filter_mode,
			created_by) VALUES ($1, $2, 'email', 'x', 'all', 'test')`, uuid.New(), orgB)
		return err
	}))
	refused("notifier updates a destination", inOrg(notifier, orgB, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "UPDATE notification_destination SET enabled = false WHERE id = $1", destB)
		return err
	}))
	refused("notifier action of another organization", inOrg(notifier, orgB, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO action (id, organization_id, code, status, actor, correlation_id,
			started_at) VALUES ($1, $2, 'x', 'started', '{}', 'c', now())`, uuid.New(), orgA)
		return err
	}))
	must("notifier organization ids", func() error {
		_, err := notifier.Exec(ctx, "SELECT paddock_organization_ids()")
		return err
	}())
}
