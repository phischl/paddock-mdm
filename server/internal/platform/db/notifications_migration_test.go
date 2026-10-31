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
// destinations, their state and fresh test deliveries; the api inserts only fresh test deliveries; a child row cannot
// reference another organization's destination or delivery; the notifier reads destinations but cannot write them,
// serves the nil organization under its own role and records its audit actions; a missing context fails closed.
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

	// A child row naming another organization's destination fails exactly like one naming no destination, so the
	// refusal reveals nothing (PDK-123 maps it to 404 not_found).
	for name, target := range map[string]uuid.UUID{"B's destination": destB, "no destination": uuid.New()} {
		err := inOrg(api, orgA, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO notification_destination_state (destination_id, organization_id)
				VALUES ($1, $2)`, target, orgA)
			return err
		})
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
			t.Fatalf("state for %s: %v, want foreign key violation 23503", name, err)
		}
	}
	refused("a delivery event of A naming B's delivery", inOrg(super, orgA, func(tx pgx.Tx) error {
		delivery := uuid.New()
		if _, err := tx.Exec(ctx, `INSERT INTO notification_delivery (id, destination_id, organization_id, kind)
			VALUES ($1, $2, $3, 'test')`, delivery, destB, orgB); err != nil {
			t.Fatal(err)
		}
		_, err := tx.Exec(ctx, `INSERT INTO notification_delivery_event (destination_id, organization_id, forward_seq,
			event_id, commit_seq, delivery_id) VALUES ($1, $2, 1, $3, 1, $4)`, destA, orgA, uuid.New(), delivery)
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
			forward_seq, event_id, commit_seq, delivery_id) VALUES ($1, $2, 1, $3, 7, $4)`, destB, orgB, uuid.New(), delivery); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO notification_destination_state (destination_id, organization_id,
			cursor_commit_seq, forward_seq) VALUES ($1, $2, 7, 1)`, destB, orgB); err != nil {
			return err
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
