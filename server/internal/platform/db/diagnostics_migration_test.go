package db_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestDeviceDiagnosticsIsolation proves the table of migration 00103 (plan M12 decision 3): RLS fails closed without
// paddock.org_id, the api and the worker see and change only their organization's bundles, the api inserts but never
// deletes, the worker deletes but never inserts, and no other service role reaches the table.
func TestDeviceDiagnosticsIsolation(t *testing.T) {
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
	devA, devB := uuid.New(), uuid.New()
	bundleA, bundleB := uuid.New(), uuid.New()
	for _, x := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'A', 'active'), ($3, $4, 'B', 'active')",
			[]any{orgA, "da" + orgA.String()[24:], orgB, "db" + orgB.String()[24:]}},
		{"INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'a', 'active'), ($3, $4, 'b', 'active')",
			[]any{devA, orgA, devB, orgB}},
		{`INSERT INTO device_diagnostics (id, organization_id, device_id, requested_by, reason, state)
			VALUES ($1, $2, $3, 'alice', 'slow logins', 'requested'), ($4, $5, $6, 'bob', 'slow logins', 'requested')`,
			[]any{bundleA, orgA, devA, bundleB, orgB, devB}},
	} {
		if _, err := super.Exec(ctx, x.sql, x.args...); err != nil {
			t.Fatal(err)
		}
	}
	// inOrg runs fn in a transaction of conn with paddock.org_id set to org (nil: unset) and rolls it back.
	inOrg := func(conn *pgx.Conn, org *uuid.UUID, fn func(tx pgx.Tx) error) error {
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if org != nil {
			if _, err := tx.Exec(ctx, "SELECT set_config('paddock.org_id', $1, true)", org.String()); err != nil {
				t.Fatal(err)
			}
		}
		return fn(tx)
	}

	for name, dsn := range map[string]string{"paddock_api": env.API, "paddock_worker": env.Worker} {
		conn := connect(dsn)
		t.Run(name, func(t *testing.T) {
			if err := inOrg(conn, nil, func(tx pgx.Tx) error {
				var n int
				return tx.QueryRow(ctx, "SELECT count(*) FROM device_diagnostics").Scan(&n)
			}); err == nil {
				t.Error("SELECT without paddock.org_id succeeded; RLS does not fail closed")
			}
			if err := inOrg(conn, &orgA, func(tx pgx.Tx) error {
				var ids []uuid.UUID
				rows, err := tx.Query(ctx, "SELECT id FROM device_diagnostics WHERE id IN ($1, $2)", bundleA, bundleB)
				if err != nil {
					return err
				}
				for rows.Next() {
					var id uuid.UUID
					if err := rows.Scan(&id); err != nil {
						return err
					}
					ids = append(ids, id)
				}
				if err := rows.Err(); err != nil {
					return err
				}
				if len(ids) != 1 || ids[0] != bundleA {
					t.Errorf("organization A sees %v, want only %s", ids, bundleA)
				}
				own, err := tx.Exec(ctx, "UPDATE device_diagnostics SET state = 'failed' WHERE id = $1", bundleA)
				if err != nil {
					return err
				}
				foreign, err := tx.Exec(ctx, "UPDATE device_diagnostics SET state = 'failed' WHERE id = $1", bundleB)
				if err != nil {
					return err
				}
				if own.RowsAffected() != 1 || foreign.RowsAffected() != 0 {
					t.Errorf("updates: own %d, foreign %d", own.RowsAffected(), foreign.RowsAffected())
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}

	api, worker := connect(env.API), connect(env.Worker)
	t.Run("api inserts in its organization only and never deletes", func(t *testing.T) {
		insert := func(org uuid.UUID, dev uuid.UUID) error {
			return inOrg(api, &orgA, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `INSERT INTO device_diagnostics (id, organization_id, device_id, requested_by, reason, state)
					VALUES ($1, $2, $3, 'alice', 'slow logins', 'requested')`, uuid.New(), org, dev)
				return err
			})
		}
		if err := insert(orgA, devA); err != nil {
			t.Errorf("own organization: %v", err)
		}
		if err := insert(orgB, devB); err == nil {
			t.Error("the api inserted a bundle of another organization")
		}
		err := inOrg(api, &orgA, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, "DELETE FROM device_diagnostics WHERE id = $1", bundleA)
			return err
		})
		wantDenied(t, "paddock_api DELETE", err)
	})
	t.Run("worker deletes but never inserts", func(t *testing.T) {
		err := inOrg(worker, &orgA, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO device_diagnostics (id, organization_id, device_id, requested_by, reason, state)
				VALUES ($1, $2, $3, 'alice', 'slow logins', 'requested')`, uuid.New(), orgA, devA)
			return err
		})
		wantDenied(t, "paddock_worker INSERT", err)
		if err := inOrg(worker, &orgA, func(tx pgx.Tx) error {
			own, err := tx.Exec(ctx, "DELETE FROM device_diagnostics WHERE id = $1", bundleA)
			if err != nil {
				return err
			}
			foreign, err := tx.Exec(ctx, "DELETE FROM device_diagnostics WHERE id = $1", bundleB)
			if err != nil {
				return err
			}
			if own.RowsAffected() != 1 || foreign.RowsAffected() != 0 {
				t.Errorf("deletes: own %d, foreign %d", own.RowsAffected(), foreign.RowsAffected())
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("no other role reaches the table", func(t *testing.T) {
		for name, dsn := range map[string]string{"paddock_compiler": env.Compiler, "paddock_relay": env.Relay,
			"paddock_notifier": env.Notifier, "paddock_escrow_reader": env.EscrowReader, "paddock_revocation": env.Revocation,
			"paddock_backup": env.Backup, "paddock_platform": env.Platform} {
			_, err := connect(dsn).Exec(ctx, "SELECT * FROM device_diagnostics")
			wantDenied(t, name+" SELECT device_diagnostics", err)
		}
	})
}
