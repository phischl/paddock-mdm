package db_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

// TestOffboardDeleteBatchFrom proves paddock_offboard_delete_batch_from (plan M17 amendment 2026-11-16 q point 5): the
// same owner, grants and status check as paddock_offboard_delete_batch; it starts at the first registered table with
// delete_order >= from_order, reports the delete_order it worked on, resumes there, returns (0, NULL) for an empty
// tail, and does not see a straggler row in a table before from_order (paddock_offboard_finalize catches that one).
func TestOffboardDeleteBatchFrom(t *testing.T) {
	env := sharedPaddock(t)
	ctx := context.Background()
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	worker, err := db.NewOrgPool(ctx, env.Worker, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(worker.Close)
	batch := func(org uuid.UUID, maxRows int32, from *int32) (b pgstore.OffboardDeleteBatchFromRow, err error) {
		err = worker.InOrgOffboarding(orgCtx(org), func(ctx context.Context, q *pgstore.Queries) error {
			b, err = q.OffboardDeleteBatchFrom(ctx, pgstore.OffboardDeleteBatchFromParams{MaxRows: maxRows, FromOrder: from})
			return err
		})
		return b, err
	}
	at := func(o int32) *int32 { return &o }
	count := func(table string, org uuid.UUID) int64 {
		t.Helper()
		var n int64
		sql := fmt.Sprintf("SELECT count(*) FROM %s WHERE organization_id = $1", pgx.Identifier{table}.Sanitize())
		if err := super.QueryRow(ctx, sql, org).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	order := func(table string) int32 {
		t.Helper()
		var o int32
		if err := super.QueryRow(ctx, "SELECT delete_order FROM offboarding_table WHERE table_name = $1", table).Scan(&o); err != nil {
			t.Fatal(err)
		}
		return o
	}

	gone := offboardingFixture(ctx, t, super, 2500)
	kept := offboardingFixture(ctx, t, super, 10)
	keptRows := offboardingRows(ctx, t, super, kept)
	watched, members := order("watched_unit"), order("device_group_member")

	t.Run("definer function owned by paddock_owner with a pinned search path", func(t *testing.T) {
		var owner string
		var definer bool
		var config []string
		if err := super.QueryRow(ctx, `SELECT pg_get_userbyid(proowner), prosecdef, coalesce(proconfig, '{}')
			FROM pg_proc WHERE proname = 'paddock_offboard_delete_batch_from'`).Scan(&owner, &definer, &config); err != nil {
			t.Fatal(err)
		}
		if owner != "paddock_owner" || !definer || len(config) != 1 ||
			config[0] != "search_path=pg_catalog, public, pg_temp" {
			t.Errorf("owner %q, security definer %v, config %v", owner, definer, config)
		}
	})

	t.Run("refuses an active organization", func(t *testing.T) {
		_, err := batch(gone, 1000, nil)
		wantSQLState(t, "active organization", err, "42501")
		if got := offboardingRows(ctx, t, super, gone); got == 0 {
			t.Error("rows of the active organization were deleted")
		}
	})

	t.Run("refuses without an organization context", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, env.Worker)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close(ctx) }()
		if _, err := conn.Exec(ctx, "SELECT * FROM paddock_offboard_delete_batch_from(1000, NULL)"); err == nil {
			t.Error("the function ran without paddock.org_id")
		}
	})

	setDeleting(ctx, t, super, gone)
	goneRows := offboardingRows(ctx, t, super, gone)

	t.Run("no other role may execute it", func(t *testing.T) {
		for name, dsn := range map[string]string{"paddock_api": env.API, "paddock_compiler": env.Compiler,
			"paddock_platform": env.Platform, "paddock_relay": env.Relay, "paddock_escrow_reader": env.EscrowReader,
			"paddock_revocation": env.Revocation, "paddock_notifier": env.Notifier, "paddock_backup": env.Backup} {
			conn, err := pgx.Connect(ctx, dsn)
			if err != nil {
				t.Fatal(err)
			}
			tx, err := conn.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, "SELECT set_config('paddock.org_id', $1, true)", gone.String()); err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(ctx, "SELECT * FROM paddock_offboard_delete_batch_from(1000, NULL)")
			wantDenied(t, name, err)
			_ = tx.Rollback(ctx)
			_ = conn.Close(ctx)
		}
		if got := offboardingRows(ctx, t, super, gone); got != goneRows {
			t.Errorf("rows of the deleting organization: %d, want %d", got, goneRows)
		}
	})

	t.Run("refuses the active organization while another is deleting", func(t *testing.T) {
		_, err := batch(kept, 1000, nil)
		wantSQLState(t, "active organization", err, "42501")
	})

	t.Run("rejects max_rows outside 1..10000", func(t *testing.T) {
		for _, maxRows := range []int32{0, -1, 10001} {
			_, err := batch(gone, maxRows, nil)
			wantSQLState(t, fmt.Sprintf("max_rows %d", maxRows), err, "22023")
		}
	})

	t.Run("starts at the first registered table with rows and reports it", func(t *testing.T) {
		b, err := batch(gone, 1000, nil)
		if err != nil || b.Deleted != 2 || b.AtOrder != members {
			t.Fatalf("first batch = %+v, %v; want the 2 device_group_member rows at %d", b, err, members)
		}
	})

	t.Run("resumes in the middle at from_order", func(t *testing.T) {
		statusRows := count("device_status", gone)
		for i, want := range []int64{1000, 1000, 500} {
			b, err := batch(gone, 1000, at(watched))
			if err != nil || b.Deleted != want || b.AtOrder != watched {
				t.Fatalf("batch %d from %d = %+v, %v; want %d watched_unit rows at %d", i+1, watched, b, err, want, watched)
			}
		}
		if n := count("watched_unit", gone); n != 0 {
			t.Fatalf("%d watched_unit rows left", n)
		}
		if n := count("device_status", gone); n != statusRows || n == 0 {
			t.Fatalf("device_status rows %d, want %d: a table before from_order was touched", n, statusRows)
		}
	})

	t.Run("an empty tail returns 0 with at_order NULL", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, env.Worker)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close(ctx) }()
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, "SELECT set_config('paddock.org_id', $1, true)", gone.String()); err != nil {
			t.Fatal(err)
		}
		var deleted int64
		var atNull bool
		err = tx.QueryRow(ctx, "SELECT deleted, at_order IS NULL FROM paddock_offboard_delete_batch_from(1000, 100000)").
			Scan(&deleted, &atNull)
		if err != nil || deleted != 0 || !atNull {
			t.Fatalf("tail after the last table = (%d, at_order NULL %v), %v; want (0, NULL)", deleted, atNull, err)
		}
		if got := offboardingRows(ctx, t, super, gone); got == 0 {
			t.Fatal("the rows before from_order were deleted")
		}
	})

	t.Run("walks to the end from its stored position", func(t *testing.T) {
		var from *int32
		last := int32(0)
		for calls := 0; ; calls++ {
			b, err := batch(gone, 1000, from)
			if err != nil {
				t.Fatalf("call %d from %v: %v", calls+1, from, err)
			}
			if b.Deleted == 0 {
				break
			}
			if b.AtOrder < last || (from != nil && b.AtOrder < *from) {
				t.Fatalf("call %d worked on delete_order %d after %d: the position went back", calls+1, b.AtOrder, last)
			}
			last = b.AtOrder
			from = at(b.AtOrder)
			if calls > 200 {
				t.Fatal("the deletion does not end")
			}
		}
		if got := offboardingRows(ctx, t, super, gone); got != 0 {
			t.Errorf("%d rows of the deleted organization remain", got)
		}
		if got := offboardingRows(ctx, t, super, kept); got != keptRows {
			t.Errorf("rows of the other organization: %d, want %d", got, keptRows)
		}
	})

	t.Run("a straggler before the position is left for finalize", func(t *testing.T) {
		if _, err := super.Exec(ctx, "INSERT INTO watched_unit (organization_id, unit) VALUES ($1, 'late.service')", gone); err != nil {
			t.Fatal(err)
		}
		if b, err := batch(gone, 1000, at(watched+1)); err != nil || b.Deleted != 0 {
			t.Fatalf("from after watched_unit = %+v, %v; want nothing left there", b, err)
		}
		if b, err := batch(gone, 1000, nil); err != nil || b.Deleted != 1 || b.AtOrder != watched {
			t.Fatalf("from the start = %+v, %v; want the straggler at %d", b, err, watched)
		}
	})
}
