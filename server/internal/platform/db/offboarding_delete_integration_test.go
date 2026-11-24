package db_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

// offboardingFixture inserts an active organization with two devices in a group, a revert chain of three change sets
// and units watched rows of watched_unit, as the superuser. The organization's settings rows come from the
// organization triggers.
func offboardingFixture(ctx context.Context, t *testing.T, super *pgx.Conn, units int) uuid.UUID {
	t.Helper()
	org, group, devA, devB := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	cs1, cs2, cs3 := uuid.New(), uuid.New(), uuid.New()
	changeSet := `INSERT INTO change_set (id, organization_id, actor, source, created_n, updated_n, deleted_n, sections,
		plan, reverts_change_set_id) VALUES ($1, $2, '{}', 'session', 0, 0, 0, '{}', '{}', $3)`
	for _, x := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'Offboarding', 'active')",
			[]any{org, "ob" + org.String()[24:]}},
		{"INSERT INTO device_group (id, organization_id, name) VALUES ($1, $2, 'all')", []any{group, org}},
		{"INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $3, 'a', 'active'), ($2, $3, 'b', 'active')",
			[]any{devA, devB, org}},
		{"INSERT INTO device_status (device_id, organization_id) VALUES ($1, $3), ($2, $3)", []any{devA, devB, org}},
		{"INSERT INTO device_group_member (organization_id, device_group_id, device_id) VALUES ($1, $2, $3), ($1, $2, $4)",
			[]any{org, group, devA, devB}},
		{changeSet, []any{cs1, org, nil}},
		{changeSet, []any{cs2, org, cs1}},
		{changeSet, []any{cs3, org, cs2}},
		{"INSERT INTO watched_unit (organization_id, unit) SELECT $1, 'u' || g || '.service' FROM generate_series(1, $2) g",
			[]any{org, units}},
	} {
		if _, err := super.Exec(ctx, x.sql, x.args...); err != nil {
			t.Fatalf("%s: %v", x.sql, err)
		}
	}
	return org
}

// offboardingRows counts org's rows in every registered table.
func offboardingRows(ctx context.Context, t *testing.T, super *pgx.Conn, org uuid.UUID) int64 {
	t.Helper()
	rows, err := super.Query(ctx, "SELECT table_name FROM offboarding_table ORDER BY delete_order")
	if err != nil {
		t.Fatal(err)
	}
	tables, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, table := range tables {
		var n int64
		sql := fmt.Sprintf("SELECT count(*) FROM %s WHERE organization_id = $1", pgx.Identifier{table}.Sanitize())
		if err := super.QueryRow(ctx, sql, org).Scan(&n); err != nil {
			t.Fatal(err)
		}
		total += n
	}
	return total
}

func setDeleting(ctx context.Context, t *testing.T, super *pgx.Conn, org uuid.UUID) {
	t.Helper()
	if _, err := super.Exec(ctx, `UPDATE organization SET status = 'deleting', deletion_requested_at = now(),
		deletion_requested_by = 'platform admin', deletion_reason = 'contract ended', delete_after = now(),
		offboarding_step = 'database' WHERE id = $1`, org); err != nil {
		t.Fatal(err)
	}
}

// TestOffboardDeleteBatch proves paddock_offboard_delete_batch (plan M17 decision 7, ADR 0052 decision 4): it refuses
// an organization that is not deleting, deletes at most max_rows rows per call in registry order until it returns 0,
// leaves other organizations untouched, and only paddock_worker may execute it.
func TestOffboardDeleteBatch(t *testing.T) {
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
	batch := func(org uuid.UUID, maxRows int32) (n int64, err error) {
		err = worker.InOrgOffboarding(orgCtx(org), func(ctx context.Context, q *pgstore.Queries) error {
			n, err = q.OffboardDeleteBatch(ctx, maxRows)
			return err
		})
		return n, err
	}

	gone := offboardingFixture(ctx, t, super, 2500)
	kept := offboardingFixture(ctx, t, super, 10)
	keptRows := offboardingRows(ctx, t, super, kept)

	t.Run("definer function owned by paddock_owner with a pinned search path", func(t *testing.T) {
		var owner string
		var definer bool
		var config []string
		if err := super.QueryRow(ctx, `SELECT pg_get_userbyid(proowner), prosecdef, coalesce(proconfig, '{}')
			FROM pg_proc WHERE proname = 'paddock_offboard_delete_batch'`).Scan(&owner, &definer, &config); err != nil {
			t.Fatal(err)
		}
		if owner != "paddock_owner" || !definer || len(config) != 1 ||
			config[0] != "search_path=pg_catalog, public, pg_temp" {
			t.Errorf("owner %q, security definer %v, config %v", owner, definer, config)
		}
	})

	t.Run("refuses an active organization", func(t *testing.T) {
		_, err := batch(gone, 1000)
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
		if _, err := conn.Exec(ctx, "SELECT paddock_offboard_delete_batch(1000)"); err == nil {
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
			_, err = tx.Exec(ctx, "SELECT paddock_offboard_delete_batch(1000)")
			wantDenied(t, name, err)
			_ = tx.Rollback(ctx)
			_ = conn.Close(ctx)
		}
		// The gateway has no database credentials at all (plan M2a decision 1).
		var exists bool
		if err := super.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'paddock_gateway')").
			Scan(&exists); err != nil || exists {
			t.Errorf("role paddock_gateway exists: %v, %v", exists, err)
		}
		if got := offboardingRows(ctx, t, super, gone); got != goneRows {
			t.Errorf("rows of the deleting organization: %d, want %d", got, goneRows)
		}
	})

	t.Run("refuses the active organization while another is deleting", func(t *testing.T) {
		_, err := batch(kept, 1000)
		wantSQLState(t, "active organization", err, "42501")
	})

	t.Run("deletes in batches until nothing is left", func(t *testing.T) {
		var total int64
		calls := 0
		for {
			n, err := batch(gone, 1000)
			if err != nil {
				t.Fatal(err)
			}
			if n < 0 || n > 1000 {
				t.Fatalf("call %d deleted %d rows, want 0..1000", calls+1, n)
			}
			calls++
			if n == 0 {
				break
			}
			total += n
			if calls > 200 {
				t.Fatal("the deletion does not end")
			}
		}
		if total != goneRows {
			t.Errorf("deleted %d rows, want %d", total, goneRows)
		}
		if calls < 4 {
			t.Errorf("%d calls for %d rows, want the 2500 watched units split over at least three batches", calls, goneRows)
		}
		if got := offboardingRows(ctx, t, super, gone); got != 0 {
			t.Errorf("%d rows of the deleted organization remain", got)
		}
		if got := offboardingRows(ctx, t, super, kept); got != keptRows {
			t.Errorf("rows of the other organization: %d, want %d", got, keptRows)
		}
		var status string
		if err := super.QueryRow(ctx, "SELECT status FROM organization WHERE id = $1", gone).Scan(&status); err != nil ||
			status != "deleting" {
			t.Errorf("organization row: status %q, %v; the tombstone is a later step", status, err)
		}
		if n, err := batch(gone, 1000); err != nil || n != 0 {
			t.Errorf("repeated call: %d, %v, want 0", n, err)
		}
	})

	t.Run("a tombstone frees its slug", func(t *testing.T) {
		var slug string
		if err := super.QueryRow(ctx, `UPDATE organization SET status = 'deleted', deleted_at = now() WHERE id = $1
			RETURNING slug`, gone).Scan(&slug); err != nil {
			t.Fatal(err)
		}
		reused := uuid.New()
		if _, err := super.Exec(ctx, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'Reused', 'active')",
			reused, slug); err != nil {
			t.Fatalf("slug of a deleted organization not reusable: %v", err)
		}
		_, err := super.Exec(ctx, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'Twice', 'active')",
			uuid.New(), slug)
		wantSQLState(t, "second live organization with the slug", err, "23505")
		got, err := pgstore.New(super).GetOrganizationBySlug(ctx, slug)
		if err != nil || got.ID != reused {
			t.Errorf("GetOrganizationBySlug = %v, %v, want the live organization %v", got.ID, err, reused)
		}
	})

	t.Run("splits a revert chain over batches", func(t *testing.T) {
		org := offboardingFixture(ctx, t, super, 0)
		setDeleting(ctx, t, super, org)
		for calls := 0; ; calls++ {
			n, err := batch(org, 1)
			if err != nil {
				t.Fatalf("call %d: %v", calls+1, err)
			}
			if n > 1 {
				t.Fatalf("call %d deleted %d rows, want at most 1", calls+1, n)
			}
			if n == 0 {
				break
			}
		}
		if got := offboardingRows(ctx, t, super, org); got != 0 {
			t.Errorf("%d rows remain", got)
		}
	})

	t.Run("a reference cycle raises instead of reporting the end", func(t *testing.T) {
		org := offboardingFixture(ctx, t, super, 0)
		if _, err := super.Exec(ctx, `UPDATE change_set SET reverts_change_set_id = (SELECT id FROM change_set c
			WHERE c.organization_id = $1 AND c.reverts_change_set_id IS NOT NULL AND NOT EXISTS
			  (SELECT 1 FROM change_set r WHERE r.reverts_change_set_id = c.id))
			WHERE organization_id = $1 AND reverts_change_set_id IS NULL`, org); err != nil {
			t.Fatal(err)
		}
		setDeleting(ctx, t, super, org)
		for calls := 0; ; calls++ {
			n, err := batch(org, 1000)
			if err != nil {
				wantSQLState(t, "cycle", err, "23503")
				break
			}
			if n == 0 || calls > 50 {
				t.Fatalf("call %d returned %d with a reference cycle left", calls+1, n)
			}
		}
	})

	t.Run("a row changed during the batch raises a retryable error", func(t *testing.T) {
		org := offboardingFixture(ctx, t, super, 0)
		setDeleting(ctx, t, super, org)
		groups := func() int64 {
			var n int64
			if err := super.QueryRow(ctx, "SELECT count(*) FROM device_group WHERE organization_id = $1", org).
				Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n
		}
		// device_group comes last in the registry: delete everything else first, so its row is the last one left.
		for calls := 0; offboardingRows(ctx, t, super, org) > groups(); calls++ {
			if _, err := batch(org, 1000); err != nil || calls > 100 {
				t.Fatalf("call %d: %v", calls+1, err)
			}
		}
		if groups() != 1 {
			t.Fatalf("%d device groups left, want 1", groups())
		}

		holder, err := pgx.Connect(ctx, env.Super)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = holder.Close(ctx) }()
		tx, err := holder.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, "UPDATE device_group SET description = 'held' WHERE organization_id = $1", org); err != nil {
			t.Fatal(err)
		}
		type result struct {
			n   int64
			err error
		}
		done := make(chan result, 1)
		go func() {
			n, err := batch(org, 1000)
			done <- result{n, err}
		}()
		deadline := time.Now().Add(10 * time.Second)
		for {
			var waiting int
			if err := super.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity
				WHERE usename = 'paddock_worker' AND wait_event_type = 'Lock'`).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting > 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("the batch never waited for the held row")
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		got := <-done
		wantSQLState(t, fmt.Sprintf("batch over a concurrently updated row (returned %d)", got.n), got.err, "40001")
		if groups() != 1 {
			t.Fatalf("%d device groups left after the failed batch, want 1", groups())
		}
		if n, err := batch(org, 1000); err != nil || n != 1 {
			t.Errorf("retry: %d, %v, want 1", n, err)
		}
		if n, err := batch(org, 1000); err != nil || n != 0 {
			t.Errorf("after the retry: %d, %v, want 0", n, err)
		}
	})

	t.Run("rejects max_rows outside 1..10000", func(t *testing.T) {
		for _, maxRows := range []int32{0, -1, 10001} {
			_, err := batch(gone, maxRows)
			wantSQLState(t, fmt.Sprintf("max_rows %d", maxRows), err, "22023")
		}
	})
}

// TestOffboardingTombstoneDomains: a tombstone frees its domains (plan M17 decision 17), and a deleted organization
// never blocks a domain claim.
func TestOffboardingTombstoneDomains(t *testing.T) {
	env := sharedPaddock(t)
	ctx := context.Background()
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = super.Close(ctx) }()
	q := pgstore.New(super)
	gone, stale, claimer := uuid.New(), uuid.New(), uuid.New()
	domain, staleDomain := gone.String()[24:]+".example", stale.String()[24:]+".example"
	if _, err := super.Exec(ctx, `INSERT INTO organization (id, slug, name, status, domains) VALUES
		($1, $2, 'Gone', 'active', $3), ($4, $5, 'Stale', 'active', $6), ($7, $8, 'Claimer', 'active', '{}')`,
		gone, "tg"+gone.String()[24:], []string{domain}, stale, "ts"+stale.String()[24:], []string{staleDomain},
		claimer, "tc"+claimer.String()[24:]); err != nil {
		t.Fatal(err)
	}
	setDeleting(ctx, t, super, gone)
	org, err := q.TombstoneOrganization(ctx, gone)
	if err != nil {
		t.Fatal(err)
	}
	if org.Status != "deleted" || org.DeletedAt == nil || len(org.Domains) != 0 {
		t.Errorf("tombstone: status %q, deleted_at %v, domains %v", org.Status, org.DeletedAt, org.Domains)
	}
	// A tombstone written before domains were cleared still must not claim its domain.
	if _, err := super.Exec(ctx, `UPDATE organization SET status = 'deleted', deleted_at = now(),
		deletion_requested_at = now(), delete_after = now() WHERE id = $1`, stale); err != nil {
		t.Fatal(err)
	}
	claims, err := q.ListOrganizationsClaimingDomains(ctx, pgstore.ListOrganizationsClaimingDomainsParams{
		Domains: []string{domain, staleDomain}, ID: claimer})
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) != 0 {
		t.Errorf("deleted organizations claim domains: %v", claims)
	}
}

// TestOffboardingGrants: the worker updates only the identity-round columns of its own organization (plan M17
// decision 20), and the audit reader cannot read audit_org_retired.
func TestOffboardingGrants(t *testing.T) {
	env := sharedPaddock(t)
	ctx := context.Background()
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = super.Close(ctx) }()
	own, other := uuid.New(), uuid.New()
	if _, err := super.Exec(ctx, `INSERT INTO organization (id, slug, name, status) VALUES
		($1, $2, 'Own', 'active'), ($3, $4, 'Other', 'active')`,
		own, "go"+own.String()[24:], other, "gx"+other.String()[24:]); err != nil {
		t.Fatal(err)
	}
	worker, err := db.NewOrgPool(ctx, env.Worker, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	updatedAt := func(id uuid.UUID) (at time.Time) {
		if err := super.QueryRow(ctx, "SELECT updated_at FROM organization WHERE id = $1", id).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	if err := worker.InOrg(orgCtx(own), func(ctx context.Context, q *pgstore.Queries) error {
		if err := q.MarkOrganizationIdentityEnsured(ctx, pgstore.MarkOrganizationIdentityEnsuredParams{
			ID: own, Revision: new("rev-1"), SeenUpdatedAt: updatedAt(own)}); err != nil {
			return err
		}
		return q.MarkOrganizationIdentityEnsured(ctx, pgstore.MarkOrganizationIdentityEnsuredParams{
			ID: other, Revision: new("rev-1"), SeenUpdatedAt: updatedAt(other)})
	}); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[uuid.UUID]bool{own: true, other: false} {
		var ensured bool
		if err := super.QueryRow(ctx, "SELECT idp_ensured_at IS NOT NULL FROM organization WHERE id = $1", id).
			Scan(&ensured); err != nil {
			t.Fatal(err)
		}
		if ensured != want {
			t.Errorf("organization %v: ensured %v, want %v", id, ensured, want)
		}
	}
	err = worker.InOrg(orgCtx(own), func(ctx context.Context, q *pgstore.Queries) error {
		_, err := q.UpdateOrganizationDomains(ctx, pgstore.UpdateOrganizationDomainsParams{ID: own, Domains: []string{}})
		return err
	})
	wantDenied(t, "worker UPDATE organization.domains", err)

	audit := sharedAudit(t)
	reader, err := pgx.Connect(ctx, audit.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close(ctx) }()
	_, err = reader.Exec(ctx, "SELECT * FROM audit_org_retired")
	wantDenied(t, "audit reader SELECT audit_org_retired", err)
}
