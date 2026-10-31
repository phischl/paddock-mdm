package app_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

type retentionWorld struct {
	retention *app.Retention
	fleet     *fakeInventoryAdmin
	super     *pgx.Conn
}

// fakeInventoryAdmin is Fleet's host deletion; err makes every deletion fail, failing makes the deletion of those hosts
// fail with their error; calls counts every deletion asked for. seen is the last check-in of those hosts (the zero time
// for the others), seenErr fails the check-in lookup of those hosts; lookups counts every lookup, unbounded those
// asked without a deadline.
type fakeInventoryAdmin struct {
	mu        sync.Mutex
	deleted   []ports.HostRef
	err       error
	failing   map[ports.HostRef]error
	calls     int
	seen      map[ports.HostRef]time.Time
	seenErr   map[ports.HostRef]error
	lookups   int
	unbounded int
}

func (f *fakeInventoryAdmin) HostSeenAt(ctx context.Context, ref ports.HostRef) (time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups++
	if _, ok := ctx.Deadline(); !ok {
		f.unbounded++
	}
	if err := f.seenErr[ref]; err != nil {
		return time.Time{}, err
	}
	return f.seen[ref], nil
}

// fleetDown is the error of a Fleet that is down (ports.InventoryAdmin: upstream_unavailable).
func fleetDown() error {
	return fmt.Errorf("%w: fleet: HTTP 503: unavailable", problem.UpstreamUnavailable)
}

// fleetRefused is the error of Fleet refusing the one host (ports.InventoryAdmin: invalid_state).
func fleetRefused(ref ports.HostRef) error {
	return fmt.Errorf("%w: fleet: HTTP 422: host %s refused", problem.InvalidState, ref)
}

func (f *fakeInventoryAdmin) DeleteHost(_ context.Context, ref ports.HostRef) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return f.err
	}
	if err := f.failing[ref]; err != nil {
		return err
	}
	f.deleted = append(f.deleted, ref)
	return nil
}

// newRetentionWorld runs the use case with the worker's role and counts days as seconds, as a development stack does.
func newRetentionWorld(t *testing.T) retentionWorld {
	t.Helper()
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	pool, err := db.NewOrgPool(ctx, env.Worker, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
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
	fleet := &fakeInventoryAdmin{}
	return retentionWorld{retention: app.NewRetention(app.NewActionRunner(pool, platform, httpx.RequestID), pool, platform, fleet, time.Second, 400),
		fleet: fleet, super: super}
}

// organization creates an organization with one device that has seen n users at seen.
func (w retentionWorld) organization(t *testing.T, n int, seen time.Time) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	org, dev := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'R', 'active')", []any{org, "r" + org.String()[24:]}},
		{"INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'ret', 'active')", []any{dev, org}},
		{`INSERT INTO device_user_seen (organization_id, device_id, username, last_seen_at)
		  SELECT $1, $2, 'user' || g, $3 FROM generate_series(1, $4::int) g`, []any{org, dev, seen, n}},
	} {
		if _, err := w.super.Exec(ctx, stmt.sql, stmt.args...); err != nil {
			t.Fatal(err)
		}
	}
	return org
}

func (w retentionWorld) seen(t *testing.T, org uuid.UUID) int {
	t.Helper()
	return countRows(t, w.super, "SELECT count(*) FROM device_user_seen WHERE organization_id = $1", org)
}

// batchLog records every DELETE statement on device_user_seen that removes rows of org: its transaction and its row
// count. With failAt > 0 the failAt-th deleting statement raises after deleting, injecting a batch failure; its log row
// rolls back with it, so the log keeps the committed batches only.
// It returns the log table's name.
func (w retentionWorld) batchLog(t *testing.T, org uuid.UUID, failAt int) string {
	t.Helper()
	ctx := context.Background()
	name := "retention_batch_" + strings.ReplaceAll(org.String(), "-", "")
	if _, err := w.super.Exec(ctx, fmt.Sprintf(`
		CREATE TABLE %[1]s (xid xid NOT NULL, n int NOT NULL);
		CREATE FUNCTION %[1]s() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $f$
		DECLARE c int;
		BEGIN
		  SELECT count(*) INTO c FROM old_rows WHERE organization_id = '%[2]s';
		  IF c > 0 THEN
		    INSERT INTO %[1]s VALUES (xid(pg_current_xact_id()), c);
		    IF %[3]d > 0 AND (SELECT count(*) FROM %[1]s) >= %[3]d THEN
		      RAISE EXCEPTION 'injected batch failure';
		    END IF;
		  END IF;
		  RETURN NULL;
		END $f$;
		CREATE TRIGGER %[1]s AFTER DELETE ON device_user_seen REFERENCING OLD TABLE AS old_rows
		  FOR EACH STATEMENT EXECUTE FUNCTION %[1]s();`, name, org, failAt)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = w.super.Exec(context.Background(), fmt.Sprintf(
			"DROP TRIGGER %[1]s ON device_user_seen; DROP FUNCTION %[1]s(); DROP TABLE %[1]s;", name))
	})
	return name
}

type purgedEvent struct {
	outcome, store, cutoff string
	deleted                int64
	sameTx                 bool
}

// purgedEvents returns org's retention.purged events of store device_user_seen; sameTx reports whether the event was
// written by a transaction the batch log saw deleting.
func (w retentionWorld) purgedEvents(t *testing.T, org uuid.UUID, log string) []purgedEvent {
	t.Helper()
	rows, err := w.super.Query(context.Background(), fmt.Sprintf(`
		SELECT a.outcome, a.params->>'store', a.params->>'cutoff', (a.params->>'deleted')::bigint,
		       EXISTS (SELECT 1 FROM %s b WHERE b.xid = a.xmin)
		  FROM action a
		 WHERE a.organization_id = $1 AND a.code = 'retention.purged' AND a.params->>'store' = 'device_user_seen'
		 ORDER BY a.started_at`, log), org)
	if err != nil {
		t.Fatal(err)
	}
	var out []purgedEvent
	for rows.Next() {
		var e purgedEvent
		if err := rows.Scan(&e.outcome, &e.store, &e.cutoff, &e.deleted, &e.sameTx); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestRetentionPurgeUserSeen (plan M10 decision 13, amendment 2026-10-30): 2 500 expired rows go in three batches of
// at most 1 000 rows, each in its own transaction, recorded as one retention.purged event with the total; rows inside
// the window stay; a second purge finds nothing and records nothing.
func TestRetentionPurgeUserSeen(t *testing.T) {
	w := newRetentionWorld(t)
	ctx := context.Background()
	now := time.Now().UTC()
	org := w.organization(t, 2500, now.Add(-400*time.Second))
	if _, err := w.super.Exec(ctx, `INSERT INTO device_user_seen (organization_id, device_id, username, last_seen_at)
		SELECT organization_id, device_id, 'fresh', $2 FROM device_user_seen WHERE organization_id = $1 LIMIT 1`,
		org, now.Add(-300*time.Second)); err != nil {
		t.Fatal(err)
	}
	log := w.batchLog(t, org, 0)

	n, err := w.retention.PurgeUserSeen(systemCtx(org), now)
	if err != nil || n != 2500 {
		t.Fatalf("purged %d (%v), want 2500", n, err)
	}
	if left := w.seen(t, org); left != 1 {
		t.Fatalf("%d rows left, want the fresh one", left)
	}
	var statements, txs, largest int
	if err := w.super.QueryRow(ctx, fmt.Sprintf("SELECT count(*), count(DISTINCT xid::text), max(n) FROM %s", log)).
		Scan(&statements, &txs, &largest); err != nil {
		t.Fatal(err)
	}
	if statements != 3 || txs != 3 || largest > 1000 {
		t.Fatalf("%d statements in %d transactions, largest %d rows; want 3 in 3, at most 1 000", statements, txs, largest)
	}
	events := w.purgedEvents(t, org, log)
	if len(events) != 1 {
		t.Fatalf("%d retention.purged events, want 1", len(events))
	}
	ev := events[0]
	cutoff, err := time.Parse(time.RFC3339, ev.cutoff)
	if ev.outcome != "success" || ev.deleted != 2500 || ev.sameTx || err != nil ||
		cutoff.Sub(now.Add(-365*time.Second)).Abs() > time.Millisecond {
		t.Fatalf("event %+v (cutoff %v)", ev, err)
	}

	if n, err := w.retention.PurgeUserSeen(systemCtx(org), now); err != nil || n != 0 {
		t.Fatalf("second purge %d (%v), want 0", n, err)
	}
	if events := w.purgedEvents(t, org, log); len(events) != 1 {
		t.Fatalf("%d events after a purge without expired rows, want 1", len(events))
	}
}

// TestRetentionPurgeUserSeenBudget (plan M10 amendment 2026-10-30): a pass whose budget has elapsed ends after the
// committed batch with outcome success and that batch's rows; the next pass continues with the rest, each pass with
// its own event.
func TestRetentionPurgeUserSeenBudget(t *testing.T) {
	w := newRetentionWorld(t)
	now := time.Now().UTC()
	org := w.organization(t, 1500, now.Add(-400*time.Second))
	log := w.batchLog(t, org, 0)
	w.retention.SetBudget(0)

	if n, err := w.retention.PurgeUserSeen(systemCtx(org), now); err != nil || n != 1000 {
		t.Fatalf("first pass purged %d (%v), want 1000", n, err)
	}
	if left := w.seen(t, org); left != 500 {
		t.Fatalf("%d rows left after the first pass, want 500", left)
	}
	if n, err := w.retention.PurgeUserSeen(systemCtx(org), now); err != nil || n != 500 {
		t.Fatalf("second pass purged %d (%v), want 500", n, err)
	}
	events := w.purgedEvents(t, org, log)
	if len(events) != 2 || events[0].outcome != "success" || events[0].deleted != 1000 ||
		events[1].outcome != "success" || events[1].deleted != 500 {
		t.Fatalf("events %+v, want success 1000 then success 500", events)
	}
}

// TestRetentionPurgeUserSeenLockTimeout (plan M10 amendment 2026-10-30): a batch blocked by a row lock beyond the lock
// timeout ends the pass with outcome success and the rows deleted so far; the next pass deletes the rest.
func TestRetentionPurgeUserSeenLockTimeout(t *testing.T) {
	w := newRetentionWorld(t)
	ctx := context.Background()
	now := time.Now().UTC()
	org := w.organization(t, 1500, now.Add(-400*time.Second))
	log := w.batchLog(t, org, 0)
	w.retention.SetLockTimeout(200 * time.Millisecond)

	tx, err := w.super.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT 1 FROM device_user_seen WHERE organization_id = $1 FOR UPDATE`, org); err != nil {
		t.Fatal(err)
	}
	n, err := w.retention.PurgeUserSeen(systemCtx(org), now)
	if rbErr := tx.Rollback(ctx); rbErr != nil {
		t.Fatal(rbErr)
	}
	if err != nil || n != 0 {
		t.Fatalf("blocked pass purged %d (%v), want 0 without error", n, err)
	}
	if left := w.seen(t, org); left != 1500 {
		t.Fatalf("%d rows left after the blocked pass, want 1500", left)
	}
	if n, err := w.retention.PurgeUserSeen(systemCtx(org), now); err != nil || n != 1500 {
		t.Fatalf("second pass purged %d (%v), want 1500", n, err)
	}
	events := w.purgedEvents(t, org, log)
	if len(events) != 2 || events[0].outcome != "success" || events[0].deleted != 0 ||
		events[1].outcome != "success" || events[1].deleted != 1500 {
		t.Fatalf("events %+v, want success 0 then success 1500", events)
	}
}

// TestRetentionPurgeUserSeenNothingExpired: an organization without expired rows gets no event.
func TestRetentionPurgeUserSeenNothingExpired(t *testing.T) {
	w := newRetentionWorld(t)
	now := time.Now().UTC()
	org := w.organization(t, 3, now.Add(-time.Second))
	log := w.batchLog(t, org, 0)
	if n, err := w.retention.PurgeUserSeen(systemCtx(org), now); err != nil || n != 0 {
		t.Fatalf("purged %d (%v), want 0", n, err)
	}
	if left := w.seen(t, org); left != 3 {
		t.Fatalf("%d rows left, want 3", left)
	}
	if events := w.purgedEvents(t, org, log); len(events) != 0 {
		t.Fatalf("events %+v, want none", events)
	}
}

// TestRetentionPurgeUserSeenBatchFailure (plan M10 amendment 2026-10-30): a failing second batch rolls back alone; the
// committed first batch stays deleted and the one event records outcome failure with its 1 000 rows.
func TestRetentionPurgeUserSeenBatchFailure(t *testing.T) {
	w := newRetentionWorld(t)
	now := time.Now().UTC()
	org := w.organization(t, 1500, now.Add(-400*time.Second))
	log := w.batchLog(t, org, 2)
	if n, err := w.retention.PurgeUserSeen(systemCtx(org), now); err == nil || n != 1000 {
		t.Fatalf("purged %d (%v), want an error after 1 000", n, err)
	}
	if left := w.seen(t, org); left != 500 {
		t.Fatalf("%d rows left, want the 500 of the failed batch", left)
	}
	events := w.purgedEvents(t, org, log)
	if len(events) != 1 || events[0].outcome != "failure" || events[0].deleted != 1000 || events[0].store != app.StoreDeviceUserSeen {
		t.Fatalf("events %+v, want one failure with deleted 1000", events)
	}
}

// TestRetentionPurgeUserSeenFirstBatchFails (plan M10 amendment 2026-10-30): when no batch commits, the failure event
// claims no deleted rows.
func TestRetentionPurgeUserSeenFirstBatchFails(t *testing.T) {
	w := newRetentionWorld(t)
	now := time.Now().UTC()
	org := w.organization(t, 10, now.Add(-400*time.Second))
	log := w.batchLog(t, org, 1)
	if n, err := w.retention.PurgeUserSeen(systemCtx(org), now); err == nil || n != 0 {
		t.Fatalf("purged %d (%v), want an error and nothing deleted", n, err)
	}
	if left := w.seen(t, org); left != 10 {
		t.Fatalf("%d rows left, want all 10", left)
	}
	events := w.purgedEvents(t, org, log)
	if len(events) != 1 || events[0].outcome != "failure" || events[0].deleted != 0 {
		t.Fatalf("events %+v, want one failure with deleted 0", events)
	}
}

// TestRetentionPurgeUserSeenSystemOnly: only the worker's system principal may purge.
func TestRetentionPurgeUserSeenSystemOnly(t *testing.T) {
	w := newRetentionWorld(t)
	now := time.Now().UTC()
	org := w.organization(t, 2, now.Add(-400*time.Second))
	admin := principal.With(context.Background(), principal.Principal{Kind: principal.KindAdmin, ID: uuid.Must(uuid.NewV7()),
		Role: principal.RoleOrgAdmin, OrganizationID: org})
	if _, err := w.retention.PurgeUserSeen(admin, now); !errors.Is(err, problem.Unauthenticated) {
		t.Fatalf("admin purge: %v, want unauthenticated", err)
	}
	if left := w.seen(t, org); left != 2 {
		t.Fatalf("%d rows left, want 2", left)
	}
}
