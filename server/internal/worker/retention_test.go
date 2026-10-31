package worker

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// seenUsers gives org a device that has seen n users at seen.
func (f fixture) seenUsers(t *testing.T, org uuid.UUID, n int, seen time.Time) {
	t.Helper()
	ctx := context.Background()
	dev := uuid.Must(uuid.NewV7())
	if _, err := f.super.Exec(ctx, "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'ret', 'active')", dev, org); err != nil {
		t.Fatal(err)
	}
	if _, err := f.super.Exec(ctx, `INSERT INTO device_user_seen (organization_id, device_id, username, last_seen_at)
		SELECT $1, $2, 'user' || g, $3 FROM generate_series(1, $4::int) g`, org, dev, seen, n); err != nil {
		t.Fatal(err)
	}
}

// failDeletes makes every deletion of org's device_user_seen rows fail until the test ends or the returned func runs.
func (f fixture) failDeletes(t *testing.T, org uuid.UUID) func() {
	t.Helper()
	name := "retention_fail_" + strings.ReplaceAll(org.String(), "-", "")
	if _, err := f.super.Exec(context.Background(), fmt.Sprintf(`
		CREATE FUNCTION %[1]s() RETURNS trigger LANGUAGE plpgsql AS $f$
		BEGIN
		  IF EXISTS (SELECT 1 FROM old_rows WHERE organization_id = '%[2]s') THEN
		    RAISE EXCEPTION 'injected batch failure';
		  END IF;
		  RETURN NULL;
		END $f$;
		CREATE TRIGGER %[1]s AFTER DELETE ON device_user_seen REFERENCING OLD TABLE AS old_rows
		  FOR EACH STATEMENT EXECUTE FUNCTION %[1]s();`, name, org)); err != nil {
		t.Fatal(err)
	}
	drop := func() {
		_, _ = f.super.Exec(context.Background(), fmt.Sprintf("DROP TRIGGER IF EXISTS %[1]s ON device_user_seen; DROP FUNCTION IF EXISTS %[1]s();", name))
	}
	t.Cleanup(drop)
	return drop
}

// TestRetentionRound (plan M10 amendment A3): a failing organization does not stop the others, its deletions roll
// back with a failure event, and the store's last success waits for a round in which every organization succeeded.
func TestRetentionRound(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	platform, err := db.NewPlatformPool(ctx, pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	runner := app.NewActionRunner(f.pool, platform, httpx.RequestID)
	day := 24 * time.Hour
	r := NewRetention(app.NewRetention(runner, f.pool, platform, &fakeSource{}, day, 400), app.NewLoginHistory(runner, f.pool, day), f.pool, platform, time.Hour)

	failing := newFixture(t).org
	expired := time.Now().Add(-400 * day)
	f.seenUsers(t, f.org, 2, expired)
	f.seenUsers(t, failing, 2, expired)
	restore := f.failDeletes(t, failing)
	seen := func(org uuid.UUID) int {
		return f.count(t, "SELECT count(*) FROM device_user_seen WHERE organization_id = $1", org)
	}
	events := func(org uuid.UUID, outcome string) int {
		return f.count(t, `SELECT count(*) FROM action WHERE organization_id = $1 AND code = 'retention.purged'
			AND outcome = $2 AND params->>'store' = 'device_user_seen'`, org, outcome)
	}
	userSeen := metricRetentionLastSuccess.WithLabelValues(app.StoreDeviceUserSeen)
	userSeen.Set(0)
	deletedBefore := testutil.ToFloat64(metricRetentionDeleted.WithLabelValues(app.StoreDeviceUserSeen))

	err = r.Round(ctx)
	if err == nil || !strings.Contains(err.Error(), failing.String()) || strings.Contains(err.Error(), f.org.String()) {
		t.Fatalf("round error %v, want only the failing organization", err)
	}
	if seen(f.org) != 0 || events(f.org, "success") != 1 {
		t.Fatalf("healthy organization: %d rows, %d success events", seen(f.org), events(f.org, "success"))
	}
	if seen(failing) != 2 || events(failing, "failure") != 1 {
		t.Fatalf("failing organization: %d rows, %d failure events", seen(failing), events(failing, "failure"))
	}
	if testutil.ToFloat64(userSeen) != 0 {
		t.Fatal("last success set although an organization failed")
	}
	if testutil.ToFloat64(metricRetentionLastSuccess.WithLabelValues(app.StoreDeviceLoginEvent)) == 0 {
		t.Fatal("the login history pass has no last success")
	}

	restore()
	if err := r.Round(ctx); err != nil {
		t.Fatal(err)
	}
	if seen(failing) != 0 || events(failing, "success") != 1 || events(f.org, "success") != 1 {
		t.Fatalf("second round: %d rows, %d/%d success events", seen(failing), events(failing, "success"), events(f.org, "success"))
	}
	if testutil.ToFloat64(userSeen) == 0 {
		t.Fatal("last success not set after a clean round")
	}
	if d := testutil.ToFloat64(metricRetentionDeleted.WithLabelValues(app.StoreDeviceUserSeen)) - deletedBefore; d < 4 {
		t.Fatalf("deleted_total grew by %v, want at least 4", d)
	}
}

// TestRetentionRoundRetiredInventory (plan M10 amendment A3): the round's third pass purges the inventory of a device
// retired longer than the organization's period, with its Fleet host, and exports the store retired_inventory.
func TestRetentionRoundRetiredInventory(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	platform, err := db.NewPlatformPool(ctx, pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	runner := app.NewActionRunner(f.pool, platform, httpx.RequestID)
	day := 24 * time.Hour
	fleet := &fakeSource{}
	r := NewRetention(app.NewRetention(runner, f.pool, platform, fleet, day, 400), app.NewLoginHistory(runner, f.pool, day), f.pool, platform, time.Hour)
	if len(r.passes) != 7 || r.passes[2].store != app.StoreRetiredInventory {
		t.Fatalf("passes %+v, want retired_inventory third of 7", r.passes)
	}
	dev := uuid.Must(uuid.NewV7())
	for _, stmt := range []string{
		"INSERT INTO device (id, organization_id, hostname, state, state_changed_at) VALUES ($1, $2, 'gone', 'retired', now() - interval '400 days')",
		"INSERT INTO device_inventory_ref (device_id, organization_id, external_id) VALUES ($1, $2, '77')",
		"INSERT INTO installed_software (device_id, organization_id, name, version, source) VALUES ($1, $2, 'bash', '5.2', 'deb_packages')",
	} {
		if _, err := f.super.Exec(ctx, stmt, dev, f.org); err != nil {
			t.Fatal(err)
		}
	}
	lastSuccess := metricRetentionLastSuccess.WithLabelValues(app.StoreRetiredInventory)
	lastSuccess.Set(0)
	deletedBefore := testutil.ToFloat64(metricRetentionDeleted.WithLabelValues(app.StoreRetiredInventory))

	if err := r.Round(ctx); err != nil {
		t.Fatal(err)
	}
	if n := f.count(t, "SELECT count(*) FROM installed_software WHERE device_id = $1", dev); n != 0 || len(fleet.deleted) != 1 || fleet.deleted[0] != "77" {
		t.Fatalf("%d software rows left, Fleet hosts deleted %v", n, fleet.deleted)
	}
	if n := f.count(t, "SELECT count(*) FROM action WHERE organization_id = $1 AND code = 'device.inventory_purged' AND outcome = 'success'", f.org); n != 1 {
		t.Fatalf("%d device.inventory_purged events, want 1", n)
	}
	if testutil.ToFloat64(lastSuccess) == 0 {
		t.Fatal("retired_inventory has no last success")
	}
	if d := testutil.ToFloat64(metricRetentionDeleted.WithLabelValues(app.StoreRetiredInventory)) - deletedBefore; d != 1 {
		t.Fatalf("deleted_total grew by %v, want 1 device", d)
	}
}

// TestRetentionRoundReadWindows (plan M10 amendment A3, decision 21): the round's fourth and last pass deletes the
// read-access coalescing keys older than 48 hours with one retention.purged event (store read_audit_window), keeps the
// younger ones and exports the store's last success.
func TestRetentionRoundReadWindows(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	platform, err := db.NewPlatformPool(ctx, pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	runner := app.NewActionRunner(f.pool, platform, httpx.RequestID)
	day := 24 * time.Hour
	r := NewRetention(app.NewRetention(runner, f.pool, platform, &fakeSource{}, day, 400), app.NewLoginHistory(runner, f.pool, day), f.pool, platform, time.Hour)
	if len(r.passes) != 7 || r.passes[3].store != app.StoreReadAuditWindow {
		t.Fatalf("passes %+v, want read_audit_window fourth of 7", r.passes)
	}
	now := time.Now().UTC()
	for i, start := range []time.Time{now.Add(-49 * time.Hour), now.Add(-50 * time.Hour), now.Add(-47 * time.Hour)} {
		if _, err := f.super.Exec(ctx, `INSERT INTO read_audit_window (organization_id, actor_id, code, window_start)
			VALUES ($1, $2, 'audit.searched', $3)`, f.org, fmt.Sprintf("actor-%d", i), start); err != nil {
			t.Fatal(err)
		}
	}
	lastSuccess := metricRetentionLastSuccess.WithLabelValues(app.StoreReadAuditWindow)
	lastSuccess.Set(0)

	if err := r.Round(ctx); err != nil {
		t.Fatal(err)
	}
	if n := f.count(t, "SELECT count(*) FROM read_audit_window WHERE organization_id = $1", f.org); n != 1 {
		t.Fatalf("%d windows left, want the one younger than 48 hours", n)
	}
	if n := f.count(t, `SELECT count(*) FROM action WHERE organization_id = $1 AND code = 'retention.purged'
		AND outcome = 'success' AND params->>'store' = 'read_audit_window' AND (params->>'deleted')::int = 2`, f.org); n != 1 {
		t.Fatalf("%d retention.purged events of read_audit_window with deleted=2, want 1", n)
	}
	if testutil.ToFloat64(lastSuccess) == 0 {
		t.Fatal("read_audit_window has no last success")
	}
}

// TestRetentionRoundFleetBreaker (plan M10 amendment 2026-10-30): the round shares one Fleet breaker across its
// organizations, so with Fleet down it asks Fleet three times in all; the organizations reached afterwards keep their
// rows and get one retention.purged failure each instead of one event per device.
func TestRetentionRoundFleetBreaker(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	platform, err := db.NewPlatformPool(ctx, pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	runner := app.NewActionRunner(f.pool, platform, httpx.RequestID)
	day := 24 * time.Hour
	fleet := &fakeSource{deleteErr: fmt.Errorf("%w: fleet: HTTP 503: unavailable", problem.UpstreamUnavailable)}
	r := NewRetention(app.NewRetention(runner, f.pool, platform, fleet, day, 400), app.NewLoginHistory(runner, f.pool, day), f.pool, platform, time.Hour)
	orgs := []uuid.UUID{f.org, newFixture(t).org}
	for i, org := range orgs {
		for j := range 3 {
			dev := uuid.Must(uuid.NewV7())
			for _, stmt := range []string{
				"INSERT INTO device (id, organization_id, hostname, state, state_changed_at) VALUES ($1, $2, 'gone', 'retired', now() - interval '400 days')",
				"INSERT INTO device_inventory_ref (device_id, organization_id, external_id) VALUES ($1, $2, $3)",
			} {
				args := []any{dev, org}
				if strings.Contains(stmt, "$3") {
					args = append(args, fmt.Sprintf("br-%d-%d", i, j))
				}
				if _, err := f.super.Exec(ctx, stmt, args...); err != nil {
					t.Fatal(err)
				}
			}
		}
	}

	if err := r.Round(ctx); err == nil {
		t.Fatal("round without an error although Fleet failed")
	}
	if fleet.deleteCalls != 3 {
		t.Fatalf("%d Fleet calls in the round, want 3", fleet.deleteCalls)
	}
	skipped := 0
	for _, org := range orgs {
		if n := f.count(t, "SELECT count(*) FROM device_inventory_ref WHERE organization_id = $1", org); n != 3 {
			t.Fatalf("organization %s keeps %d host references, want 3", org, n)
		}
		skips := f.count(t, `SELECT count(*) FROM action WHERE organization_id = $1 AND code = 'retention.purged'
			AND params->>'store' = 'retired_inventory' AND outcome = 'failure' AND error_code = 'upstream_unavailable'`, org)
		if skips > 1 {
			t.Fatalf("organization %s has %d skip events, want at most 1", org, skips)
		}
		skipped += skips
	}
	if skipped == 0 {
		t.Fatal("no organization recorded the skipped Fleet step")
	}
}

// TestRetentionRoundWaitsForLegacyLock (plan M10 amendment 2026-10-30): while a worker of an earlier version holds the
// login history round's lock, the retention round purges nothing, so a rolling upgrade never runs both purges at once.
func TestRetentionRoundWaitsForLegacyLock(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	platform, err := db.NewPlatformPool(ctx, pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	runner := app.NewActionRunner(f.pool, platform, httpx.RequestID)
	day := 24 * time.Hour
	r := NewRetention(app.NewRetention(runner, f.pool, platform, &fakeSource{}, day, 400), app.NewLoginHistory(runner, f.pool, day), f.pool, platform, time.Hour)
	f.seenUsers(t, f.org, 2, time.Now().Add(-400*day))
	seen := func() int {
		return f.count(t, "SELECT count(*) FROM device_user_seen WHERE organization_id = $1", f.org)
	}

	if _, err := f.super.Exec(ctx, "SELECT pg_advisory_lock($1)", int64(legacyLoginHistoryLockKey)); err != nil {
		t.Fatal(err)
	}
	if err := r.Round(ctx); err != nil {
		t.Fatal(err)
	}
	if n := seen(); n != 2 {
		t.Fatalf("%d rows left while the legacy lock is held, want 2", n)
	}
	if _, err := f.super.Exec(ctx, "SELECT pg_advisory_unlock($1)", int64(legacyLoginHistoryLockKey)); err != nil {
		t.Fatal(err)
	}
	if err := r.Round(ctx); err != nil {
		t.Fatal(err)
	}
	if n := seen(); n != 0 {
		t.Fatalf("%d rows left after the legacy lock was released, want 0", n)
	}
}

// TestRetentionRoundControlPlane (ADR 0032 amendments 2026-10-18 and 2026-10-31, PDK-180): after pass 4 the round
// purges finished commands, cleared alerts and filled event gaps older than the audit index retention, each with its
// own retention.purged event, and keeps the younger rows.
func TestRetentionRoundControlPlane(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	platform, err := db.NewPlatformPool(ctx, pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	runner := app.NewActionRunner(f.pool, platform, httpx.RequestID)
	day := 24 * time.Hour
	r := NewRetention(app.NewRetention(runner, f.pool, platform, &fakeSource{}, day, 500), app.NewLoginHistory(runner, f.pool, day), f.pool, platform, time.Hour)
	dev := uuid.Must(uuid.NewV7())
	expired, kept := time.Now().Add(-501*day), time.Now().Add(-499*day)
	if _, err := f.super.Exec(ctx, "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'cp', 'active')", dev, f.org); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`INSERT INTO device_command (id, organization_id, device_id, type, status, issued_at, expires_at, finished_at)
		 SELECT gen_random_uuid(), $1, $2, 'run_bundle', 'succeeded', t - interval '1 s', t + interval '1 day', t
		   FROM unnest(ARRAY[$3, $4]::timestamptz[]) t`,
		`INSERT INTO device_alert (id, organization_id, device_id, kind, raised_at, cleared_at)
		 SELECT gen_random_uuid(), $1, $2, 'stale_warning', t, t FROM unnest(ARRAY[$3, $4]::timestamptz[]) t`,
		`INSERT INTO device_event_gap (id, organization_id, device_id, from_seq, to_seq, first_seen_at, first_seen_last_seq, filled_at)
		 SELECT gen_random_uuid(), $1, $2, n, n, t, n, t FROM unnest(ARRAY[$3, $4]::timestamptz[]) WITH ORDINALITY AS u(t, n)`,
	} {
		if _, err := f.super.Exec(ctx, stmt, f.org, dev, expired, kept); err != nil {
			t.Fatal(err)
		}
	}

	if err := r.Round(ctx); err != nil {
		t.Fatal(err)
	}
	for _, store := range []string{app.StoreDeviceCommand, app.StoreDeviceAlert, app.StoreDeviceEventGap} {
		if n := f.count(t, "SELECT count(*) FROM "+store+" WHERE organization_id = $1", f.org); n != 1 {
			t.Errorf("%s: %d rows left, want the younger one", store, n)
		}
		if n := f.count(t, `SELECT count(*) FROM action WHERE organization_id = $1 AND code = 'retention.purged'
			AND outcome = 'success' AND params->>'store' = $2 AND (params->>'deleted')::int = 1`, f.org, store); n != 1 {
			t.Errorf("%s: %d success events with deleted 1, want 1", store, n)
		}
		if testutil.ToFloat64(metricRetentionLastSuccess.WithLabelValues(store)) == 0 {
			t.Errorf("%s has no last success", store)
		}
	}
	if len(r.passes) != 7 || r.passes[4].store != app.StoreDeviceCommand || r.passes[5].store != app.StoreDeviceAlert ||
		r.passes[6].store != app.StoreDeviceEventGap {
		t.Fatalf("passes %+v, want device_command, device_alert, device_event_gap after pass 4", r.passes)
	}
}
