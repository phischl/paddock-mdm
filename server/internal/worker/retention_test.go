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
	r := NewRetention(app.NewRetention(runner, f.pool, day), app.NewLoginHistory(runner, f.pool, day), f.pool, platform, time.Hour)

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
