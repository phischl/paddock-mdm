package worker

import (
	"context"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// TestStalenessThenFindings (plan M9 decision 32): the findings round runs right after the staleness round, so the
// critical alert one staleness round raises is a finding when that round returns, and the alert it clears is a
// cleared finding.
func TestStalenessThenFindings(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	platform, err := db.NewPlatformPool(ctx, pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	runner := app.NewActionRunner(f.pool, platform, httpx.RequestID)
	staleness := NewStaleness(app.NewStaleness(runner, f.pool, time.Minute), f.pool, platform, time.Hour).
		Then(NewFindings(app.NewFindings(runner, f.pool), f.pool, platform).Round)
	if _, err := f.super.Exec(ctx, "INSERT INTO organization_update_settings (organization_id, staleness_warning_h, staleness_critical_h) VALUES ($1, 2, 5)", f.org); err != nil {
		t.Fatal(err)
	}
	dev := f.device(t, "active")
	if _, err := f.super.Exec(ctx, "INSERT INTO device_status (device_id, organization_id, last_contact_at) VALUES ($1, $2, $3)",
		dev, f.org, time.Now().Add(-10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	live := "SELECT count(*) FROM finding WHERE device_id = $1 AND kind = 'attention' AND code = 'stale_critical' AND cleared_at IS NULL"
	cleared := "SELECT count(*) FROM finding WHERE device_id = $1 AND kind = 'attention' AND code = 'stale_critical' AND cleared_at IS NOT NULL"
	if err := staleness.Round(ctx); err != nil {
		t.Fatal(err)
	}
	if n := f.count(t, live, dev); n != 1 {
		t.Fatalf("%d live stale_critical findings after one round, want 1", n)
	}
	if _, err := f.super.Exec(ctx, "UPDATE device_status SET last_contact_at = now() WHERE device_id = $1", dev); err != nil {
		t.Fatal(err)
	}
	if err := staleness.Round(ctx); err != nil {
		t.Fatal(err)
	}
	if live, cleared := f.count(t, live, dev), f.count(t, cleared, dev); live != 0 || cleared != 1 {
		t.Fatalf("after the check-in: %d live, %d cleared findings; want 0 and 1", live, cleared)
	}
}
