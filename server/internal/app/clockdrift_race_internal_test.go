package app

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// TestClockDriftClaimRechecksOffset (PDK-418): a check-in that commits between the claim's read of the clock state and
// its update neither opens an episode on an offset back in range nor closes one on an offset that drifted again.
func TestClockDriftClaimRechecksOffset(t *testing.T) {
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	pool, err := db.NewOrgPool(ctx, env.Worker, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	org, dev := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	if _, err := super.Exec(ctx, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'C', 'active')", org, "c"+org.String()[24:]); err != nil {
		t.Fatal(err)
	}
	if _, err := super.Exec(ctx, "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'h', 'active')", dev, org); err != nil {
		t.Fatal(err)
	}
	runner := NewActionRunner(pool, nil, func(context.Context) string { return uuid.NewString() })
	reports := NewDeviceReports(runner, pool)
	sys := principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker", OrganizationID: org})
	at := time.Now().UTC().Add(-time.Hour)
	beat := func(offset int64) {
		t.Helper()
		at = at.Add(time.Minute)
		if err := reports.RecordStatus(sys, ingest.Heartbeat{DeviceID: dev, OrganizationID: org, ReceivedAt: at,
			ClockOffsetS: offset, Health: json.RawMessage(`{}`)}); err != nil {
			t.Fatal(err)
		}
	}
	// The concurrent check-in commits on its own connection while the claim's transaction is still open.
	concurrentCheckin := func(offset int64) func(context.Context) error {
		return func(context.Context) error {
			_, err := super.Exec(ctx, "UPDATE device_status SET clock_offset_s = $2 WHERE device_id = $1", dev, offset)
			return err
		}
	}
	state := func() (drifting bool, raised, cleared int) {
		t.Helper()
		if err := super.QueryRow(ctx, `SELECT clock_drift_since IS NOT NULL,
			(SELECT count(*) FROM action WHERE target ->> 'id' = $2 AND code = 'device.clock_drift'),
			(SELECT count(*) FROM action WHERE target ->> 'id' = $2 AND code = 'device.clock_drift_cleared')
			FROM device_status WHERE device_id = $1`, dev, dev.String()).Scan(&drifting, &raised, &cleared); err != nil {
			t.Fatal(err)
		}
		return drifting, raised, cleared
	}

	reports.afterClockRead = concurrentCheckin(10)
	beat(120)
	if drifting, raised, _ := state(); drifting || raised != 0 {
		t.Fatalf("episode opened on an offset back in range: drifting %v, %d device.clock_drift", drifting, raised)
	}

	reports.afterClockRead = nil
	beat(120)
	if drifting, raised, _ := state(); !drifting || raised != 1 {
		t.Fatalf("setup: drifting %v, %d device.clock_drift, want an open episode", drifting, raised)
	}

	reports.afterClockRead = concurrentCheckin(120)
	beat(5)
	if drifting, _, cleared := state(); !drifting || cleared != 0 {
		t.Fatalf("episode closed on an offset that drifted again: drifting %v, %d device.clock_drift_cleared", drifting, cleared)
	}

	reports.afterClockRead = nil
	beat(5)
	if drifting, _, cleared := state(); drifting || cleared != 1 {
		t.Fatalf("drifting %v, %d device.clock_drift_cleared after the clock is back, want one", drifting, cleared)
	}
}
