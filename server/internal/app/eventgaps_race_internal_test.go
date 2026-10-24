package app

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// TestEventGapRoundAfterReset (PDK-108 review 1, B1): a reset that commits after the round listed its candidates and
// before it evaluates the device is not undone: the round neither restores the old pointer nor opens or reports gaps
// of the old numbering.
func TestEventGapRoundAfterReset(t *testing.T) {
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
	if _, err := super.Exec(ctx, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'G', 'active')", org, "g"+org.String()[24:]); err != nil {
		t.Fatal(err)
	}
	if _, err := super.Exec(ctx, "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'h', 'active')", dev, org); err != nil {
		t.Fatal(err)
	}
	runner := NewActionRunner(pool, nil, func(context.Context) string { return uuid.NewString() })
	reports, gaps := NewDeviceReports(runner, pool), NewEventGaps(runner, pool)
	sys := principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker", OrganizationID: org})
	at := time.Now().UTC().Add(-time.Hour)
	seq := int64(10)
	checkin := func(high int64) {
		t.Helper()
		at, seq = at.Add(time.Second), seq+1
		if err := reports.RecordStatus(sys, ingest.Heartbeat{DeviceID: dev, OrganizationID: org, ReceivedAt: at, Seq: seq,
			EventSeqHigh: high, Health: json.RawMessage(`{}`)}); err != nil {
			t.Fatal(err)
		}
	}
	round := func() {
		t.Helper()
		if err := gaps.Evaluate(sys, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	count := func(q string) int {
		t.Helper()
		var n int
		if err := super.QueryRow(ctx, q, dev).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	at = at.Add(time.Second)
	events := make([]protocol.Event, 0, 4)
	for s := int64(1); s <= 4; s++ {
		events = append(events, protocol.Event{EventSeq: s, Type: protocol.EventBundleApplied, OccurredAt: at, Data: json.RawMessage(`{"version":1}`)})
	}
	if err := reports.RecordEvents(sys, dev, at, events); err != nil {
		t.Fatal(err)
	}
	checkin(6)
	round()
	if c := count("SELECT event_seq_contiguous FROM device_status WHERE device_id = $1"); c != 4 {
		t.Fatalf("setup: event_seq_contiguous %d, want 4", c)
	}

	gaps.afterCandidates = func(context.Context) error {
		checkin(0)
		return nil
	}
	round()
	gaps.afterCandidates = nil
	if n := count("SELECT count(*) FROM action WHERE code = 'device.event_seq_reset' AND target ->> 'id' = $1::text"); n != 1 {
		t.Fatalf("%d device.event_seq_reset, want 1", n)
	}
	if c := count("SELECT event_seq_contiguous FROM device_status WHERE device_id = $1"); c != 0 {
		t.Fatalf("event_seq_contiguous %d after the reset, want 0", c)
	}
	if n := count("SELECT count(*) FROM device_event_gap WHERE device_id = $1 AND filled_at IS NULL"); n != 0 {
		t.Fatalf("%d open gaps of the old numbering after the reset", n)
	}
	checkin(0)
	checkin(0)
	round()
	if n := count("SELECT count(*) FROM action WHERE code = 'device.event_gap' AND target ->> 'id' = $1::text"); n != 0 {
		t.Fatalf("%d device.event_gap after the reset, want none", n)
	}
}
