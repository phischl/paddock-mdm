package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// gapWorld is one active device and the event gap round of its organization (plan M8b decisions 17–23).
type gapWorld struct {
	releaseHarness
	gaps     *app.EventGaps
	org, dev uuid.UUID
	at       time.Time
	seq      int64
}

func newGapWorld(t *testing.T) *gapWorld {
	t.Helper()
	h := newReleaseHarness(t, true)
	pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).Worker, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	org, dev := h.device(t)
	return &gapWorld{releaseHarness: h, gaps: app.NewEventGaps(h.runner, pool), org: org, dev: dev,
		at: time.Now().UTC().Add(-time.Hour), seq: 10}
}

// tick advances the gateway's clock of the world.
func (w *gapWorld) tick() time.Time {
	w.at = w.at.Add(time.Second)
	return w.at
}

// events records events with the given numbers as one batch the gateway received now.
func (w *gapWorld) events(t *testing.T, seqs ...int64) {
	t.Helper()
	w.eventsAt(t, w.tick(), seqs...)
}

func (w *gapWorld) eventsAt(t *testing.T, received time.Time, seqs ...int64) {
	t.Helper()
	events := make([]protocol.Event, 0, len(seqs))
	for _, s := range seqs {
		events = append(events, protocol.Event{EventSeq: s, Type: protocol.EventBundleApplied, OccurredAt: received,
			Data: json.RawMessage(`{"version":1}`)})
	}
	if err := w.reports.RecordEvents(systemCtx(w.org), w.dev, received, events); err != nil {
		t.Fatal(err)
	}
}

// checkin materializes a check-in that reports high as the highest event number; each one advances last_seq.
func (w *gapWorld) checkin(t *testing.T, high int64) {
	t.Helper()
	w.checkinAt(t, w.tick(), high)
}

func (w *gapWorld) checkinAt(t *testing.T, received time.Time, high int64) {
	t.Helper()
	w.seq++
	if err := w.reports.RecordStatus(systemCtx(w.org), ingest.Heartbeat{DeviceID: w.dev, OrganizationID: w.org,
		ReceivedAt: received, Seq: w.seq, EventSeqHigh: high, Health: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
}

func (w *gapWorld) round(t *testing.T) {
	t.Helper()
	if err := w.gaps.Evaluate(systemCtx(w.org), time.Now()); err != nil {
		t.Fatal(err)
	}
}

func (w *gapWorld) count(t *testing.T, code string) int {
	t.Helper()
	var n int
	if err := w.super.QueryRow(context.Background(), "SELECT count(*) FROM action WHERE organization_id = $1 AND code = $2 AND target ->> 'id' = $3",
		w.org, code, w.dev.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (w *gapWorld) params(t *testing.T, code string) map[string]any {
	t.Helper()
	var p map[string]any
	if err := w.super.QueryRow(context.Background(), "SELECT params FROM action WHERE organization_id = $1 AND code = $2 AND target ->> 'id' = $3",
		w.org, code, w.dev.String()).Scan(&p); err != nil {
		t.Fatal(err)
	}
	return p
}

// gapRow is a device_event_gap row.
type gapRow struct {
	id               uuid.UUID
	from, to         int64
	firstSeenLastSeq int64
	reported, filled bool
}

func (w *gapWorld) gapRows(t *testing.T) []gapRow {
	t.Helper()
	rows, err := w.super.Query(context.Background(), `SELECT id, from_seq, to_seq, first_seen_last_seq, reported_at IS NOT NULL, filled_at IS NOT NULL
		FROM device_event_gap WHERE device_id = $1 ORDER BY from_seq, first_seen_at`, w.dev)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []gapRow
	for rows.Next() {
		var r gapRow
		if err := rows.Scan(&r.id, &r.from, &r.to, &r.firstSeenLastSeq, &r.reported, &r.filled); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func (w *gapWorld) attention(t *testing.T) []string {
	t.Helper()
	rows, err := w.super.Query(context.Background(),
		"SELECT kind || '|' || detail || '|' || id FROM attention_condition WHERE device_id = $1 AND kind = 'event_gap'", w.dev)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

func (w *gapWorld) status(t *testing.T) (contiguous, high, seen int64) {
	t.Helper()
	if err := w.super.QueryRow(context.Background(), `SELECT event_seq_contiguous, event_seq_high,
		(SELECT count(*) FROM device_event_seen WHERE device_id = $1) FROM device_status WHERE device_id = $1`, w.dev).
		Scan(&contiguous, &high, &seen); err != nil {
		t.Fatal(err)
	}
	return contiguous, high, seen
}

// TestEventGapReportedAndFilled (plan M8b decision 20): a hole is opened by the round that first sees it, reported
// once after two further check-ins and closed with device.event_gap_filled when its events arrive later.
func TestEventGapReportedAndFilled(t *testing.T) {
	w := newGapWorld(t)
	w.events(t, 1, 2, 4)
	w.checkin(t, 4)
	first := w.seq
	w.round(t)
	rows := w.gapRows(t)
	if len(rows) != 1 || rows[0].from != 3 || rows[0].to != 3 || rows[0].reported || rows[0].filled || rows[0].firstSeenLastSeq != first {
		t.Fatalf("gap rows after round 1: %+v", rows)
	}
	if c, _, _ := w.status(t); c != 2 {
		t.Fatalf("event_seq_contiguous %d, want 2", c)
	}
	w.checkin(t, 4)
	w.round(t)
	if n := w.count(t, "device.event_gap"); n != 0 || len(w.attention(t)) != 0 {
		t.Fatalf("gap reported after one further check-in (%d events)", n)
	}
	w.checkin(t, 4)
	w.round(t)
	w.round(t)
	if n := w.count(t, "device.event_gap"); n != 1 {
		t.Fatalf("%d device.event_gap, want 1", n)
	}
	p := w.params(t, "device.event_gap")
	if p["from_seq"] != float64(3) || p["to_seq"] != float64(3) || p["event_seq_high"] != float64(4) || p["first_seen_at"] == nil || p["last_contact_at"] == nil {
		t.Fatalf("device.event_gap params %v", p)
	}
	rows = w.gapRows(t)
	if len(rows) != 1 || !rows[0].reported || rows[0].filled {
		t.Fatalf("gap rows after the report: %+v", rows)
	}
	if got, want := w.attention(t), "event_gap|3-3|event_gap:"+rows[0].id.String(); len(got) != 1 || got[0] != want {
		t.Fatalf("attention %v, want [%s]", got, want)
	}

	w.events(t, 3)
	w.round(t)
	w.round(t)
	if n := w.count(t, "device.event_gap_filled"); n != 1 {
		t.Fatalf("%d device.event_gap_filled, want 1", n)
	}
	if p := w.params(t, "device.event_gap_filled"); p["from_seq"] != float64(3) || p["to_seq"] != float64(3) || p["reported_at"] == nil {
		t.Fatalf("device.event_gap_filled params %v", p)
	}
	if rows := w.gapRows(t); len(rows) != 1 || !rows[0].filled {
		t.Fatalf("gap rows after the fill: %+v", rows)
	}
	if got := w.attention(t); len(got) != 0 {
		t.Fatalf("attention after the fill: %v", got)
	}
	if c, _, _ := w.status(t); c != 4 {
		t.Fatalf("event_seq_contiguous %d, want 4", c)
	}
}

// TestEventGapFilledBeforeReport: a hole whose events arrive before the second further check-in closes silently.
func TestEventGapFilledBeforeReport(t *testing.T) {
	w := newGapWorld(t)
	w.events(t, 1, 3)
	w.checkin(t, 3)
	w.round(t)
	w.checkin(t, 3)
	w.events(t, 2)
	w.round(t)
	w.checkin(t, 3)
	w.checkin(t, 3)
	w.round(t)
	rows := w.gapRows(t)
	if len(rows) != 1 || rows[0].reported || !rows[0].filled {
		t.Fatalf("gap rows %+v, want one closed without a report", rows)
	}
	if n, f := w.count(t, "device.event_gap"), w.count(t, "device.event_gap_filled"); n != 0 || f != 0 {
		t.Fatalf("device.event_gap %d, device.event_gap_filled %d, want none", n, f)
	}
}

// TestEventGapSilence (plan G3): events a device claims and never delivers form a trailing gap up to its claim.
func TestEventGapSilence(t *testing.T) {
	w := newGapWorld(t)
	w.events(t, 1, 2, 3)
	w.checkin(t, 6)
	w.round(t)
	w.checkin(t, 6)
	w.checkin(t, 6)
	w.round(t)
	if p := w.params(t, "device.event_gap"); p["from_seq"] != float64(4) || p["to_seq"] != float64(6) || p["event_seq_high"] != float64(6) {
		t.Fatalf("device.event_gap params %v", p)
	}
}

// TestEventGapGrowsWithoutConflict: a trailing gap that grows with the next claim opens a second row for the new
// numbers instead of colliding with the open one.
func TestEventGapGrowsWithoutConflict(t *testing.T) {
	w := newGapWorld(t)
	w.events(t, 1)
	w.checkin(t, 2)
	w.round(t)
	w.checkin(t, 5)
	w.round(t)
	rows := w.gapRows(t)
	if len(rows) != 2 || rows[0].from != 2 || rows[0].to != 2 || rows[1].from != 3 || rows[1].to != 5 {
		t.Fatalf("gap rows %+v, want 2-2 and 3-5", rows)
	}
}

// TestEventGapDroppedRangeIsNoGap (plan M8b decision 19): numbers the agent admits it dropped are no gap.
func TestEventGapDroppedRangeIsNoGap(t *testing.T) {
	w := newGapWorld(t)
	w.events(t, 1, 2, 3, 4)
	received := w.tick()
	if err := w.reports.RecordEvents(systemCtx(w.org), w.dev, received, []protocol.Event{{EventSeq: 7, Type: protocol.EventAgentEventsDropped,
		OccurredAt: received, Data: json.RawMessage(`{"from_seq":5,"to_seq":6,"count":2}`)}}); err != nil {
		t.Fatal(err)
	}
	w.checkin(t, 7)
	w.round(t)
	w.checkin(t, 7)
	w.checkin(t, 7)
	w.round(t)
	if rows := w.gapRows(t); len(rows) != 0 {
		t.Fatalf("gap rows %+v, want none", rows)
	}
	if c, _, _ := w.status(t); c != 7 {
		t.Fatalf("event_seq_contiguous %d, want 7", c)
	}
}

// TestEventSeqReset (plan M8b decision 22): a check-in that claims less than the device delivered before it forgets
// the delivered numbers once, closes open gaps without an event, and the restarted numbering is recorded again.
func TestEventSeqReset(t *testing.T) {
	w := newGapWorld(t)
	w.events(t, 1, 2, 3, 4)
	w.checkin(t, 6)
	w.round(t)
	if c, _, _ := w.status(t); c != 4 || len(w.gapRows(t)) != 1 {
		t.Fatalf("setup: contiguous %d, gaps %+v", c, w.gapRows(t))
	}
	w.checkin(t, 1)
	if n := w.count(t, "device.event_seq_reset"); n != 1 {
		t.Fatalf("%d device.event_seq_reset, want 1", n)
	}
	p := w.params(t, "device.event_seq_reset")
	if p["previous_high"] != float64(4) || p["reported_high"] != float64(1) || p["events_seen"] != float64(4) {
		t.Fatalf("device.event_seq_reset params %v", p)
	}
	if c, high, seen := w.status(t); c != 0 || high != 1 || seen != 0 {
		t.Fatalf("after the reset: contiguous %d, high %d, seen rows %d", c, high, seen)
	}
	if rows := w.gapRows(t); len(rows) != 1 || !rows[0].filled || rows[0].reported {
		t.Fatalf("open gap after the reset: %+v", rows)
	}
	if n := w.count(t, "device.event_gap_filled"); n != 0 {
		t.Fatalf("a reset closed a gap with an event")
	}
	w.checkin(t, 1)
	if n := w.count(t, "device.event_seq_reset"); n != 1 {
		t.Fatalf("a second identical check-in recorded %d resets", n)
	}
	fresh, err := w.reports.RecordEvent(systemCtx(w.org), w.dev, protocol.Event{EventSeq: 1, Type: protocol.EventBundleApplied,
		OccurredAt: time.Now(), Data: json.RawMessage(`{"version":1}`)})
	if err != nil || !fresh {
		t.Fatalf("event 1 after the reset: fresh %v, %v", fresh, err)
	}
}

// TestEventSeqNoResetForLaterEvents (amendment 2026-10-24): events the agent numbered after a check-in and the worker
// recorded before it are no reset — they reached the gateway after the check-in.
func TestEventSeqNoResetForLaterEvents(t *testing.T) {
	w := newGapWorld(t)
	w.events(t, 1, 2, 3)
	w.checkin(t, 3)
	checkin := w.tick()
	w.events(t, 4, 5, 6)
	w.checkinAt(t, checkin, 3)
	if n := w.count(t, "device.event_seq_reset"); n != 0 {
		t.Fatalf("%d device.event_seq_reset for events received after the check-in", n)
	}
	if _, _, seen := w.status(t); seen != 6 {
		t.Fatalf("%d delivered numbers kept, want 6", seen)
	}
	fresh, err := w.reports.RecordEvent(systemCtx(w.org), w.dev, protocol.Event{EventSeq: 5, Type: protocol.EventBundleApplied,
		OccurredAt: time.Now(), Data: json.RawMessage(`{"version":1}`)})
	if err != nil || fresh {
		t.Fatalf("redelivered event 5: fresh %v, %v; want deduplicated", fresh, err)
	}
	w.round(t)
	if rows := w.gapRows(t); len(rows) != 0 {
		t.Fatalf("gap rows %+v, want none", rows)
	}
}

// TestEventGapTablesWriteOnlyForWorker: the api reads gaps and nothing else of the new tables; DELETE on the event
// tables belongs to the worker alone.
func TestEventGapTablesWriteOnlyForWorker(t *testing.T) {
	w := newGapWorld(t)
	ctx := context.Background()
	for _, stmt := range []string{
		"INSERT INTO device_event_gap (id, organization_id, device_id, from_seq, to_seq, first_seen_at, first_seen_last_seq) VALUES (gen_random_uuid(), $1, $2, 1, 1, now(), 0)",
		"UPDATE device_event_gap SET reported_at = now() WHERE organization_id = $1 AND device_id = $2",
		"DELETE FROM device_event_gap WHERE organization_id = $1 AND device_id = $2",
		"SELECT 1 FROM device_event_dropped WHERE organization_id = $1 AND device_id = $2",
		"INSERT INTO device_event_dropped (device_id, from_seq, to_seq, organization_id) VALUES ($2, 1, 1, $1)",
		"DELETE FROM device_event_seen WHERE organization_id = $1 AND device_id = $2",
	} {
		tx, err := w.super.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE paddock_api"); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, "SELECT set_config('paddock.org_id', $1, true)", w.org.String()); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, stmt, w.org, w.dev)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("paddock_api %q: %v, want permission denied (42501)", stmt, err)
		}
		_ = tx.Rollback(ctx)
	}
	rows, err := w.super.Query(ctx, `SELECT table_name || ':' || grantee FROM information_schema.role_table_grants
		WHERE privilege_type = 'DELETE' AND table_name IN ('device_event_seen', 'device_event_dropped', 'device_event_gap')
		  AND grantee LIKE 'paddock\_%' AND grantee <> 'paddock_owner' ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var grants []string
	for rows.Next() {
		var g string
		if err := rows.Scan(&g); err != nil {
			t.Fatal(err)
		}
		grants = append(grants, g)
	}
	if len(grants) != 2 || grants[0] != "device_event_dropped:paddock_worker" || grants[1] != "device_event_seen:paddock_worker" {
		t.Fatalf("DELETE grants %v", grants)
	}
	var reads bool
	if err := w.super.QueryRow(ctx, "SELECT has_table_privilege('paddock_api', 'device_event_gap', 'SELECT')").Scan(&reads); err != nil || !reads {
		t.Fatalf("paddock_api cannot read device_event_gap: %v", err)
	}
}

// TestEventSeqNoResetForLaterEventsAfterRound (PDK-108 review 1, T1): a round that advanced the pointer over events
// received after a check-in does not turn that check-in into a reset: the pointer is no evidence (amendment
// 2026-10-24, decision 22).
func TestEventSeqNoResetForLaterEventsAfterRound(t *testing.T) {
	w := newGapWorld(t)
	w.events(t, 1, 2, 3)
	w.checkin(t, 3)
	checkin := w.tick()
	w.events(t, 4, 5, 6)
	w.round(t)
	if c, _, _ := w.status(t); c != 6 {
		t.Fatalf("setup: event_seq_contiguous %d, want 6", c)
	}
	w.checkinAt(t, checkin, 3)
	if n := w.count(t, "device.event_seq_reset"); n != 0 {
		t.Fatalf("%d device.event_seq_reset for events received after the check-in", n)
	}
	if c, _, seen := w.status(t); c != 6 || seen != 6 {
		t.Fatalf("contiguous %d, delivered numbers %d; want 6 and 6", c, seen)
	}
	w.round(t)
	if rows := w.gapRows(t); len(rows) != 0 {
		t.Fatalf("gap rows %+v, want none", rows)
	}
}
