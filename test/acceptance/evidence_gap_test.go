package acceptance

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/test/acceptance/devicesim"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// gapDevice is an active devicesim device of the event gap gate and the means to drive it.
type gapDevice struct {
	t     *testing.T
	d     *devicesim.Device
	alice *env.Portal
	db    *pgx.Conn
}

// send posts events with the given numbers (or one prepared event) and waits until the worker recorded them.
func (g gapDevice) send(events ...protocol.Event) {
	g.t.Helper()
	ctx := testContext(g.t, time.Minute)
	if res, err := g.d.SendEvents(ctx, events); err != nil || res.Status != http.StatusAccepted {
		g.t.Fatalf("events: %v HTTP %d %s", err, res.Status, res.Body)
	}
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(250 * time.Millisecond) {
		var pending int
		if err := g.db.QueryRow(ctx, `SELECT count(*) FROM unnest($2::bigint[]) s
			WHERE NOT EXISTS (SELECT 1 FROM device_event_seen e WHERE e.device_id = $1 AND e.event_seq = s AND e.received_at > now() - interval '1 minute')`,
			g.d.DeviceID, seqs(events)).Scan(&pending); err != nil {
			g.t.Fatal(err)
		}
		if pending == 0 {
			return
		}
		if time.Now().After(deadline) {
			g.t.Fatalf("events %v of %s not recorded within 30 s", seqs(events), g.d.DeviceID)
		}
	}
}

func seqs(events []protocol.Event) []int64 {
	out := make([]int64, 0, len(events))
	for _, ev := range events {
		out = append(out, ev.EventSeq)
	}
	return out
}

func bundleApplied(seq int64) protocol.Event {
	return protocol.Event{EventSeq: seq, Type: protocol.EventBundleApplied, OccurredAt: time.Now(), Data: json.RawMessage(`{"version":1}`)}
}

// materialize checks in with the device's EventSeqHigh and waits until the worker wrote the heartbeat. The coalescing
// claim hb:<device> (one materialized heartbeat per 60 s, plan M2a decision 12) is deleted first, so the gate does not
// wait a minute between check-ins (the plan's "≥ 65 s").
func (g gapDevice) materialize() {
	g.t.Helper()
	ctx := testContext(g.t, time.Minute)
	var before int64
	if err := g.db.QueryRow(ctx, "SELECT coalesce(max(last_seq), 0) FROM device_status WHERE device_id = $1", g.d.DeviceID).Scan(&before); err != nil {
		g.t.Fatal(err)
	}
	valkeyCLI(g.t, "DEL hb:"+g.d.DeviceID)
	if _, res, err := g.d.Checkin(ctx); err != nil || res.Status != http.StatusOK {
		g.t.Fatalf("check-in: %v %d %s", err, res.Status, res.Body)
	}
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(250 * time.Millisecond) {
		var seq int64
		if err := g.db.QueryRow(ctx, "SELECT coalesce(max(last_seq), 0) FROM device_status WHERE device_id = $1", g.d.DeviceID).Scan(&seq); err != nil {
			g.t.Fatal(err)
		}
		if seq > before {
			return
		}
		if time.Now().After(deadline) {
			g.t.Fatalf("check-in of %s not materialized within 30 s", g.d.DeviceID)
		}
	}
}

// waitOpenGap waits until the round opened a gap row from..to; the report counts the check-ins after it.
func (g gapDevice) waitOpenGap(from, to int64) {
	g.t.Helper()
	ctx := testContext(g.t, time.Minute)
	for deadline := time.Now().Add(45 * time.Second); ; time.Sleep(500 * time.Millisecond) {
		var n int
		if err := g.db.QueryRow(ctx, `SELECT count(*) FROM device_event_gap
			WHERE device_id = $1 AND from_seq = $2 AND to_seq = $3 AND filled_at IS NULL`, g.d.DeviceID, from, to).Scan(&n); err != nil {
			g.t.Fatal(err)
		}
		if n == 1 {
			return
		}
		if time.Now().After(deadline) {
			g.t.Fatalf("no open gap %d-%d of %s within 45 s", from, to, g.d.DeviceID)
		}
	}
}

// attention returns the details of the device's event_gap conditions.
func (g gapDevice) attention(p *env.Portal) []string {
	g.t.Helper()
	res := call(g.t, p, http.MethodGet, "/api/v1/attention/devices?"+url.Values{"device_id": {g.d.DeviceID}, "kind": {"event_gap"}}.Encode(), nil)
	expectStatus(g.t, res, http.StatusOK, "")
	var page struct {
		Items []struct {
			Conditions []struct {
				Kind   string `json:"kind"`
				Detail string `json:"detail"`
			} `json:"conditions"`
		} `json:"items"`
	}
	if err := res.JSON(&page); err != nil {
		g.t.Fatal(err)
	}
	var out []string
	for _, it := range page.Items {
		for _, c := range it.Conditions {
			if c.Kind == "event_gap" {
				out = append(out, c.Detail)
			}
		}
	}
	return out
}

// waitAttention polls the attention list until the device's event_gap details are want (the round runs every 15 s).
func (g gapDevice) waitAttention(want ...string) {
	g.t.Helper()
	for deadline := time.Now().Add(45 * time.Second); ; time.Sleep(time.Second) {
		got := g.attention(g.alice)
		if len(got) == len(want) && (len(want) == 0 || got[0] == want[0]) {
			return
		}
		if time.Now().After(deadline) {
			g.t.Fatalf("attention event_gap of %s: %v, want %v", g.d.DeviceID, got, want)
		}
	}
}

// events returns the device's audit events with code, once there are want of them (the audit pipeline is
// asynchronous); more than want fails at once.
func (g gapDevice) events(code string, want int) []env.AuditEvent {
	g.t.Helper()
	for deadline := time.Now().Add(90 * time.Second); ; time.Sleep(time.Second) {
		all, err := g.alice.AuditEvents(testContext(g.t, time.Minute), code)
		if err != nil {
			g.t.Fatal(err)
		}
		var mine []env.AuditEvent
		for _, e := range all {
			if e.Target != nil && e.Target.ID == g.d.DeviceID {
				mine = append(mine, e)
			}
		}
		if len(mine) == want {
			return mine
		}
		if len(mine) > want || time.Now().After(deadline) {
			g.t.Fatalf("%d %s for %s, want %d", len(mine), code, g.d.DeviceID, want)
		}
	}
}

// TestEventGap (plan M8b §9 G1–G4, decisions 17–23): a hole in a device's event numbering that survives two further
// check-ins is reported once and shown on the attention list, and closed once when its event arrives; events a
// device claims and never delivers are a gap up to its claim; a restarted counter is recorded once and its numbers
// are accepted again; ranges the agent admits it dropped are no gap. Another organization never sees the gap.
func TestEventGap(t *testing.T) {
	alice := login(t, env.Alice)
	db := ownerDB(t)
	g := gapDevice{t: t, d: activeDevice(t, alice, "", "gap-"+uniqueSuffix()), alice: alice, db: db}

	// G1: events 1, 2 and 4 with a claim of 4.
	g.send(bundleApplied(1), bundleApplied(2), bundleApplied(4))
	g.materialize()
	g.waitOpenGap(3, 3)
	g.materialize()
	g.materialize()
	g.waitAttention("3-3")
	gap := g.events("device.event_gap", 1)[0]
	if gap.Params["from_seq"] != float64(3) || gap.Params["to_seq"] != float64(3) || gap.Params["event_seq_high"] != float64(4) || gap.Outcome != "success" {
		t.Fatalf("device.event_gap %+v", gap)
	}
	if got := g.attention(login(t, env.Carol)); len(got) != 0 {
		t.Fatalf("carol sees the event gap of the acme device: %v", got)
	}

	// G2: event 3 arrives.
	g.send(bundleApplied(3))
	g.waitAttention()
	filled := g.events("device.event_gap_filled", 1)[0]
	if filled.Params["from_seq"] != float64(3) || filled.Params["to_seq"] != float64(3) {
		t.Fatalf("device.event_gap_filled %+v", filled)
	}

	// G4: the counter restarts at 1; event 1 is recorded a second time.
	g.d.EventSeqHigh = 1
	g.materialize()
	reset := g.events("device.event_seq_reset", 1)[0]
	if reset.Params["previous_high"] != float64(4) || reset.Params["reported_high"] != float64(1) {
		t.Fatalf("device.event_seq_reset %+v", reset)
	}
	g.send(bundleApplied(1))
	if n := len(g.appliedEvents(1, 2)); n != 2 {
		t.Fatalf("%d device.bundle_applied with event_seq 1, want 2", n)
	}
	g.materialize()
	if n := len(g.events("device.event_seq_reset", 1)); n != 1 {
		t.Fatalf("%d device.event_seq_reset after a further check-in, want 1", n)
	}

	// G4: 5..6 declared dropped, 2..4 delivered, claim 7: no gap.
	g.send(bundleApplied(2), bundleApplied(3), bundleApplied(4), protocol.Event{EventSeq: 7, Type: protocol.EventAgentEventsDropped,
		OccurredAt: time.Now(), Data: json.RawMessage(`{"from_seq":5,"to_seq":6,"count":2}`)})
	g.materialize()
	g.materialize()
	g.materialize()
	time.Sleep(20 * time.Second) // one more round after the last check-in; a wrong gap would be reported by now
	if got := g.attention(alice); len(got) != 0 {
		t.Fatalf("attention event_gap after a declared drop: %v", got)
	}
	g.events("device.event_gap", 1)

	// G3: events 1..3 delivered, 6 claimed.
	s := gapDevice{t: t, d: activeDevice(t, alice, "", "gap-silent-"+uniqueSuffix()), alice: alice, db: db}
	s.send(bundleApplied(1), bundleApplied(2), bundleApplied(3))
	s.d.EventSeqHigh = 6
	s.materialize()
	s.waitOpenGap(4, 6)
	s.materialize()
	s.materialize()
	s.waitAttention("4-6")
	silent := s.events("device.event_gap", 1)[0]
	if silent.Params["from_seq"] != float64(4) || silent.Params["to_seq"] != float64(6) || silent.Params["event_seq_high"] != float64(6) {
		t.Fatalf("device.event_gap %+v", silent)
	}
}

// appliedEvents returns the device's device.bundle_applied events with event_seq seq, once there are want of them.
func (g gapDevice) appliedEvents(seq int64, want int) []env.AuditEvent {
	g.t.Helper()
	for deadline := time.Now().Add(90 * time.Second); ; time.Sleep(time.Second) {
		var out []env.AuditEvent
		all, err := g.alice.AuditEvents(testContext(g.t, time.Minute), "device.bundle_applied")
		if err != nil {
			g.t.Fatal(err)
		}
		for _, e := range all {
			if e.Target != nil && e.Target.ID == g.d.DeviceID && e.Params["event_seq"] == float64(seq) {
				out = append(out, e)
			}
		}
		if len(out) >= want || time.Now().After(deadline) {
			return out
		}
	}
}
