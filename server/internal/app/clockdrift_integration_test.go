package app_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/ingest"
)

// TestClockDriftEpisode (plan M8b decisions 12–15): a materialized heartbeat more than 60 s off opens a clock drift
// episode once (device.clock_drift, attention kind clock_drift), an offset between 30 and 60 s changes nothing, an
// offset within 30 s closes it once (device.clock_drift_cleared); a heartbeat that arrives out of order is ignored
// and event_seq_high is stored as reported.
func TestClockDriftEpisode(t *testing.T) {
	h := newReleaseHarness(t, true)
	org, dev := h.device(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-time.Hour)
	beat := func(offset, seqHigh int64) {
		t.Helper()
		at = at.Add(time.Minute)
		if err := h.reports.RecordStatus(systemCtx(org), ingest.Heartbeat{DeviceID: dev, OrganizationID: org, ReceivedAt: at,
			ClockOffsetS: offset, EventSeqHigh: seqHigh, Health: json.RawMessage(`{}`)}); err != nil {
			t.Fatal(err)
		}
	}
	count := func(code string) int {
		t.Helper()
		var n int
		if err := h.super.QueryRow(ctx, "SELECT count(*) FROM action WHERE organization_id = $1 AND code = $2", org, code).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	attention := func() []string {
		t.Helper()
		rows, err := h.super.Query(ctx, "SELECT kind || '|' || detail || '|' || id FROM attention_condition WHERE device_id = $1 AND kind = 'clock_drift'", dev)
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

	beat(10, 7)
	if count("device.clock_drift") != 0 || len(attention()) != 0 {
		t.Fatal("an in-sync device raised a clock drift")
	}
	beat(120, 3)
	var since *time.Time
	var seqHigh int64
	if err := h.super.QueryRow(ctx, "SELECT clock_drift_since, event_seq_high FROM device_status WHERE device_id = $1", dev).Scan(&since, &seqHigh); err != nil {
		t.Fatal(err)
	}
	if since == nil {
		t.Fatal("clock_drift_since not set")
	}
	if seqHigh != 3 {
		t.Fatalf("event_seq_high %d, want 3 as reported", seqHigh)
	}
	var params map[string]any
	var target string
	if err := h.super.QueryRow(ctx, "SELECT params, target ->> 'id' FROM action WHERE organization_id = $1 AND code = 'device.clock_drift'", org).Scan(&params, &target); err != nil {
		t.Fatal(err)
	}
	if params["offset_s"] != float64(120) || params["threshold_s"] != float64(60) || params["last_contact_at"] == nil || target != dev.String() {
		t.Fatalf("device.clock_drift params %v target %s", params, target)
	}
	want := "clock_drift|120 s|clock_drift:" + dev.String()
	if got := attention(); len(got) != 1 || got[0] != want {
		t.Fatalf("attention %v, want [%s]", got, want)
	}

	beat(120, 3)
	beat(-45, 3)
	if n := count("device.clock_drift"); n != 1 {
		t.Fatalf("%d device.clock_drift after a repeated and a hysteresis check-in, want 1", n)
	}
	if n := count("device.clock_drift_cleared"); n != 0 {
		t.Fatalf("an offset of 45 s cleared the episode (%d)", n)
	}
	if got := attention(); len(got) != 1 || got[0] != "clock_drift|-45 s|clock_drift:"+dev.String() {
		t.Fatalf("attention while drifting %v", got)
	}

	// A late heartbeat from before the episode does not overwrite the newer offset and so does not clear it.
	if err := h.reports.RecordStatus(systemCtx(org), ingest.Heartbeat{DeviceID: dev, OrganizationID: org,
		ReceivedAt: at.Add(-time.Hour), Health: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if n := count("device.clock_drift_cleared"); n != 0 {
		t.Fatal("an out-of-order heartbeat cleared the episode")
	}

	beat(10, 3)
	beat(0, 3)
	if n := count("device.clock_drift_cleared"); n != 1 {
		t.Fatalf("%d device.clock_drift_cleared, want 1", n)
	}
	if err := h.super.QueryRow(ctx, "SELECT params FROM action WHERE organization_id = $1 AND code = 'device.clock_drift_cleared'", org).Scan(&params); err != nil {
		t.Fatal(err)
	}
	if params["offset_s"] != float64(10) || params["threshold_s"] != float64(30) || params["since"] != since.UTC().Truncate(time.Millisecond).Format(time.RFC3339Nano) {
		t.Fatalf("device.clock_drift_cleared params %v, since %v", params, since)
	}
	if got := attention(); len(got) != 0 {
		t.Fatalf("attention after the clock is back %v", got)
	}
}

// TestClockDriftOnlyActiveRaises (plan M8b decision 14): a quarantined device raises no episode, but an episode that
// was open when it was quarantined is closed when its clock is back.
func TestClockDriftOnlyActiveRaises(t *testing.T) {
	h := newReleaseHarness(t, true)
	org, dev := h.device(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-time.Hour)
	beat := func(offset int64) {
		t.Helper()
		at = at.Add(time.Minute)
		if err := h.reports.RecordStatus(systemCtx(org), ingest.Heartbeat{DeviceID: dev, OrganizationID: org, ReceivedAt: at,
			ClockOffsetS: offset, Health: json.RawMessage(`{}`)}); err != nil {
			t.Fatal(err)
		}
	}
	codes := func() map[string]int {
		t.Helper()
		rows, err := h.super.Query(ctx, "SELECT code, count(*) FROM action WHERE organization_id = $1 AND code LIKE 'device.clock_drift%' GROUP BY code", org)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]int{}
		for rows.Next() {
			var code string
			var n int
			if err := rows.Scan(&code, &n); err != nil {
				t.Fatal(err)
			}
			out[code] = n
		}
		return out
	}
	setState := func(state string) {
		t.Helper()
		if _, err := h.super.Exec(ctx, "UPDATE device SET state = $2 WHERE id = $1", dev, state); err != nil {
			t.Fatal(err)
		}
	}

	beat(-120)
	if got := codes(); got["device.clock_drift"] != 1 {
		t.Fatalf("a device 120 s ahead raised %v, want one device.clock_drift", got)
	}
	setState("quarantined")
	var drifting int
	if err := h.super.QueryRow(ctx, "SELECT count(*) FROM attention_condition WHERE device_id = $1 AND kind = 'clock_drift'", dev).Scan(&drifting); err != nil || drifting != 0 {
		t.Fatalf("a quarantined device is listed as clock_drift (%d, %v)", drifting, err)
	}
	beat(5)
	if got := codes(); got["device.clock_drift_cleared"] != 1 {
		t.Fatalf("the open episode of a quarantined device was not cleared: %v", got)
	}
	beat(300)
	if got := codes(); got["device.clock_drift"] != 1 {
		t.Fatalf("a quarantined device raised a clock drift: %v", got)
	}
	var since *time.Time
	if err := h.super.QueryRow(ctx, "SELECT clock_drift_since FROM device_status WHERE device_id = $1", dev).Scan(&since); err != nil || since != nil {
		t.Fatalf("clock_drift_since %v of a quarantined device (%v)", since, err)
	}
}
