package acceptance

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// TestClockDrift (plan M8b §9 C1–C2, decisions 11–15): a device whose signed check-in time is 2 minutes behind the
// server appears on the attention list with the kind clock_drift and its offset, and the audit log holds exactly one
// device.clock_drift; a second skewed check-in and a check-in 45 s off (hysteresis) change nothing; once the clock is
// back the condition is gone and exactly one device.clock_drift_cleared exists. Another organization never sees it.
func TestClockDrift(t *testing.T) {
	alice := login(t, env.Alice)
	d := activeDevice(t, alice, "", "clk-"+uniqueSuffix())
	ctx := testContext(t, 5*time.Minute)
	db := ownerDB(t)

	// materialize checks in with the clock offset and waits until the worker wrote the heartbeat. The coalescing
	// claim hb:<device> (one materialized heartbeat per 60 s, plan M2a decision 12) is deleted first, so the gate
	// does not wait a minute between check-ins.
	materialize := func(offset time.Duration) int64 {
		t.Helper()
		var before *time.Time
		if err := db.QueryRow(ctx, "SELECT max(last_contact_at) FROM device_status WHERE device_id = $1", d.DeviceID).Scan(&before); err != nil {
			t.Fatal(err)
		}
		valkeyCLI(t, "DEL hb:"+d.DeviceID)
		d.ClockOffset = offset
		if _, res, err := d.Checkin(ctx); err != nil || res.Status != http.StatusOK {
			t.Fatalf("check-in with offset %s: %v %d %s", offset, err, res.Status, res.Body)
		}
		for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(250 * time.Millisecond) {
			var at *time.Time
			var got *int64
			if err := db.QueryRow(ctx, "SELECT max(last_contact_at), max(clock_offset_s) FROM device_status WHERE device_id = $1", d.DeviceID).Scan(&at, &got); err != nil {
				t.Fatal(err)
			}
			if at != nil && (before == nil || at.After(*before)) && got != nil {
				return *got
			}
			if time.Now().After(deadline) {
				t.Fatalf("check-in with offset %s not materialized within 30 s", offset)
			}
		}
	}
	type condition struct {
		Kind   string `json:"kind"`
		Detail string `json:"detail"`
	}
	drift := func(p *env.Portal) []condition {
		t.Helper()
		res := call(t, p, http.MethodGet, "/api/v1/attention/devices?"+url.Values{"device_id": {d.DeviceID}, "kind": {"clock_drift"}}.Encode(), nil)
		expectStatus(t, res, http.StatusOK, "")
		var page struct {
			Items []struct {
				Conditions []condition `json:"conditions"`
			} `json:"items"`
		}
		if err := res.JSON(&page); err != nil {
			t.Fatal(err)
		}
		var out []condition
		for _, it := range page.Items {
			for _, c := range it.Conditions {
				if c.Kind == "clock_drift" {
					out = append(out, c)
				}
			}
		}
		return out
	}
	// waitDrift polls the attention list: the worker evaluates the drift right after it wrote the heartbeat.
	waitDrift := func(open bool) []condition {
		t.Helper()
		for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(250 * time.Millisecond) {
			got := drift(alice)
			if (len(got) == 1) == open {
				return got
			}
			if time.Now().After(deadline) {
				t.Fatalf("attention clock_drift of %s: %+v, want open %v", d.DeviceID, got, open)
			}
		}
	}
	waitEvents := func(code string, want int) {
		t.Helper()
		for deadline := time.Now().Add(90 * time.Second); ; time.Sleep(time.Second) {
			n := eventCount(t, alice, code, d.DeviceID)
			if n == want {
				return
			}
			if n > want || time.Now().After(deadline) {
				t.Fatalf("%d %s for %s, want %d", n, code, d.DeviceID, want)
			}
		}
	}

	// C1: 2 minutes behind. The offset is whole seconds of the server's and the signed time, so latency across a
	// second boundary may add one.
	offset := materialize(-2 * time.Minute)
	if offset != 120 && offset != 121 {
		t.Fatalf("clock offset %d, want 120 (or 121 across a second boundary)", offset)
	}
	want := fmt.Sprintf("%d s", offset)
	if got := waitDrift(true); got[0].Detail != want {
		t.Fatalf("attention clock_drift of %s: %+v, want detail %q", d.DeviceID, got, want)
	}
	waitEvents("device.clock_drift", 1)
	events, err := alice.AuditEvents(ctx, "device.clock_drift")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Target != nil && e.Target.ID == d.DeviceID &&
			(e.Params["offset_s"] != float64(offset) || e.Params["threshold_s"] != float64(60) || e.Outcome != "success") {
			t.Fatalf("device.clock_drift %+v", e)
		}
	}
	if got := drift(login(t, env.Carol)); len(got) != 0 {
		t.Fatalf("carol sees the clock drift of the acme device: %+v", got)
	}

	// A second skewed check-in and one 45 s off (between the clear and the raise threshold) change nothing.
	materialize(-2 * time.Minute)
	materialize(-45 * time.Second)
	time.Sleep(2 * time.Second) // the evaluation follows the heartbeat write; a wrong clear would show by now
	if got := drift(alice); len(got) != 1 {
		t.Fatalf("clock_drift after a check-in 45 s off: %+v, want still open", got)
	}

	// C2: the clock is back.
	materialize(0)
	waitDrift(false)
	waitEvents("device.clock_drift_cleared", 1)
	if n := eventCount(t, alice, "device.clock_drift", d.DeviceID); n != 1 {
		t.Fatalf("%d device.clock_drift for %s after the episode, want 1", n, d.DeviceID)
	}
}
