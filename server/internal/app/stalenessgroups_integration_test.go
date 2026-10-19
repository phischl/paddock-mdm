package app_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

// group inserts a device group with a staleness override (0, 0 = none) and adds the devices.
func (h stalenessHarness) group(t *testing.T, warningH, criticalH int, devices ...uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	var w, c any
	if warningH > 0 {
		w, c = warningH, criticalH
	}
	h.exec(t, `INSERT INTO device_group (id, organization_id, name, staleness_warning_h, staleness_critical_h)
		VALUES ($1, $2, $3, $4, $5)`, id, h.org, "g-"+id.String()[24:], w, c)
	for _, d := range devices {
		h.exec(t, "INSERT INTO device_group_member (organization_id, device_group_id, device_id) VALUES ($1, $2, $3)", h.org, id, d)
	}
	return id
}

// staleParams returns the params of the device's last staleness event.
func (h stalenessHarness) staleParams(t *testing.T, device uuid.UUID) map[string]any {
	t.Helper()
	var raw []byte
	if err := h.super.QueryRow(context.Background(), `SELECT payload -> 'params' FROM outbox
		WHERE payload -> 'target' ->> 'id' = $1 AND payload ->> 'code' LIKE 'device.stale%' ORDER BY id DESC LIMIT 1`,
		device.String()).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestStalenessGroupThresholds (plan M8d decision 12): a device in a group with its own thresholds is warned by them
// and the event names the source; a device without one follows the organization; the most lenient group wins, and a
// more lenient group added later clears the warning at the next round.
func TestStalenessGroupThresholds(t *testing.T) {
	h := newStalenessHarness(t)
	h.exec(t, "INSERT INTO organization_update_settings (organization_id, staleness_warning_h, staleness_critical_h) VALUES ($1, 24, 168)", h.org)
	start := time.Now().UTC().Truncate(time.Second)
	grouped := h.device(t, "active", start)
	plain := h.device(t, "active", start)
	h.group(t, 2, 4, grouped)
	h.group(t, 0, 0, plain) // a group without an override changes nothing
	ctx := systemCtx(h.org)
	round := func(at time.Time) {
		t.Helper()
		if err := h.staleness.Evaluate(ctx, at); err != nil {
			t.Fatal(err)
		}
	}
	round(start.Add(3 * time.Minute))
	if k, _ := h.open(t, grouped); k != "stale_warning" {
		t.Fatalf("grouped device after 3 minutes: %q", k)
	}
	if k, _ := h.open(t, plain); k != "" {
		t.Fatalf("plain device after 3 minutes: %q", k)
	}
	if p := h.staleParams(t, grouped); p["threshold_h"] != float64(2) || p["source"] != "device_group" {
		t.Fatalf("warning params %v", p)
	}

	h.group(t, 10, 20, grouped)
	round(start.Add(4 * time.Minute))
	if k, lost := h.open(t, grouped); k != "" || lost {
		t.Fatalf("after a more lenient group: %q %v", k, lost)
	}
	if got := h.codes(t, grouped); len(got) != 2 || got[1] != "device.stale_cleared" {
		t.Fatalf("events %v", got)
	}
	round(start.Add(11 * time.Minute))
	if k, _ := h.open(t, grouped); k != "stale_warning" {
		t.Fatalf("after 11 minutes: %q", k)
	}
	if p := h.staleParams(t, grouped); p["threshold_h"] != float64(10) || p["source"] != "device_group" {
		t.Fatalf("second warning params %v", p)
	}

	round(start.Add(25 * time.Minute))
	if k, _ := h.open(t, plain); k != "stale_warning" {
		t.Fatalf("plain device after 25 minutes: %q", k)
	}
	if p := h.staleParams(t, plain); p["threshold_h"] != float64(24) || p["source"] != "organization" {
		t.Fatalf("organization params %v", p)
	}
}
