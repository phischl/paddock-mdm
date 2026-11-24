package app_test

import (
	"context"
	"encoding/json"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/inventory"
	"github.com/phischl/paddock-mdm/server/internal/ports"
)

// silentEvents returns the params of the device's device.tamper_fleetd_silent events.
func (h inventoryHarness) silentEvents(t *testing.T, dev uuid.UUID) []map[string]any {
	t.Helper()
	rows, err := h.super.Query(context.Background(), `SELECT params FROM action WHERE code = 'device.tamper_fleetd_silent'
		AND target ->> 'id' = $1`, dev.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var raw []byte
		var p map[string]any
		if err := rows.Scan(&raw); err != nil || json.Unmarshal(raw, &p) != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
	return out
}

// TestApplyFleetWatch (plan M5a amendment 2026-11-16 c, section 8, and 2026-11-24 f, F-8): Start keeps an existing
// start, Note takes the device's last contact and keeps a noted one, Reset clears start and check-in but keeps the report
// mark, Clear clears all three; a report records exactly one event with its params and a tamper finding, and applying
// it again records nothing; a device of another organization is neither changed nor reported in this organization's
// call, and its own call reports it there.
func TestApplyFleetWatch(t *testing.T) {
	h := newInventoryHarness(t)
	org, dev := h.device(t, uuid.Nil, uuid.NewString(), "active")
	_, started := h.device(t, org, uuid.NewString(), "active")
	_, reset := h.device(t, org, uuid.NewString(), "active")
	_, cleared := h.device(t, org, uuid.NewString(), "active")
	_, noted := h.device(t, org, uuid.NewString(), "active")
	_, kept := h.device(t, org, uuid.NewString(), "active")
	other, foreign := h.device(t, uuid.Nil, uuid.NewString(), "active")
	for _, d := range [][2]uuid.UUID{{org, dev}, {org, started}, {org, reset}, {org, cleared}, {org, noted}, {org, kept}, {other, foreign}} {
		if err := h.sync.StoreHost(systemCtx(d[0]), d[1], "9", ports.HostInventory{}); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	earlier := now.Add(-2 * time.Hour)
	for _, d := range []uuid.UUID{started, reset, cleared, kept} {
		if _, err := h.super.Exec(context.Background(), `UPDATE device_inventory_ref SET fleet_silent_since = $2, fleet_silent_checkin_at = $2,
			fleet_silent_reported_at = $2 WHERE device_id = $1`, d, earlier); err != nil {
			t.Fatal(err)
		}
	}
	contactAt := now.Add(-3 * time.Minute)
	for _, d := range []uuid.UUID{noted, kept, foreign} {
		if _, err := h.super.Exec(context.Background(), `INSERT INTO device_status (device_id, organization_id, last_contact_at)
			SELECT id, organization_id, $2 FROM device WHERE id = $1`, d, contactAt); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.super.Exec(context.Background(), "UPDATE device_inventory_ref SET fleet_silent_since = $2 WHERE device_id = ANY($1::uuid[])",
		[]uuid.UUID{noted, foreign}, earlier); err != nil {
		t.Fatal(err)
	}
	seen, policy, contact, since := now.Add(-20*time.Minute), now.Add(-25*time.Minute), now.Add(-time.Minute), now.Add(-16*time.Minute)
	report := func(d, o uuid.UUID) inventory.SilentDevice {
		return inventory.SilentDevice{WatchedDevice: inventory.WatchedDevice{DeviceID: d, OrganizationID: o, LastContactAt: &contact,
			SilentSince: &since}, FleetdSeenAt: &seen, FleetdPolicyUpdatedAt: &policy, Reason: inventory.SilentContact}
	}
	w := inventory.FleetWatch{Start: []uuid.UUID{dev, started, foreign}, Note: []uuid.UUID{noted, kept, foreign},
		Reset: []uuid.UUID{reset}, Clear: []uuid.UUID{cleared},
		Report: []inventory.SilentDevice{report(dev, org), report(foreign, other)}}
	for range 2 {
		ids, err := h.sync.ApplyFleetWatch(systemCtx(org), w, now)
		if err != nil {
			t.Fatal(err)
		}
		if len(ids) > 1 || len(ids) == 1 && ids[0] != dev {
			t.Fatalf("reported %v", ids)
		}
	}
	stamp := func(at time.Time) string { return audit.Timestamp(at).Format(time.RFC3339Nano) }
	want := map[string]any{"fleetd_seen_at": stamp(seen), "policy_updated_at": stamp(policy), "last_contact_at": stamp(contact),
		"silent_since": stamp(since), "reason": "contact"}
	if events := h.silentEvents(t, dev); len(events) != 1 || !maps.Equal(events[0], want) {
		t.Fatalf("events %v, want one %v", events, want)
	}
	if n := h.count(t, `SELECT count(*) FROM finding WHERE device_id = $1 AND kind = 'tamper' AND code = 'device.tamper_fleetd_silent'
		AND subject = '' AND closed_at IS NULL`, dev); n != 1 {
		t.Fatalf("%d open tamper findings", n)
	}
	checks := []struct {
		name  string
		query string
		args  []any
	}{
		{"start and mark", "fleet_silent_since = $2 AND fleet_silent_reported_at = $2", []any{dev, now}},
		{"start keeps an existing start", "fleet_silent_since = $2 AND fleet_silent_reported_at = $2", []any{started, earlier}},
		{"reset keeps the mark", "fleet_silent_since IS NULL AND fleet_silent_checkin_at IS NULL AND fleet_silent_reported_at = $2", []any{reset, earlier}},
		{"clear", "fleet_silent_since IS NULL AND fleet_silent_checkin_at IS NULL AND fleet_silent_reported_at IS NULL", []any{cleared}},
		{"note takes the last contact", "fleet_silent_checkin_at = $2", []any{noted, contactAt}},
		{"note keeps a noted check-in", "fleet_silent_checkin_at = $2", []any{kept, earlier}},
		{"another organization's device untouched", "fleet_silent_since = $2 AND fleet_silent_checkin_at IS NULL AND fleet_silent_reported_at IS NULL", []any{foreign, earlier}},
	}
	for _, c := range checks {
		if n := h.count(t, "SELECT count(*) FROM device_inventory_ref WHERE device_id = $1 AND "+c.query, c.args...); n != 1 {
			t.Errorf("%s: not as expected", c.name)
		}
	}
	if len(h.silentEvents(t, foreign)) != 0 {
		t.Fatal("another organization's device was reported in this organization's call")
	}
	ids, err := h.sync.ApplyFleetWatch(systemCtx(other), w, now)
	if err != nil || !slices.Equal(ids, []uuid.UUID{foreign}) {
		t.Fatalf("own call: %v %v", ids, err)
	}
	if n := h.count(t, "SELECT count(*) FROM action WHERE code = 'device.tamper_fleetd_silent' AND target ->> 'id' = $1 AND organization_id = $2",
		foreign.String(), other); n != 1 {
		t.Fatalf("the foreign device has %d events in its organization", n)
	}
}

// TestFleetWatchDevices (plan M5a amendment 2026-11-16 c, section 8, and 2026-11-24 f): active devices with a
// reference of two organizations are returned with their values, a device without a binding row with nil binding times; a retired device and a device without a reference are absent.
func TestFleetWatchDevices(t *testing.T) {
	h := newInventoryHarness(t)
	hw := uuid.NewString()
	org, dev := h.device(t, uuid.Nil, hw, "active")
	_, retired := h.device(t, org, uuid.NewString(), "retired")
	_, noRef := h.device(t, org, uuid.NewString(), "active")
	other, foreign := h.device(t, uuid.Nil, uuid.NewString(), "active")
	evaluated := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	for _, d := range [][2]uuid.UUID{{org, dev}, {org, retired}, {other, foreign}} {
		if err := h.sync.StoreHost(systemCtx(d[0]), d[1], "9", ports.HostInventory{PolicyUpdatedAt: &evaluated}); err != nil {
			t.Fatal(err)
		}
	}
	contact := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := h.super.Exec(context.Background(), "INSERT INTO device_status (device_id, organization_id, last_contact_at) VALUES ($1, $2, $3)",
		dev, org, contact); err != nil {
		t.Fatal(err)
	}
	if _, err := h.super.Exec(context.Background(), `INSERT INTO device_fleet_binding (device_id, organization_id, host_id, reset_announced_at,
		bound_at, suspended_at) VALUES ($1, $2, '9', $3, $3, $3)`, dev, org, evaluated); err != nil {
		t.Fatal(err)
	}
	if _, err := h.super.Exec(context.Background(), `UPDATE device_inventory_ref SET fleet_silent_checkin_at = $2, fleet_reenrolled_at = $2
		WHERE device_id = $1`, dev, evaluated); err != nil {
		t.Fatal(err)
	}
	devices, err := h.sync.FleetWatchDevices(systemCtx(uuid.Nil))
	if err != nil {
		t.Fatal(err)
	}
	find := func(id uuid.UUID) *inventory.WatchedDevice {
		i := slices.IndexFunc(devices, func(d inventory.WatchedDevice) bool { return d.DeviceID == id })
		if i < 0 {
			return nil
		}
		return &devices[i]
	}
	d := find(dev)
	if d == nil || d.OrganizationID != org || d.HardwareUUID != hw || d.ExternalID != "9" || d.BoundHost != "9" ||
		d.LastContactAt == nil || !d.LastContactAt.Equal(contact) || d.PolicyUpdatedAt == nil || !d.PolicyUpdatedAt.Equal(evaluated) ||
		d.SilentSince != nil || d.ReportedAt != nil {
		t.Fatalf("device %+v", d)
	}
	for name, at := range map[string]*time.Time{"checkin": d.CheckinAt, "reset": d.ResetAnnouncedAt, "bound": d.BoundAt,
		"suspended": d.SuspendedAt, "reenrolled": d.ReenrolledAt} {
		if at == nil || !at.Equal(evaluated) {
			t.Errorf("%s %v, want %v", name, at, evaluated)
		}
	}
	if f := find(foreign); f == nil || f.OrganizationID != other || f.BoundHost != "" || f.LastContactAt != nil ||
		f.CheckinAt != nil || f.ResetAnnouncedAt != nil || f.BoundAt != nil || f.SuspendedAt != nil || f.ReenrolledAt != nil {
		t.Fatalf("other organization's device %+v", f)
	}
	if find(retired) != nil || find(noRef) != nil {
		t.Fatal("a retired device or a device without a reference is watched")
	}
}
