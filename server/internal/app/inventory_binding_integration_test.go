package app_test

import (
	"context"
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/inventory"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

const (
	bindToken1 = "11111111-1d2f-4a3b-9c4d-5e6f7a8b9c0d"
	bindToken2 = "22222222-1d2f-4a3b-9c4d-5e6f7a8b9c0d"
	bindToken3 = "33333333-1d2f-4a3b-9c4d-5e6f7a8b9c0d"
)

// deviceReports is the use case that records heartbeats, on the worker's organization pool.
func deviceReports(t *testing.T) *app.DeviceReports {
	t.Helper()
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	worker, err := db.NewOrgPool(ctx, env.Worker, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(worker.Close)
	platform, err := db.NewPlatformPool(ctx, env.Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	return app.NewDeviceReports(app.NewActionRunner(worker, platform, httpx.RequestID), worker)
}

// pending returns a device's pending token ("" when none or no row).
func (h inventoryHarness) pending(t *testing.T, dev uuid.UUID) string {
	t.Helper()
	var token *string
	err := h.super.QueryRow(context.Background(), "SELECT pending_token FROM device_fleet_binding WHERE device_id = $1", dev).Scan(&token)
	if err != nil || token == nil {
		return ""
	}
	return *token
}

// TestRecordFleetDeviceToken (ADR 0057, H4): the token is recorded for an active device, a newer one overwrites, an
// older one does not; a retired device gets no row, and another organization's context cannot write one.
func TestRecordFleetDeviceToken(t *testing.T) {
	h := newInventoryHarness(t)
	reports := deviceReports(t)
	org, dev := h.device(t, uuid.Nil, uuid.NewString(), "active")
	_, retired := h.device(t, org, uuid.NewString(), "retired")
	other, _ := h.device(t, uuid.Nil, uuid.NewString(), "active")
	now := time.Now().UTC()
	record := func(ctxOrg, device uuid.UUID, token string, at time.Time) {
		t.Helper()
		hb := ingest.Heartbeat{DeviceID: device, OrganizationID: ctxOrg, ReceivedAt: at, FleetDeviceToken: token}
		if err := reports.RecordFleetReport(systemCtx(ctxOrg), hb); err != nil {
			t.Fatal(err)
		}
	}
	record(org, dev, bindToken1, now.Add(-2*time.Minute))
	if got := h.pending(t, dev); got != bindToken1 {
		t.Fatalf("insert: %q", got)
	}
	record(org, dev, bindToken2, now.Add(-time.Minute))
	record(org, dev, bindToken3, now.Add(-3*time.Minute))
	if got := h.pending(t, dev); got != bindToken2 {
		t.Fatalf("newer then older: %q", got)
	}
	record(org, retired, bindToken1, now)
	record(other, dev, bindToken3, now)
	if n := h.count(t, "SELECT count(*) FROM device_fleet_binding WHERE device_id = $1", retired); n != 0 {
		t.Fatal("a retired device got a row")
	}
	if got := h.pending(t, dev); got != bindToken2 {
		t.Fatalf("another organization wrote the token: %q", got)
	}
}

// TestRecordFleetReportRefusesStaleToken (ADR 0057, H13): a token received TokenMaxAge or longer ago, such as one of a
// heartbeat that waited in the queue, is not stored; the announced reset of the same heartbeat still is.
func TestRecordFleetReportRefusesStaleToken(t *testing.T) {
	h := newInventoryHarness(t)
	reports := deviceReports(t)
	org, dev := h.device(t, uuid.Nil, uuid.NewString(), "active")
	now := time.Now().UTC()
	reset := now.Add(-time.Hour).Truncate(time.Microsecond)
	stale := ingest.Heartbeat{DeviceID: dev, OrganizationID: org, ReceivedAt: now.Add(-inventory.TokenMaxAge),
		FleetDeviceToken: bindToken1, FleetEnrollmentResetAt: &reset}
	if err := reports.RecordFleetReport(systemCtx(org), stale); err != nil {
		t.Fatal(err)
	}
	if got := h.pending(t, dev); got != "" {
		t.Fatalf("a token received %s ago was stored", inventory.TokenMaxAge)
	}
	if n := h.count(t, "SELECT count(*) FROM device_fleet_binding WHERE device_id = $1 AND reset_announced_at = $2", dev, reset); n != 1 {
		t.Fatal("the announced reset was not stored")
	}
	fresh := ingest.Heartbeat{DeviceID: dev, OrganizationID: org, ReceivedAt: now.Add(-inventory.TokenMaxAge + 10*time.Second),
		FleetDeviceToken: bindToken1}
	if err := reports.RecordFleetReport(systemCtx(org), fresh); err != nil {
		t.Fatal(err)
	}
	if got := h.pending(t, dev); got != bindToken1 {
		t.Fatalf("a token just inside the bound: %q", got)
	}
	older := reset.Add(-time.Minute)
	if err := reports.RecordFleetReport(systemCtx(org), ingest.Heartbeat{DeviceID: dev, OrganizationID: org, ReceivedAt: now,
		FleetEnrollmentResetAt: &older}); err != nil {
		t.Fatal(err)
	}
	if n := h.count(t, "SELECT count(*) FROM device_fleet_binding WHERE device_id = $1 AND reset_announced_at = $2", dev, reset); n != 1 {
		t.Fatal("an older announcement overwrote a newer one")
	}
}

// TestBindInventoryHost (ADR 0057, H5): the bind is a compare-and-set on the reported time, in the device's
// organization only; the platform listing returns the binding.
func TestBindInventoryHost(t *testing.T) {
	h := newInventoryHarness(t)
	reports := deviceReports(t)
	hw := uuid.NewString()
	org, dev := h.device(t, uuid.Nil, strings.ToUpper(hw), "active")
	other, _ := h.device(t, uuid.Nil, uuid.NewString(), "active")
	reported := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	if err := reports.RecordFleetReport(systemCtx(org), ingest.Heartbeat{DeviceID: dev, OrganizationID: org, ReceivedAt: reported,
		FleetDeviceToken: bindToken1}); err != nil {
		t.Fatal(err)
	}
	bindings, err := h.sync.InventoryBindings(systemCtx(uuid.Nil))
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(bindings, func(b inventory.Binding) bool { return b.DeviceID == dev })
	if i < 0 || bindings[i].PendingToken != bindToken1 || bindings[i].Host != "" || bindings[i].HardwareUUID != hw ||
		bindings[i].TokenReportedAt == nil || !bindings[i].TokenReportedAt.Equal(reported) || bindings[i].OrganizationID != org {
		t.Fatalf("bindings %+v", bindings)
	}
	if ok, err := h.sync.BindInventoryHost(systemCtx(other), dev, reported, "9", time.Now()); err != nil || ok {
		t.Fatalf("another organization bound: %v %v", ok, err)
	}
	if ok, err := h.sync.BindInventoryHost(systemCtx(org), dev, reported.Add(-time.Second), "9", time.Now()); err != nil || ok {
		t.Fatalf("a token reported meanwhile was overwritten: %v %v", ok, err)
	}
	if ok, err := h.sync.BindInventoryHost(systemCtx(org), dev, reported, "9", time.Now()); err != nil || !ok {
		t.Fatalf("bind: %v %v", ok, err)
	}
	if n := h.count(t, "SELECT count(*) FROM device_fleet_binding WHERE device_id = $1 AND host_id = '9' AND pending_token IS NULL", dev); n != 1 {
		t.Fatal("not bound")
	}
	if err := reports.RecordFleetReport(systemCtx(org), ingest.Heartbeat{DeviceID: dev, OrganizationID: org, ReceivedAt: reported.Add(time.Second),
		FleetDeviceToken: bindToken2}); err != nil {
		t.Fatal(err)
	}
	if err := h.sync.ClearFleetDeviceToken(systemCtx(other), dev, reported.Add(time.Second)); err != nil || h.pending(t, dev) != bindToken2 {
		t.Fatalf("another organization cleared the token: %v", err)
	}
	if err := h.sync.ClearFleetDeviceToken(systemCtx(org), dev, reported); err != nil || h.pending(t, dev) != bindToken2 {
		t.Fatalf("a newer token was cleared: %v", err)
	}
	if err := h.sync.ClearFleetDeviceToken(systemCtx(org), dev, reported.Add(time.Second)); err != nil || h.pending(t, dev) != "" {
		t.Fatalf("clear: %v", err)
	}
}

// TestExpireFleetDeviceTokens (ADR 0057, H13): tokens reported before the bound go, in every device state.
func TestExpireFleetDeviceTokens(t *testing.T) {
	h := newInventoryHarness(t)
	org, old := h.device(t, uuid.Nil, uuid.NewString(), "active")
	_, retired := h.device(t, org, uuid.NewString(), "active")
	_, recent := h.device(t, org, uuid.NewString(), "active")
	now := time.Now().UTC()
	for dev, at := range map[uuid.UUID]time.Time{old: now.Add(-51 * time.Minute), retired: now.Add(-51 * time.Minute), recent: now.Add(-49 * time.Minute)} {
		if _, err := h.super.Exec(context.Background(), `INSERT INTO device_fleet_binding (device_id, organization_id, pending_token,
			token_reported_at) VALUES ($1, $2, $3, $4)`, dev, org, bindToken1, at); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.super.Exec(context.Background(), "UPDATE device SET state = 'retired' WHERE id = $1", retired); err != nil {
		t.Fatal(err)
	}
	if _, err := h.sync.ExpireFleetDeviceTokens(systemCtx(uuid.Nil), now.Add(-inventory.TokenMaxAge)); err != nil {
		t.Fatal(err)
	}
	if h.pending(t, old) != "" || h.pending(t, retired) != "" || h.pending(t, recent) != bindToken1 {
		t.Fatalf("pending: old %q retired %q recent %q", h.pending(t, old), h.pending(t, retired), h.pending(t, recent))
	}
}

// TestInventoryDevicesCountsBoundDevices (review round 1, F3, regression): a bound device still makes its hardware
// UUID ambiguous, so another device with that UUID maps to no host.
func TestInventoryDevicesCountsBoundDevices(t *testing.T) {
	h := newInventoryHarness(t)
	hw := uuid.NewString()
	org, a := h.device(t, uuid.Nil, hw, "active")
	h.device(t, org, hw, "active")
	if _, err := h.super.Exec(context.Background(), "INSERT INTO device_fleet_binding (device_id, organization_id, host_id) VALUES ($1, $2, '9')", a, org); err != nil {
		t.Fatal(err)
	}
	if got, err := h.sync.MapHosts(systemCtx(uuid.Nil), []string{hw}); err != nil || len(got) != 0 {
		t.Fatalf("a UUID of a bound and an unbound device: %v %v", got, err)
	}
}

// claimEvents returns the params of the device's claim events.
func (h inventoryHarness) claimEvents(t *testing.T, dev uuid.UUID) []map[string]any {
	t.Helper()
	rows, err := h.super.Query(context.Background(), `SELECT params FROM action WHERE code = 'device.tamper_fleet_host_claimed'
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

// TestApplyClaimWatch (ADR 0057, H7 and H10): the transitions apply in the device's organization only; a claim is
// recorded once per episode with its seven params and a tamper finding.
func TestApplyClaimWatch(t *testing.T) {
	h := newInventoryHarness(t)
	org, dev := h.device(t, uuid.Nil, uuid.NewString(), "active")
	_, cleared := h.device(t, org, uuid.NewString(), "active")
	other, foreign := h.device(t, uuid.Nil, uuid.NewString(), "active")
	for _, d := range [][2]uuid.UUID{{org, dev}, {org, cleared}, {other, foreign}} {
		if err := h.sync.StoreHost(systemCtx(d[0]), d[1], "9", ports.HostInventory{}); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := h.super.Exec(context.Background(), "UPDATE device_inventory_ref SET fleet_claim_since = $2, fleet_claim_reported_at = $2 WHERE device_id = $1",
		cleared, now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	enrolled := now.Add(-time.Minute)
	others := []ports.HostRef{"10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21"}
	claim := inventory.ClaimedDevice{ClaimDevice: inventory.ClaimDevice{DeviceID: dev, OrganizationID: org},
		Kind: inventory.ClaimSecondHost, Binding: inventory.BindingDevice, Bound: "9", Others: others, Hosts: 13,
		SpeakingEnrolledAt: &enrolled, Since: now.Add(-16 * time.Minute)}
	w := inventory.ClaimWatch{Enrolled: map[uuid.UUID]*time.Time{dev: &enrolled}, Reenrolled: []uuid.UUID{dev, foreign},
		ClaimStart: []uuid.UUID{dev, foreign}, ClaimClear: []uuid.UUID{cleared}, Claims: []inventory.ClaimedDevice{claim}}
	for range 2 {
		if _, err := h.sync.ApplyClaimWatch(systemCtx(org), w, now); err != nil {
			t.Fatal(err)
		}
	}
	events := h.claimEvents(t, dev)
	want := map[string]any{"kind": "second_host", "binding": "device", "bound_host": "9", "other_hosts": "10,11,12,13,14,15,16,17,18,19",
		"hosts": float64(13), "enrolled_at": audit.Timestamp(enrolled).Format(time.RFC3339Nano),
		"claim_since": audit.Timestamp(claim.Since).Format(time.RFC3339Nano)}
	if len(events) != 1 || !maps.Equal(events[0], want) {
		t.Fatalf("events %v, want one %v", events, want)
	}
	if n := h.count(t, `SELECT count(*) FROM finding WHERE device_id = $1 AND kind = 'tamper' AND code = 'device.tamper_fleet_host_claimed'
		AND subject = '' AND closed_at IS NULL`, dev); n != 1 {
		t.Fatalf("%d open tamper findings", n)
	}
	if n := h.count(t, `SELECT count(*) FROM device_inventory_ref WHERE device_id = $1 AND fleet_enrolled_at = $2 AND fleet_reenrolled_at = $3
		AND fleet_claim_since = $3 AND fleet_claim_reported_at = $3`, dev, enrolled, now); n != 1 {
		t.Fatal("transitions of the device not applied")
	}
	if n := h.count(t, "SELECT count(*) FROM device_inventory_ref WHERE device_id = $1 AND fleet_claim_since IS NULL AND fleet_claim_reported_at IS NULL", cleared); n != 1 {
		t.Fatal("the ended episode was not cleared")
	}
	if n := h.count(t, "SELECT count(*) FROM device_inventory_ref WHERE device_id = $1 AND fleet_reenrolled_at IS NULL AND fleet_claim_since IS NULL", foreign); n != 1 {
		t.Fatal("another organization's device was changed")
	}
	if n := h.count(t, "SELECT count(*) FROM action WHERE code = 'device.tamper_fleet_host_claimed' AND organization_id = $1", other); n != 0 {
		t.Fatal("another organization got an event")
	}

	devices, err := h.sync.InventoryClaimDevices(systemCtx(uuid.Nil))
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(devices, func(d inventory.ClaimDevice) bool { return d.DeviceID == dev })
	if i < 0 || devices[i].ExternalID != "9" || devices[i].BoundHost != "" || devices[i].ResetAnnouncedAt != nil ||
		devices[i].ClaimSince == nil || !devices[i].ClaimSince.Equal(now) || devices[i].EnrolledAt == nil {
		t.Fatalf("claim devices %+v", devices)
	}
}

// TestReportAgentNotRunningHeldAfterReenroll (ADR 0057, H8): a device whose inventory host was enrolled again within
// ClaimQuiet is not reported by the inventory-derived agent reports; afterwards it is.
func TestReportAgentNotRunningHeldAfterReenroll(t *testing.T) {
	h := newInventoryHarness(t)
	ctx := context.Background()
	org, dev := h.device(t, uuid.Nil, uuid.NewString(), "active")
	now := time.Now().UTC()
	evaluated := now.Add(-time.Hour)
	inv := ports.HostInventory{PolicyUpdatedAt: &evaluated, Policies: []ports.PolicyResult{{Key: inventory.PolicyAgentRunning},
		{Key: inventory.PolicyAgentBinaryKnown}}}
	if err := h.sync.StoreHost(systemCtx(org), dev, "1", inv); err != nil {
		t.Fatal(err)
	}
	reenrolled := func(at time.Time) {
		if _, err := h.super.Exec(ctx, "UPDATE device_inventory_ref SET fleet_reenrolled_at = $2 WHERE device_id = $1", dev, at); err != nil {
			t.Fatal(err)
		}
	}
	reenrolled(now.Add(-10 * time.Minute))
	if got, err := h.sync.ReportAgentNotRunning(systemCtx(org), now); err != nil || len(got) != 0 {
		t.Fatalf("agent not running during the hold: %v %v", got, err)
	}
	if got, err := h.sync.ReportAgentBinaryUnknown(systemCtx(org), now, evaluated.Add(-time.Minute), 1); err != nil || len(got) != 0 {
		t.Fatalf("agent binary during the hold: %v %v", got, err)
	}
	reenrolled(now.Add(-61 * time.Minute))
	if got, err := h.sync.ReportAgentNotRunning(systemCtx(org), now); err != nil || !slices.Equal(got, []uuid.UUID{dev}) {
		t.Fatalf("agent not running after the hold: %v %v", got, err)
	}
	if got, err := h.sync.ReportAgentBinaryUnknown(systemCtx(org), now, evaluated.Add(-time.Minute), 1); err != nil || !slices.Equal(got, []uuid.UUID{dev}) {
		t.Fatalf("agent binary after the hold: %v %v", got, err)
	}
}

// TestMapHostsRetiredHolder (review round 4): a retired device keeps its hardware UUID until retention purged its
// inventory or it was retired as uninstalled, in any organization; a retired device alone maps to nothing.
func TestMapHostsRetiredHolder(t *testing.T) {
	h := newInventoryHarness(t)
	ctx := context.Background()
	hw := uuid.NewString()
	org, active := h.device(t, uuid.Nil, hw, "active")
	otherOrg, retired := h.device(t, uuid.Nil, hw, "retired")
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := h.super.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	maps := func(want uuid.UUID, step string) {
		t.Helper()
		got, err := h.sync.MapHosts(systemCtx(uuid.Nil), []string{hw})
		if err != nil || got[hw].DeviceID != want {
			t.Fatalf("%s: mapped %v (%v), want %s", step, got, err, want)
		}
	}
	maps(active, "retired without a stored host")
	exec("INSERT INTO device_inventory_ref (device_id, organization_id, external_id) VALUES ($1, $2, '9')", retired, otherOrg)
	maps(uuid.Nil, "retired holder in another organization")
	exec("INSERT INTO retention_inventory_hold (device_id, organization_id, last_answer, retired_at) VALUES ($1, $2, 'hardware', now())", retired, otherOrg)
	maps(active, "inventory purged with a hold")
	exec("DELETE FROM retention_inventory_hold WHERE device_id = $1", retired)
	exec("UPDATE device SET uninstalled_at = now() WHERE id = $1", retired)
	maps(active, "retired as uninstalled")
	exec("UPDATE device SET uninstalled_at = NULL WHERE id = $1", retired)
	exec("DELETE FROM device_inventory_ref WHERE device_id = $1", retired)
	maps(active, "reference deleted")
	exec("INSERT INTO device_inventory_ref (device_id, organization_id, external_id) VALUES ($1, $2, '9')", retired, otherOrg)
	exec("UPDATE device SET state = 'retired' WHERE id = $1", active)
	maps(uuid.Nil, "retired devices alone")
	if org == otherOrg {
		t.Fatal("the holder must be in another organization")
	}
}
