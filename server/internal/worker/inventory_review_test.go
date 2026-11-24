package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/inventory"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/ports"
)

// drop removes a host from the inventory system's list.
func (r *bindRig) drop(ref ports.HostRef) {
	for n, h := range r.src.hosts {
		if h.Ref == ref {
			r.src.hosts = append(r.src.hosts[:n], r.src.hosts[n+1:]...)
			return
		}
	}
}

// relabel makes a listed host report another hardware UUID.
func (r *bindRig) relabel(ref ports.HostRef, hw string) {
	for n, h := range r.src.hosts {
		if h.Ref == ref {
			r.src.hosts[n].HardwareUUID = hw
		}
	}
}

func (r *bindRig) synced(t *testing.T, dev uuid.UUID) string {
	return r.value(t, "SELECT synced_at::text FROM device_inventory_ref WHERE device_id = $1", dev)
}

func (r *bindRig) suspended(t *testing.T, dev uuid.UUID) bool {
	return r.value(t, "SELECT (suspended_at IS NOT NULL)::text FROM device_fleet_binding WHERE device_id = $1", dev) == "true"
}

// bindNow binds a device to a listed host through a reported token and one round.
func (r *bindRig) bindNow(t *testing.T, dev uuid.UUID, host ports.HostRef, hw string) {
	t.Helper()
	token := uuid.NewString()
	r.binder.hosts[token] = ports.HostSeen{Ref: host, HardwareUUID: hw}
	r.report(t, dev, token, r.clock.Add(-time.Second))
	r.round(t)
	if got := r.boundHost(t, dev); got != host {
		t.Fatalf("bound to %q, want %q", got, host)
	}
}

// clearForeignTokens clears the pending tokens other tests left in the shared database, so that this test's resolution
// budget counts only its own.
func (r *bindRig) clearForeignTokens(t *testing.T) {
	t.Helper()
	if _, err := r.f.super.Exec(context.Background(), "UPDATE device_fleet_binding SET pending_token = NULL WHERE organization_id <> $1", r.f.org); err != nil {
		t.Fatal(err)
	}
}

// TestInventoryRoundBoundHostListedWithOtherUUID (review round 1, F1, regression): a bound host that the inventory
// system lists with another hardware UUID is stored for nobody; the device's pending token is resolved and the binding
// suspended without a claim; the device's next host rebinds it and ends the suspension.
func TestInventoryRoundBoundHostListedWithOtherUUID(t *testing.T) {
	r := newBindRig(t)
	hwV, hwW := uuid.NewString(), uuid.NewString()
	v := r.device(t, hwV)
	r.device(t, hwW)
	r.host(r.id(100), hwV, true)
	r.bindNow(t, v, r.id(100), hwV)
	r.advance(5*time.Minute, r.id(100))
	r.round(t)
	before := r.synced(t, v)

	r.relabel(r.id(100), hwW)
	r.answer(r.id(100), false)
	r.binder.hosts[tokenB] = ports.HostSeen{Ref: r.id(100), HardwareUUID: hwW}
	r.report(t, v, tokenB, r.clock)
	calls := r.binder.calls
	r.advance(5*time.Minute, r.id(100))
	r.round(t)
	if r.binder.calls != calls+1 {
		t.Errorf("the pending token was not resolved (%d calls)", r.binder.calls-calls)
	}
	if got := r.synced(t, v); got != before {
		t.Errorf("V stored host %s again although it reports another hardware UUID", r.externalID(t, v))
	}
	if !r.suspended(t, v) {
		t.Error("V's binding is not suspended")
	}
	if n := r.events(t, agentBinaryCode, v) + r.events(t, claimCode, v); n != 0 {
		t.Errorf("%d events for V", n)
	}

	r.host(r.id(101), hwV, true)
	r.bindNow(t, v, r.id(101), hwV)
	if r.suspended(t, v) || r.externalID(t, v) != r.id(101) {
		t.Fatalf("after the rebind: suspended %v, stored %s", r.suspended(t, v), r.externalID(t, v))
	}
}

// TestInventoryRoundSuspendedBindingNoSecondHostFor60Min (review round 1, F1, regression): while a bound host is not
// listed, a new host with the device's hardware UUID raises no second_host claim.
func TestInventoryRoundSuspendedBindingNoSecondHostFor60Min(t *testing.T) {
	r := newBindRig(t)
	hw := uuid.NewString()
	v := r.device(t, hw)
	r.host(r.id(100), hw, true)
	r.bindNow(t, v, r.id(100), hw)
	r.round(t)
	r.drop(r.id(100))
	r.host(r.id(102), hw, true)
	for range 7 {
		r.advance(5*time.Minute, r.id(102))
		r.round(t)
	}
	if n := r.events(t, claimCode, v); n != 0 || !r.suspended(t, v) {
		t.Fatalf("%d claims within 35 minutes of the suspension, suspended %v", n, r.suspended(t, v))
	}
}

// TestInventoryRoundOlderHostDoesNotReplaceStoredHost (review round 1, F2, regression): a host with a lower ID that
// starts reporting an unbound device's hardware UUID does not replace the host stored for it, and is reported.
func TestInventoryRoundOlderHostDoesNotReplaceStoredHost(t *testing.T) {
	r := newBindRig(t)
	hw := uuid.NewString()
	v := r.device(t, hw)
	r.host(r.id(20), hw, true)
	r.round(t)
	r.host(r.id(10), hw, false)
	for range 3 {
		r.advance(5*time.Minute, r.id(10), r.id(20))
		r.round(t)
		if got := r.externalID(t, v); got != r.id(20) {
			t.Fatalf("V stores %s, want its stored host %s", got, r.id(20))
		}
	}
	if n := r.events(t, agentBinaryCode, v); n != 0 {
		t.Fatalf("%d agent binary events from the other host", n)
	}
	r.seedClaimSince(t, v, inventory.HostClaimConfirm)
	r.round(t)
	if r.events(t, claimCode, v) != 1 || r.claimParam(t, v, "kind") != "second_host" || r.claimParam(t, v, "bound_host") != string(r.id(20)) {
		t.Fatalf("claims %d, kind %q, bound %q", r.events(t, claimCode, v), r.claimParam(t, v, "kind"), r.claimParam(t, v, "bound_host"))
	}
}

// TestInventoryRoundFirstSpeakerReplacedIsReenrolled (review round 1, F2, regression): when an unbound device's stored
// host disappears and another host takes its place, it is reported at once as reenrolled and the agent reports wait.
func TestInventoryRoundFirstSpeakerReplacedIsReenrolled(t *testing.T) {
	r := newBindRig(t)
	hw := uuid.NewString()
	v := r.device(t, hw)
	r.host(r.id(20), hw, true)
	r.round(t)
	r.drop(r.id(20))
	r.host(r.id(10), hw, false)
	r.advance(5*time.Minute, r.id(10))
	r.round(t)
	if r.events(t, claimCode, v) != 1 || r.claimParam(t, v, "kind") != "reenrolled" || r.claimParam(t, v, "binding") != "first" {
		t.Fatalf("claims %d, kind %q", r.events(t, claimCode, v), r.claimParam(t, v, "kind"))
	}
	r.advance(5*time.Minute, r.id(10))
	r.round(t)
	if n := r.events(t, agentBinaryCode, v); n != 0 {
		t.Fatalf("%d agent binary events during the hold", n)
	}
	r.advance(inventory.ClaimQuiet, r.id(10))
	r.round(t)
	if n := r.events(t, agentBinaryCode, v); n != 1 {
		t.Fatalf("%d agent binary events after the hold, want 1", n)
	}
}

// TestInventoryRoundDuplicateOfBoundDeviceGetsNothing (review round 1, F3, regression): an unbound device with a
// bound device's hardware UUID gets no host; the bound device keeps its host.
func TestInventoryRoundDuplicateOfBoundDeviceGetsNothing(t *testing.T) {
	r := newBindRig(t)
	hw := uuid.NewString()
	v := r.device(t, hw)
	r.host(r.id(7), hw, true)
	r.host(r.id(9), hw, true)
	r.bindNow(t, v, r.id(9), hw)
	r.src.seenAt[r.id(7)] = r.clock.Add(-time.Hour)
	x := r.device(t, hw)
	for range 2 {
		r.advance(5*time.Minute, r.id(9))
		r.round(t)
	}
	if got := r.externalID(t, x); got != "" {
		t.Fatalf("X stores %s", got)
	}
	if got := r.externalID(t, v); got != r.id(9) {
		t.Fatalf("V stores %s", got)
	}
}

// TestInventoryRoundRefusesHostInUse (review round 1, R1, regression; §164): a token that resolves to the host a device
// of another organization uses binds nothing; neither the log nor the metric labels name that device or organization.
func TestInventoryRoundRefusesHostInUse(t *testing.T) {
	logs := captureLogs(t)
	r := newBindRig(t)
	ctx := context.Background()
	hw := uuid.NewString()
	otherOrg, y := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	if _, err := r.f.super.Exec(ctx, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'O', 'active')", otherOrg,
		"o"+otherOrg.String()[24:]); err != nil {
		t.Fatal(err)
	}
	if _, err := r.f.super.Exec(ctx, "INSERT INTO device (id, organization_id, hostname, state, hardware_uuid) VALUES ($1, $2, 'lt-y', 'active', $3)",
		y, otherOrg, hw); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = r.f.super.Exec(ctx, "UPDATE device SET state = 'retired' WHERE id = $1", y) })
	r.host(r.id(30), hw, true)
	r.round(t)
	if r.externalID(t, y) != r.id(30) {
		t.Fatal("Y does not store its host")
	}
	before := testutil.ToFloat64(metricHostBindings.WithLabelValues("host_in_use"))
	x := r.device(t, hw)
	r.binder.hosts[tokenC] = ports.HostSeen{Ref: r.id(30), HardwareUUID: hw}
	r.report(t, x, tokenC, r.clock)
	r.advance(5*time.Minute, r.id(30))
	r.round(t)
	if got := r.boundHost(t, x); got != "" {
		t.Fatalf("X bound to %s", got)
	}
	if got := r.externalID(t, x); got != "" {
		t.Fatalf("X stores %s", got)
	}
	if r.externalID(t, y) != r.id(30) || r.boundHost(t, y) != "" {
		t.Fatalf("Y changed: stored %s, bound %s", r.externalID(t, y), r.boundHost(t, y))
	}
	if got := testutil.ToFloat64(metricHostBindings.WithLabelValues("host_in_use")) - before; got != 1 {
		t.Fatalf("host_in_use +%v", got)
	}
	var line string
	for _, l := range strings.Split(logs.String(), "\n") {
		if strings.Contains(l, "host_in_use") {
			line = l
		}
	}
	if !strings.Contains(line, x.String()) || !strings.Contains(line, r.f.org.String()) {
		t.Fatalf("the refusal does not name the requesting device: %s", line)
	}
	reg := prometheus.NewRegistry()
	if err := reg.Register(metricHostBindings); err != nil {
		t.Fatal(err)
	}
	families, err := reg.Gather()
	if err != nil || len(families) == 0 {
		t.Fatalf("binding counter not gathered: %v", err)
	}
	series := fmt.Sprint(families)
	for _, id := range []string{y.String(), otherOrg.String()} {
		if strings.Contains(logs.String(), id) {
			t.Errorf("the logs name the other organization's %s", id)
		}
		if strings.Contains(series, id) {
			t.Errorf("a metric label names the other organization's %s", id)
		}
	}
}

// TestInventoryRoundFleetRestoreBoundDevices (review round 1, F4): most bound devices re-enrolled under their IDs and
// two hosts re-created under new IDs raise no claim; the re-enrolled devices' agent reports are held, the two bindings
// are suspended until their devices name the new hosts.
func TestInventoryRoundFleetRestoreBoundDevices(t *testing.T) {
	r := newBindRig(t)
	// The guard counts every bound watched device of the shared database: re-enroll more than all others together.
	others := r.f.count(t, `SELECT count(*) FROM device d JOIN device_inventory_ref i ON i.device_id = d.id
		JOIN device_fleet_binding b ON b.device_id = d.id WHERE d.state = 'active' AND b.host_id IS NOT NULL`)
	reenrolled := max(3, others+3)
	type dev struct {
		id uuid.UUID
		hw string
	}
	var devs []dev
	for n := range reenrolled + 2 {
		d := dev{r.device(t, uuid.NewString()), ""}
		d.hw = r.value(t, "SELECT hardware_uuid FROM device WHERE id = $1", d.id)
		r.host(r.id(int64(100+n)), d.hw, true)
		token := uuid.NewString()
		r.binder.hosts[token] = ports.HostSeen{Ref: r.id(int64(100 + n)), HardwareUUID: d.hw}
		r.report(t, d.id, token, r.clock)
		devs = append(devs, d)
	}
	r.round(t)
	r.round(t)
	restored := r.clock
	live := []ports.HostRef{}
	for n, d := range devs {
		ref := r.id(int64(100 + n))
		if n < reenrolled {
			r.src.enrolledAt[ref] = &restored
			r.answer(ref, false)
			live = append(live, ref)
			continue
		}
		r.drop(ref)
		r.host(r.id(int64(200+n)), d.hw, true)
		live = append(live, r.id(int64(200+n)))
	}
	r.advance(5*time.Minute, live...)
	r.round(t)
	if got := testutil.ToFloat64(metricClaimWatchSuppressed.WithLabelValues("device")); got < float64(reenrolled) {
		t.Fatalf("gauge %v, want at least %d", got, reenrolled)
	}
	for _, d := range devs[reenrolled:] {
		if !r.suspended(t, d.id) {
			t.Fatalf("%s: not suspended", d.id)
		}
	}
	for minutes := 10; minutes <= 70; minutes += 10 {
		if minutes == 30 {
			// The devices name their new hosts late, after the confirmation time of a second host.
			for n, d := range devs[reenrolled:] {
				token := uuid.NewString()
				r.binder.hosts[token] = ports.HostSeen{Ref: r.id(int64(200 + reenrolled + n)), HardwareUUID: d.hw}
				r.report(t, d.id, token, r.clock)
			}
		}
		r.advance(10*time.Minute, live...)
		r.round(t)
		for n, d := range devs {
			if c := r.events(t, claimCode, d.id); c != 0 {
				t.Fatalf("%s: %d claims after %d minutes", d.id, c, minutes)
			}
			if b := r.events(t, agentBinaryCode, d.id); n < reenrolled && minutes < 60 && b != 0 {
				t.Fatalf("%s: agent binary event during the hold", d.id)
			}
		}
	}
	for n, d := range devs[reenrolled:] {
		if r.suspended(t, d.id) || r.boundHost(t, d.id) != r.id(int64(200+reenrolled+n)) {
			t.Fatalf("%s: suspended %v, bound %s", d.id, r.suspended(t, d.id), r.boundHost(t, d.id))
		}
	}
}

// TestBindHostsResettingAndSuspendedFirst (review round 1, L2): with a small resolution budget, a device that announced
// its enrollment reset and a device with a suspended binding are resolved before an older token.
func TestBindHostsResettingAndSuspendedFirst(t *testing.T) {
	r := newBindRig(t)
	r.clearForeignTokens(t)
	r.inv.resolvePerRound = 2
	old, resetting, suspended := r.device(t, uuid.NewString()), r.device(t, uuid.NewString()), r.device(t, uuid.NewString())
	r.host(r.id(1), uuid.NewString(), true)
	if _, err := r.f.super.Exec(context.Background(), `INSERT INTO device_fleet_binding (device_id, organization_id, host_id,
		bound_at, suspended_at) VALUES ($1, $2, $3, $4, $4)`, suspended, r.f.org, string(r.id(99)), r.clock.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.f.super.Exec(context.Background(), `INSERT INTO device_fleet_binding (device_id, organization_id,
		reset_announced_at) VALUES ($1, $2, $3)`, resetting, r.f.org, r.clock.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	r.report(t, old, tokenA, r.clock.Add(-10*time.Minute))
	r.report(t, resetting, tokenB, r.clock.Add(-time.Minute))
	r.report(t, suspended, tokenC, r.clock.Add(-time.Minute))
	r.round(t)
	pending := func(d uuid.UUID) string {
		return r.value(t, "SELECT pending_token FROM device_fleet_binding WHERE device_id = $1", d)
	}
	if pending(old) != tokenA || pending(resetting) != "" || pending(suspended) != "" {
		t.Fatalf("pending: old %q, resetting %q, suspended %q", pending(old), pending(resetting), pending(suspended))
	}
}

// TestReportsHeartbeatToleratesUnknownFields (review round 1, L3): a heartbeat with a field this release does not know
// is recorded, not dead-lettered; a decoder of a release without the inventory fields reads a heartbeat that has them.
func TestReportsHeartbeatToleratesUnknownFields(t *testing.T) {
	f := newFixture(t)
	runner := app.NewActionRunner(f.pool, nil, httpx.RequestID)
	r := NewReports(app.NewDeviceReports(runner, f.pool), app.NewDeviceCommands(runner, f.pool), f.cache)
	dev := f.device(t, "active")
	body, _ := json.Marshal(map[string]any{"device_id": dev, "organization_id": f.org, "received_at": time.Now().UTC(),
		"fleet_device_token": tokenA, "future_field": "x"})
	if o := r.heartbeat(context.Background(), "m1", body); o != ack {
		t.Fatalf("outcome %v", o)
	}
	if f.count(t, "SELECT count(*) FROM device_status WHERE device_id = $1", dev) != 1 {
		t.Fatal("the heartbeat was not recorded")
	}
	var older struct {
		DeviceID   uuid.UUID `json:"device_id"`
		ReceivedAt time.Time `json:"received_at"`
	}
	if err := decodeLenient(body, &older); err != nil || older.DeviceID != dev {
		t.Fatalf("older decoder: %v", err)
	}
}

// TestHostTargetsDoubleBoundLogged (review round 1, L1): a host bound to two devices is stored for neither and logged.
func TestHostTargetsDoubleBoundLogged(t *testing.T) {
	logs := captureLogs(t)
	r := newBindRig(t)
	hw := uuid.NewString()
	a, b := r.device(t, hw), r.device(t, hw)
	r.host(r.id(5), hw, true)
	for _, d := range []uuid.UUID{a, b} {
		if _, err := r.f.super.Exec(context.Background(), "INSERT INTO device_fleet_binding (device_id, organization_id, host_id) VALUES ($1, $2, $3)",
			d, r.f.org, string(r.id(5))); err != nil {
			t.Fatal(err)
		}
	}
	r.round(t)
	if !strings.Contains(logs.String(), "inventory host bound to several devices") || !strings.Contains(logs.String(), string(r.id(5))) {
		t.Fatalf("not logged:\n%s", logs.String())
	}
	if r.externalID(t, a) != "" || r.externalID(t, b) != "" {
		t.Fatal("a host bound to two devices was stored")
	}
}

// TestInventoryRoundHostIDsSwapped (review round 1, N1, regression): after the inventory system reassigned two bound
// host IDs crosswise, each device's new token names the other device's previous host; both devices rebind, with no
// host_in_use refusal and no second_host claim.
func TestInventoryRoundHostIDsSwapped(t *testing.T) {
	r := newBindRig(t)
	admin := withLeftHostRemoval(r)
	hwV, hwW := uuid.NewString(), uuid.NewString()
	v, w := r.device(t, hwV), r.device(t, hwW)
	r.host(r.id(100), hwV, true)
	r.host(r.id(101), hwW, true)
	r.bindNow(t, v, r.id(100), hwV)
	r.bindNow(t, w, r.id(101), hwW)
	before := testutil.ToFloat64(metricHostBindings.WithLabelValues("host_in_use"))

	r.relabel(r.id(100), hwW)
	r.relabel(r.id(101), hwV)
	r.binder.hosts[tokenC] = ports.HostSeen{Ref: r.id(101), HardwareUUID: hwV}
	r.binder.hosts[tokenD] = ports.HostSeen{Ref: r.id(100), HardwareUUID: hwW}
	r.report(t, v, tokenC, r.clock)
	r.report(t, w, tokenD, r.clock)
	for range 5 {
		r.advance(5*time.Minute, r.id(100), r.id(101))
		r.round(t)
	}
	if r.boundHost(t, v) != r.id(101) || r.boundHost(t, w) != r.id(100) {
		t.Fatalf("V bound to %s, W bound to %s; want %s and %s", r.boundHost(t, v), r.boundHost(t, w), r.id(101), r.id(100))
	}
	if r.externalID(t, v) != r.id(101) || r.externalID(t, w) != r.id(100) || r.suspended(t, v) || r.suspended(t, w) {
		t.Fatalf("V stores %s, W stores %s", r.externalID(t, v), r.externalID(t, w))
	}
	if got := testutil.ToFloat64(metricHostBindings.WithLabelValues("host_in_use")) - before; got != 0 {
		t.Fatalf("host_in_use +%v", got)
	}
	if n := r.events(t, claimCode, v) + r.events(t, claimCode, w); n != 0 {
		t.Fatalf("%d claims", n)
	}
	if len(admin.calls) != 0 {
		t.Fatalf("hosts that are bound now were deleted: %v", admin.calls)
	}
}
