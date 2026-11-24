package worker

import (
	"context"
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/inventory"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

const (
	claimCode           = "device.tamper_fleet_host_claimed"
	agentBinaryCode     = "device.tamper_agent_binary_changed"
	agentNotRunningCode = "device.tamper_agent_not_running"
)

// fakeBinder resolves device tokens from a fixed table; err fails every call.
type fakeBinder struct {
	hosts map[string]ports.HostSeen
	err   error
	calls int
}

func (b *fakeBinder) ResolveDeviceToken(_ context.Context, token string) (ports.HostRef, string, error) {
	b.calls++
	if b.err != nil {
		return "", "", b.err
	}
	h, ok := b.hosts[token]
	if !ok {
		return "", "", fmt.Errorf("%w: resolve a fleet device token: HTTP 401", problem.NotFound)
	}
	return h.Ref, h.HardwareUUID, nil
}

// bindRig is an inventory round over hosts that the test lists, with a controllable clock and binder.
type bindRig struct {
	f      fixture
	src    *fakeSource
	binder *fakeBinder
	inv    *Inventory
	clock  time.Time
	sys    context.Context
	// base makes the rig's host IDs unique in the shared database, as the inventory system's IDs are.
	base int64
	// fresh creates another worker instance over the same inventory system and database (a restart).
	fresh func() *Inventory
}

// id is the rig's host n.
func (r *bindRig) id(n int64) ports.HostRef { return ports.HostRef(strconv.FormatInt(r.base+n, 10)) }

func newBindRig(t *testing.T) *bindRig {
	t.Helper()
	f := newFixture(t)
	ctx := context.Background()
	platform, err := db.NewPlatformPool(ctx, pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	r := &bindRig{f: f, binder: &fakeBinder{hosts: map[string]ports.HostSeen{}}, clock: time.Now().UTC().Truncate(time.Second),
		src: &fakeSource{perHost: map[ports.HostRef]ports.HostInventory{}, seenAt: map[ports.HostRef]time.Time{},
			enrolledAt: map[ports.HostRef]*time.Time{}},
		sys: principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker"}), base: rand.Int64N(1e12) * 1000}
	runner := app.NewActionRunner(f.pool, platform, httpx.RequestID)
	r.fresh = func() *Inventory {
		inv := NewInventory(nil, r.src, app.NewInventorySync(runner, f.pool, platform), app.NewVulnerabilitySummary(runner), f.pool,
			platform, time.Minute).WithBinder(r.binder)
		inv.hashes = &fakeHashes{hashes: []string{strings.Repeat("a", 64)}}
		inv.now = func() time.Time { return r.clock }
		return inv
	}
	r.inv = r.fresh()
	// The claim watch and its guard see every device of the shared database; a rig's devices, whose clock runs ahead,
	// leave the watch with the test.
	t.Cleanup(func() {
		_, _ = f.super.Exec(context.Background(), "UPDATE device SET state = 'retired' WHERE organization_id = $1", f.org)
		_, _ = f.super.Exec(context.Background(), "UPDATE device_inventory_left_host SET removed_at = now() WHERE organization_id = $1", f.org)
	})
	return r
}

func (r *bindRig) device(t *testing.T, hw string) uuid.UUID {
	t.Helper()
	dev := uuid.Must(uuid.NewV7())
	if _, err := r.f.super.Exec(context.Background(), "INSERT INTO device (id, organization_id, hostname, state, hardware_uuid) VALUES ($1, $2, 'lt-bind', 'active', $3)",
		dev, r.f.org, hw); err != nil {
		t.Fatal(err)
	}
	return dev
}

// host lists a host whose agent policies pass or fail, last seen now, evaluated well after the binary policy's gate.
func (r *bindRig) host(ref ports.HostRef, hw string, passing bool) {
	r.src.hosts = append(r.src.hosts, ports.InventoryHost{Ref: ref, HardwareUUID: hw})
	r.answer(ref, passing)
	r.src.seenAt[ref] = r.clock
	enrolled := r.clock.Add(-48 * time.Hour)
	r.src.enrolledAt[ref] = &enrolled
}

func (r *bindRig) answer(ref ports.HostRef, passing bool) {
	evaluated := r.clock.Add(24 * time.Hour)
	r.src.perHost[ref] = ports.HostInventory{PolicyUpdatedAt: &evaluated, Policies: []ports.PolicyResult{
		{Key: inventory.PolicyAgentBinaryKnown, Passing: passing}, {Key: inventory.PolicyAgentRunning, Passing: passing}}}
}

// report records a pending token as the device's heartbeat would.
func (r *bindRig) report(t *testing.T, dev uuid.UUID, token string, at time.Time) {
	t.Helper()
	if _, err := r.f.super.Exec(context.Background(), `INSERT INTO device_fleet_binding (device_id, organization_id, pending_token, token_reported_at)
		VALUES ($1, $2, $3, $4) ON CONFLICT (device_id) DO UPDATE SET pending_token = EXCLUDED.pending_token,
		token_reported_at = EXCLUDED.token_reported_at`, dev, r.f.org, token, at); err != nil {
		t.Fatal(err)
	}
}

// advance moves the clock; the hosts in live were seen at the new time.
func (r *bindRig) advance(d time.Duration, live ...ports.HostRef) {
	r.clock = r.clock.Add(d)
	for _, ref := range live {
		r.src.seenAt[ref] = r.clock
	}
}

func (r *bindRig) round(t *testing.T) {
	t.Helper()
	if err := r.inv.Round(r.sys); err != nil {
		t.Fatal(err)
	}
}

func (r *bindRig) value(t *testing.T, query string, args ...any) string {
	t.Helper()
	var v *string
	if err := r.f.super.QueryRow(context.Background(), query, args...).Scan(&v); err != nil || v == nil {
		return ""
	}
	return *v
}

func (r *bindRig) externalID(t *testing.T, dev uuid.UUID) ports.HostRef {
	return ports.HostRef(r.value(t, "SELECT external_id FROM device_inventory_ref WHERE device_id = $1", dev))
}

func (r *bindRig) boundHost(t *testing.T, dev uuid.UUID) ports.HostRef {
	return ports.HostRef(r.value(t, "SELECT host_id FROM device_fleet_binding WHERE device_id = $1", dev))
}

func (r *bindRig) events(t *testing.T, code string, dev uuid.UUID) int {
	t.Helper()
	return r.f.count(t, "SELECT count(*) FROM action WHERE code = $1 AND target ->> 'id' = $2", code, dev.String())
}

func (r *bindRig) claimParam(t *testing.T, dev uuid.UUID, key string) string {
	return r.value(t, "SELECT params ->> $3::text FROM action WHERE code = $1 AND target ->> 'id' = $2", claimCode, dev.String(), key)
}

// seedClaimSince moves the device's open claim episode back, as if it had started d ago.
func (r *bindRig) seedClaimSince(t *testing.T, dev uuid.UUID, d time.Duration) {
	t.Helper()
	if _, err := r.f.super.Exec(context.Background(), "UPDATE device_inventory_ref SET fleet_claim_since = $2 WHERE device_id = $1 AND fleet_claim_since IS NOT NULL",
		dev, r.clock.Add(-d)); err != nil {
		t.Fatal(err)
	}
}

const (
	tokenA = "0a0a0a0a-1d2f-4a3b-9c4d-5e6f7a8b9c0d"
	tokenB = "0b0b0b0b-1d2f-4a3b-9c4d-5e6f7a8b9c0d"
	tokenC = "0c0c0c0c-1d2f-4a3b-9c4d-5e6f7a8b9c0d"
	tokenD = "0d0d0d0d-1d2f-4a3b-9c4d-5e6f7a8b9c0d"
	tokenE = "0e0e0e0e-1d2f-4a3b-9c4d-5e6f7a8b9c0d"
	tokenF = "0f0f0f0f-1d2f-4a3b-9c4d-5e6f7a8b9c0d"
)

// TestInventoryRoundBoundHost (ADR 0057, H6, regression): a host enrolled first with the device's hardware UUID never
// replaces the bound host's data; it is reported as a second host after the confirmation.
func TestInventoryRoundBoundHost(t *testing.T) {
	r := newBindRig(t)
	hw := uuid.NewString()
	dev := r.device(t, hw)
	r.host(r.id(7), hw, false)
	r.host(r.id(9), hw, true)
	r.binder.hosts[tokenA] = ports.HostSeen{Ref: r.id(9), HardwareUUID: hw}
	r.report(t, dev, tokenA, r.clock.Add(-time.Minute))
	for range 3 {
		r.round(t)
		if got := r.externalID(t, dev); got != r.id(9) {
			t.Fatalf("external_id %q, want the bound host 9", got)
		}
		r.advance(5*time.Minute, r.id(7), r.id(9))
	}
	if n := r.events(t, agentBinaryCode, dev); n != 0 {
		t.Fatalf("%d agent binary events from another host", n)
	}
	if n := r.events(t, claimCode, dev); n != 0 {
		t.Fatalf("claim before the confirmation: %d", n)
	}
	r.seedClaimSince(t, dev, inventory.HostClaimConfirm)
	r.round(t)
	r.round(t)
	if n := r.events(t, claimCode, dev); n != 1 || r.claimParam(t, dev, "kind") != "second_host" ||
		r.claimParam(t, dev, "binding") != "device" || r.claimParam(t, dev, "bound_host") != string(r.id(9)) || r.claimParam(t, dev, "other_hosts") != string(r.id(7)) {
		t.Fatalf("%d claims, kind %q binding %q bound %q others %q", n, r.claimParam(t, dev, "kind"), r.claimParam(t, dev, "binding"),
			r.claimParam(t, dev, "bound_host"), r.claimParam(t, dev, "other_hosts"))
	}
}

// TestInventoryRoundFirstEnrolledHost (ADR 0057, H6, regression): a device that named no host keeps the host enrolled
// first; a later host that keeps changing is not stored and is reported with binding first.
func TestInventoryRoundFirstEnrolledHost(t *testing.T) {
	r := newBindRig(t)
	hw := uuid.NewString()
	dev := r.device(t, hw)
	r.host(r.id(7), hw, false)
	r.host(r.id(9), hw, true)
	for range 3 {
		r.round(t)
		if got := r.externalID(t, dev); got != r.id(7) {
			t.Fatalf("external_id %q, want the first-enrolled host 7", got)
		}
		if got := r.value(t, "SELECT passing::text FROM inventory_policy_result WHERE device_id = $1 AND policy_key = $2", dev, inventory.PolicyAgentRunning); got != "false" {
			t.Fatalf("agent running %q, want the first host's failing answer", got)
		}
		r.advance(5*time.Minute, r.id(7), r.id(9))
	}
	r.seedClaimSince(t, dev, inventory.HostClaimConfirm)
	r.round(t)
	if r.events(t, claimCode, dev) != 1 || r.claimParam(t, dev, "binding") != "first" || r.claimParam(t, dev, "bound_host") != string(r.id(7)) {
		t.Fatalf("claim binding %q bound %q", r.claimParam(t, dev, "binding"), r.claimParam(t, dev, "bound_host"))
	}
}

// TestInventoryRoundBindsReportedToken (ADR 0057, H5): every decision with its counter; a failing inventory system
// keeps the token without failing the round, and at most ResolvePerRound tokens are resolved per round.
func TestInventoryRoundBindsReportedToken(t *testing.T) {
	r := newBindRig(t)
	counter := func(result string) float64 { return testutil.ToFloat64(metricHostBindings.WithLabelValues(result)) }
	before := map[string]float64{}
	for _, l := range []string{"bound", "rebound", "current", "expired", "unknown_token", "uuid_mismatch", "unavailable"} {
		before[l] = counter(l)
	}
	hw := map[string]string{}
	devs := map[string]uuid.UUID{}
	for _, name := range []string{"bound", "rebound", "mismatch", "unknown", "expired", "current"} {
		hw[name] = uuid.NewString()
		devs[name] = r.device(t, hw[name])
	}
	r.host(r.id(10), hw["bound"], true)
	r.host(r.id(20), hw["rebound"], true)
	r.host(r.id(21), hw["rebound"], true)
	r.host(r.id(30), uuid.NewString(), true)
	r.host(r.id(60), hw["current"], true)
	r.src.seenAt[r.id(20)] = r.clock.Add(-inventory.BindingStale) // the bound host fell silent: the token is resolved
	r.binder.hosts[tokenA] = ports.HostSeen{Ref: r.id(10), HardwareUUID: strings.ToUpper(hw["bound"])}
	r.binder.hosts[tokenB] = ports.HostSeen{Ref: r.id(21), HardwareUUID: hw["rebound"]}
	r.binder.hosts[tokenC] = ports.HostSeen{Ref: r.id(30), HardwareUUID: uuid.NewString()}
	r.binder.hosts[tokenE] = ports.HostSeen{Ref: r.id(60), HardwareUUID: hw["current"]}
	reported := r.clock.Add(-time.Minute)
	if _, err := r.f.super.Exec(context.Background(), "INSERT INTO device_fleet_binding (device_id, organization_id, host_id, bound_at) VALUES ($1, $3, $5, $4), ($2, $3, $6, $4)",
		devs["rebound"], devs["current"], r.f.org, r.clock.Add(-time.Hour), string(r.id(20)), string(r.id(60))); err != nil {
		t.Fatal(err)
	}
	r.report(t, devs["bound"], tokenA, reported)
	r.report(t, devs["rebound"], tokenB, reported)
	r.report(t, devs["mismatch"], tokenC, reported)
	r.report(t, devs["unknown"], tokenD, reported)
	r.report(t, devs["expired"], tokenF, r.clock.Add(-inventory.TokenMaxAge))
	r.report(t, devs["current"], tokenE, reported)
	r.round(t)
	want := map[string]ports.HostRef{"bound": r.id(10), "rebound": r.id(21), "mismatch": "", "unknown": "", "expired": "", "current": r.id(60)}
	for name, host := range want {
		if got := r.boundHost(t, devs[name]); got != host {
			t.Errorf("%s: bound to %q, want %q", name, got, host)
		}
		if got := r.value(t, "SELECT pending_token FROM device_fleet_binding WHERE device_id = $1", devs[name]); got != "" {
			t.Errorf("%s: token still pending", name)
		}
	}
	if r.binder.calls != 4 {
		t.Errorf("%d resolutions, want 4 (no call for an expired token or a talking bound host)", r.binder.calls)
	}
	for l, d := range map[string]float64{"bound": 1, "rebound": 1, "current": 1, "expired": 1, "unknown_token": 1, "uuid_mismatch": 1} {
		if got := counter(l) - before[l]; got != d {
			t.Errorf("counter %s +%v, want +%v", l, got, d)
		}
	}

	r.binder.err = fmt.Errorf("%w: resolve a fleet device token: HTTP 502", problem.UpstreamUnavailable)
	r.report(t, devs["mismatch"], tokenC, r.clock)
	r.report(t, devs["unknown"], tokenD, r.clock)
	calls := r.binder.calls
	r.round(t)
	if r.binder.calls != calls+1 || counter("unavailable")-before["unavailable"] != 1 {
		t.Fatalf("calls +%d, unavailable +%v: one failed call stops the round's resolutions", r.binder.calls-calls, counter("unavailable")-before["unavailable"])
	}
	if r.value(t, "SELECT pending_token FROM device_fleet_binding WHERE device_id = $1", devs["mismatch"]) != tokenC ||
		r.value(t, "SELECT pending_token FROM device_fleet_binding WHERE device_id = $1", devs["unknown"]) != tokenD {
		t.Fatal("tokens of an unavailable inventory system were cleared")
	}
}

// TestInventoryRoundResolvesAtMostPerRound (ADR 0057, H5 rule 3).
func TestInventoryRoundResolvesAtMostPerRound(t *testing.T) {
	r := newBindRig(t)
	r.host(r.id(1), uuid.NewString(), true)
	at := r.clock.Add(-time.Minute)
	for n := range inventory.ResolvePerRound + 1 {
		r.report(t, r.device(t, uuid.NewString()), fmt.Sprintf("%08x-1d2f-4a3b-9c4d-5e6f7a8b9c0d", n), at)
	}
	r.round(t)
	if r.binder.calls != inventory.ResolvePerRound {
		t.Fatalf("%d resolutions, want %d", r.binder.calls, inventory.ResolvePerRound)
	}
	if n := r.f.count(t, "SELECT count(*) FROM device_fleet_binding WHERE organization_id = $1 AND pending_token IS NOT NULL", r.f.org); n != 1 {
		t.Fatalf("%d tokens pending, want 1 for the next round", n)
	}
}

// TestInventoryRoundReenrolledHost (ADR 0057, H7 and H8, regression): a re-enrollment of the speaking host is
// reported at once, and its failing agent binary policy waits ClaimQuiet.
func TestInventoryRoundReenrolledHost(t *testing.T) {
	r := newBindRig(t)
	hw := uuid.NewString()
	dev := r.device(t, hw)
	r.host(r.id(9), hw, true)
	r.binder.hosts[tokenA] = ports.HostSeen{Ref: r.id(9), HardwareUUID: hw}
	r.report(t, dev, tokenA, r.clock.Add(-time.Minute))
	r.round(t)
	r.advance(5*time.Minute, r.id(9))
	r.round(t)
	reenrolled := r.clock
	r.src.enrolledAt[r.id(9)] = &reenrolled
	r.answer(r.id(9), false)
	r.advance(5*time.Minute, r.id(9))
	r.round(t)
	if r.events(t, claimCode, dev) != 1 || r.claimParam(t, dev, "kind") != "reenrolled" {
		t.Fatalf("claim kind %q", r.claimParam(t, dev, "kind"))
	}
	if n := r.events(t, agentBinaryCode, dev); n != 0 {
		t.Fatalf("%d agent binary events during the hold", n)
	}
	r.advance(inventory.ClaimQuiet+time.Minute, r.id(9))
	r.round(t)
	if n := r.events(t, agentBinaryCode, dev); n != 1 {
		t.Fatalf("%d agent binary events after the hold, want 1", n)
	}
	if n := r.events(t, claimCode, dev); n != 1 {
		t.Fatalf("%d claims, want 1 per episode", n)
	}
}

// TestInventoryRoundFleetRestore (ADR 0057, H9): most watched devices re-enrolled in one round raise no claim; the
// gauge counts them and the agent reports are held; the episodes end after ClaimQuiet.
func TestInventoryRoundFleetRestore(t *testing.T) {
	r := newBindRig(t)
	var devs []uuid.UUID
	// The guard counts every watched device of the shared database: re-enroll more than all others together.
	restoredDevices := max(5, r.f.count(t, "SELECT count(*) FROM device d JOIN device_inventory_ref i ON i.device_id = d.id WHERE d.state = 'active'")+1)
	for n := range restoredDevices {
		hw := uuid.NewString()
		dev := r.device(t, hw)
		ref := r.id(100 + int64(n))
		r.host(ref, hw, true)
		devs = append(devs, dev)
	}
	r.round(t)
	r.round(t)
	restored := r.clock
	for n := range restoredDevices {
		ref := r.id(100 + int64(n))
		r.src.enrolledAt[ref] = &restored
		r.answer(ref, false)
	}
	r.advance(5 * time.Minute)
	r.round(t)
	if got := testutil.ToFloat64(metricClaimWatchSuppressed.WithLabelValues("first")); got < float64(restoredDevices) {
		t.Fatalf("gauge %v, want at least %d", got, restoredDevices)
	}
	for _, dev := range devs {
		if r.events(t, claimCode, dev)+r.events(t, agentBinaryCode, dev)+r.events(t, agentNotRunningCode, dev) != 0 {
			t.Fatalf("device %s reported during a restore", dev)
		}
	}
	r.advance(inventory.ClaimQuiet + time.Minute)
	r.round(t)
	if got := testutil.ToFloat64(metricClaimWatchSuppressed.WithLabelValues("first")); got != 0 {
		t.Fatalf("gauge %v after the episodes ended", got)
	}
	if n := r.f.count(t, "SELECT count(*) FROM device_inventory_ref WHERE organization_id = $1 AND fleet_claim_since IS NOT NULL", r.f.org); n != 0 {
		t.Fatalf("%d open episodes", n)
	}
}

// TestInventoryRoundAnnouncedResetRaisesNoClaim (ADR 0057, H14, regression): after the agent announced its enrollment
// reset, the new host is listed while its token cannot be resolved for 20 minutes; no claim is raised, and the device
// ends bound to the new host.
func TestInventoryRoundAnnouncedResetRaisesNoClaim(t *testing.T) {
	r := newBindRig(t)
	hw := uuid.NewString()
	dev := r.device(t, hw)
	r.host(r.id(7), hw, true)
	r.round(t)
	if r.externalID(t, dev) != r.id(7) {
		t.Fatal("the previous host was not stored")
	}
	if _, err := r.f.super.Exec(context.Background(), `INSERT INTO device_fleet_binding (device_id, organization_id, reset_announced_at)
		VALUES ($1, $2, $3)`, dev, r.f.org, r.clock); err != nil {
		t.Fatal(err)
	}
	r.advance(time.Minute)
	r.host(r.id(12), hw, true)
	r.binder.hosts[tokenA] = ports.HostSeen{Ref: r.id(12), HardwareUUID: hw}
	r.report(t, dev, tokenA, r.clock)
	r.binder.err = fmt.Errorf("%w: resolve a fleet device token: HTTP 503", problem.UpstreamUnavailable)
	for range 5 {
		r.round(t)
		r.advance(5*time.Minute, r.id(12))
	}
	r.binder.err = nil
	r.round(t)
	r.advance(5*time.Minute, r.id(12))
	r.round(t)
	if r.boundHost(t, dev) != r.id(12) || r.externalID(t, dev) != r.id(12) {
		t.Fatalf("bound %q, stored %q; want the new host 12", r.boundHost(t, dev), r.externalID(t, dev))
	}
	if n := r.events(t, claimCode, dev); n != 0 {
		t.Fatalf("%d claims for the device's own announced reset", n)
	}
}

// TestInventoryRoundNotLeaderResetsClaimGauge (ADR 0057, H9): a process that did not run the round reports no
// suppression.
func TestInventoryRoundNotLeaderResetsClaimGauge(t *testing.T) {
	r := newBindRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := r.f.super.Exec(ctx, "SELECT pg_advisory_lock($1)", int64(inventorySyncLockKey)); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = r.f.super.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", int64(inventorySyncLockKey))
	}()
	metricClaimWatchSuppressed.WithLabelValues("device").Set(4)
	metricBindingsSuspended.Set(3)
	done := make(chan error, 1)
	go func() { done <- r.inv.RunSync(ctx) }()
	deadline := time.Now().Add(30 * time.Second)
	for testutil.ToFloat64(metricClaimWatchSuppressed.WithLabelValues("device"))+testutil.ToFloat64(metricBindingsSuspended) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the gauge kept its value without the lock")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
