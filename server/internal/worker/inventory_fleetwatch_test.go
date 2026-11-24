package worker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/phischl/paddock-mdm/server/internal/inventory"
	"github.com/phischl/paddock-mdm/server/internal/ports"
)

const fleetdSilentCode = "device.tamper_fleetd_silent"

// fleetRig is a bindRig whose devices each have one host and check in; a frozen host stops contacting the inventory
// system, a policy-frozen host stops storing policy results. Its clock runs a year ahead, so that no device another
// test left in the shared database counts as checking in.
type fleetRig struct {
	*bindRig
	devices      []uuid.UUID
	hosts        []ports.HostRef
	frozen       map[ports.HostRef]bool
	policyFrozen map[ports.HostRef]bool
	silent       map[uuid.UUID]bool
}

func newFleetRig(t *testing.T, n int) *fleetRig {
	t.Helper()
	r := &fleetRig{bindRig: newBindRig(t), frozen: map[ports.HostRef]bool{}, policyFrozen: map[ports.HostRef]bool{},
		silent: map[uuid.UUID]bool{}}
	r.clock = r.clock.AddDate(1, 0, 0)
	r.src.policyAt = map[ports.HostRef]*time.Time{}
	for k := range n {
		hw := uuid.NewString()
		dev := r.device(t, hw)
		ref := r.id(int64(k))
		r.host(ref, hw, true)
		if _, err := r.f.super.Exec(context.Background(), "INSERT INTO device_status (device_id, organization_id, last_contact_at) VALUES ($1, $2, $3)",
			dev, r.f.org, r.clock); err != nil {
			t.Fatal(err)
		}
		r.devices, r.hosts = append(r.devices, dev), append(r.hosts, ref)
	}
	r.contact(t)
	return r
}

// contact lets every host that is not frozen contact the inventory system now and every device that is not silent
// check in.
func (r *fleetRig) contact(t *testing.T) {
	t.Helper()
	for n, ref := range r.hosts {
		at := r.clock
		if !r.frozen[ref] {
			r.src.seenAt[ref] = at
		}
		if !r.policyFrozen[ref] {
			r.src.policyAt[ref] = &at
		}
		if r.silent[r.devices[n]] {
			continue
		}
		if _, err := r.f.super.Exec(context.Background(), "UPDATE device_status SET last_contact_at = $2 WHERE device_id = $1",
			r.devices[n], at.Add(-30*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
}

// tick moves the clock by one round, lets the hosts and devices contact and runs the round; it returns its error.
func (r *fleetRig) tick(t *testing.T) error {
	t.Helper()
	r.clock = r.clock.Add(DefaultInventorySyncInterval)
	r.contact(t)
	return r.inv.Round(r.sys)
}

func (r *fleetRig) events(t *testing.T, dev uuid.UUID) int {
	return r.bindRig.events(t, fleetdSilentCode, dev)
}

func (r *fleetRig) total(t *testing.T) int {
	n := 0
	for _, d := range r.devices {
		n += r.events(t, d)
	}
	return n
}

func (r *fleetRig) since(t *testing.T, dev uuid.UUID) string {
	return r.value(t, "SELECT fleet_silent_since::text FROM device_inventory_ref WHERE device_id = $1", dev)
}

// TestInventoryRoundFleetSilence (plan M5a amendment 2026-11-16 c, section 8; AC-D1): the watched host stops while
// three peers keep contacting and the device keeps checking in. It is reported in the round where it has been stale
// for 15 minutes relative to the newest contact and confirmed for 15 more, exactly once; contact again clears the
// mark, and a second silence is reported again.
func TestInventoryRoundFleetSilence(t *testing.T) {
	r := newFleetRig(t, 4)
	watched := r.devices[0]
	if err := r.tick(t); err != nil {
		t.Fatal(err)
	}
	r.frozen[r.hosts[0]] = true
	for k := 1; k <= 17; k++ {
		switch k {
		case 10:
			r.frozen[r.hosts[0]] = false
		case 11:
			r.frozen[r.hosts[0]] = true
		}
		if err := r.tick(t); err != nil {
			t.Fatal(err)
		}
		want := 0
		switch {
		case k >= 17:
			want = 2
		case k >= 7:
			want = 1
		}
		if n := r.events(t, watched); n != want {
			t.Fatalf("round %d: %d events, want %d", k, n, want)
		}
		if k == 10 && r.value(t, "SELECT fleet_silent_reported_at::text FROM device_inventory_ref WHERE device_id = $1", watched) != "" {
			t.Fatal("the mark was not cleared when the host made contact again")
		}
	}
	if n := r.events(t, r.devices[1]) + r.events(t, r.devices[2]) + r.events(t, r.devices[3]); n != 0 {
		t.Fatalf("%d events of peers", n)
	}
	if reason := r.value(t, "SELECT params ->> 'reason' FROM action WHERE code = $1 AND target ->> 'id' = $2 LIMIT 1",
		fleetdSilentCode, watched.String()); reason != inventory.SilentContact {
		t.Fatalf("reason %q", reason)
	}
	if n := r.f.count(t, "SELECT count(*) FROM finding WHERE device_id = $1 AND kind = 'tamper' AND code = $2", watched, fleetdSilentCode); n != 1 {
		t.Fatalf("%d tamper findings", n)
	}
}

// TestInventoryRoundFleetPolicies (plan M5a amendment 2026-11-16 d, F5; AC-d2): a host that keeps contacting but
// stores no policy results for 30 minutes longer than the newest host is reported with reason policies.
func TestInventoryRoundFleetPolicies(t *testing.T) {
	r := newFleetRig(t, 4)
	watched := r.devices[0]
	if err := r.tick(t); err != nil {
		t.Fatal(err)
	}
	r.policyFrozen[r.hosts[0]] = true
	for k := 1; k <= 10; k++ {
		if err := r.tick(t); err != nil {
			t.Fatal(err)
		}
		want := 0
		if k >= 10 {
			want = 1
		}
		if n := r.events(t, watched); n != want {
			t.Fatalf("round %d: %d events, want %d", k, n, want)
		}
	}
	if reason := r.value(t, "SELECT params ->> 'reason' FROM action WHERE code = $1 AND target ->> 'id' = $2",
		fleetdSilentCode, watched.String()); reason != inventory.SilentPolicies {
		t.Fatalf("reason %q", reason)
	}
}

// TestInventoryRoundFleetOutage (plan M5a amendment 2026-11-16 c, section 8; AC-D2, regression for the guards):
//  1. the host list fails for six rounds: the rounds fail, nothing changes;
//  2. every host contacts again in the same round except the watched one, which follows a round later: no event;
//  3. every host's contact frozen for 40 minutes while the devices check in: no event;
//  4. 3 of 4 live devices stale for 40 minutes: no event, the gauge holds 3 and each held round warns fresh_minority.
func TestInventoryRoundFleetOutage(t *testing.T) {
	r := newFleetRig(t, 4)
	logs := captureLogs(t)
	if err := r.tick(t); err != nil {
		t.Fatal(err)
	}
	unchanged := func(step string) {
		t.Helper()
		for _, d := range r.devices {
			if r.since(t, d) != "" {
				t.Fatalf("%s: device %s has a silence start", step, d)
			}
		}
		if n := r.total(t); n != 0 {
			t.Fatalf("%s: %d events", step, n)
		}
	}
	for _, ref := range r.hosts {
		r.frozen[ref] = true
	}
	r.src.listErr = errors.New("fleet: HTTP 502")
	for k := range 6 {
		if err := r.tick(t); err == nil {
			t.Fatalf("outage round %d succeeded", k+1)
		}
	}
	unchanged("outage")
	r.src.listErr = nil
	for _, ref := range r.hosts[1:] {
		r.frozen[ref] = false
	}
	if err := r.tick(t); err != nil {
		t.Fatal(err)
	}
	if r.since(t, r.devices[0]) == "" {
		t.Fatal("the late host was not found silent")
	}
	r.frozen[r.hosts[0]] = false
	if err := r.tick(t); err != nil {
		t.Fatal(err)
	}
	unchanged("reconnect")

	for _, ref := range r.hosts {
		r.frozen[ref] = true
	}
	for range 8 {
		if err := r.tick(t); err != nil {
			t.Fatal(err)
		}
	}
	unchanged("frozen list")

	for _, ref := range r.hosts {
		r.frozen[ref] = false
	}
	if err := r.tick(t); err != nil {
		t.Fatal(err)
	}
	logs.Reset()
	for _, ref := range r.hosts[:3] {
		r.frozen[ref] = true
	}
	for range 8 {
		if err := r.tick(t); err != nil {
			t.Fatal(err)
		}
	}
	if n := r.total(t); n != 0 {
		t.Fatalf("fresh minority: %d events", n)
	}
	if g := testutil.ToFloat64(metricFleetSilentSuppressed); g != 3 {
		t.Fatalf("gauge %v, want 3", g)
	}
	warns := strings.Count(logs.String(), `"msg":"fleet silence watch suppressed","reason":"fresh_minority","due":3,"live":4,"fresh":1`)
	if warns != 2 {
		t.Fatalf("%d suppression warnings, want 2:\n%s", warns, logs)
	}
}

// TestInventoryFleetSuppressedGauge (plan M5a amendment 2026-11-16 c, E8): a round that holds back 2 devices sets the
// gauge to 2; the following round, in which enough devices check in, reports them and sets 0; a process that did not
// run the round sets 0.
func TestInventoryFleetSuppressedGauge(t *testing.T) {
	r := newFleetRig(t, 5)
	r.silent[r.devices[3]], r.silent[r.devices[4]] = true, true
	if _, err := r.f.super.Exec(context.Background(), "UPDATE device_status SET last_contact_at = $2 WHERE device_id = ANY($1)",
		[]uuid.UUID{r.devices[3], r.devices[4]}, r.clock.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := r.tick(t); err != nil {
		t.Fatal(err)
	}
	r.frozen[r.hosts[0]], r.frozen[r.hosts[1]] = true, true
	for range 7 {
		if err := r.tick(t); err != nil {
			t.Fatal(err)
		}
	}
	if g := testutil.ToFloat64(metricFleetSilentSuppressed); g != 2 || r.total(t) != 0 {
		t.Fatalf("gauge %v with %d events, want 2 held", g, r.total(t))
	}
	r.silent[r.devices[3]], r.silent[r.devices[4]] = false, false
	if err := r.tick(t); err != nil {
		t.Fatal(err)
	}
	if g := testutil.ToFloat64(metricFleetSilentSuppressed); g != 0 || r.events(t, r.devices[0]) != 1 || r.events(t, r.devices[1]) != 1 {
		t.Fatalf("gauge %v, events %d and %d after the guards hold", g, r.events(t, r.devices[0]), r.events(t, r.devices[1]))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := r.f.super.Exec(ctx, "SELECT pg_advisory_lock($1)", int64(inventorySyncLockKey)); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = r.f.super.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", int64(inventorySyncLockKey))
	}()
	metricFleetSilentSuppressed.Set(2)
	done := make(chan error, 1)
	go func() { done <- r.inv.RunSync(ctx) }()
	deadline := time.Now().Add(30 * time.Second)
	for testutil.ToFloat64(metricFleetSilentSuppressed) != 0 {
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

// TestInventoryRoundFleetWorkerRestart (plan M5a amendment 2026-11-16 c, section 8): a new worker instance continues
// the stored state: a device silent for 16 minutes is reported in its first round, exactly once across both instances.
func TestInventoryRoundFleetWorkerRestart(t *testing.T) {
	r := newFleetRig(t, 4)
	watched := r.devices[0]
	if err := r.tick(t); err != nil {
		t.Fatal(err)
	}
	r.frozen[r.hosts[0]] = true
	for range 4 {
		if err := r.tick(t); err != nil {
			t.Fatal(err)
		}
	}
	if r.since(t, watched) == "" || r.events(t, watched) != 0 {
		t.Fatal("the silence did not start")
	}
	if _, err := r.f.super.Exec(context.Background(), "UPDATE device_inventory_ref SET fleet_silent_since = $2 WHERE device_id = $1",
		watched, r.clock.Add(-16*time.Minute)); err != nil {
		t.Fatal(err)
	}
	old := r.inv
	r.inv = r.fresh()
	if err := r.tick(t); err != nil {
		t.Fatal(err)
	}
	if n := r.events(t, watched); n != 1 {
		t.Fatalf("new instance: %d events, want 1", n)
	}
	r.inv = old
	if err := r.tick(t); err != nil {
		t.Fatal(err)
	}
	if n := r.events(t, watched); n != 1 {
		t.Fatalf("across both instances: %d events, want 1", n)
	}
}

// TestInventoryRoundAgentRunningQueryFails (plan M5a amendment 2026-11-16 d, F6; AC-d3, regression L1-A): an
// agent-running policy that the host lists without an answer in evaluations past the gate counts as failing; with
// evaluations 10 minutes apart while the device checks in, device.tamper_agent_not_running is recorded once, after the
// third evaluation.
func TestInventoryRoundAgentRunningQueryFails(t *testing.T) {
	r := newBinaryRig(t, strings.Repeat("a", 64))
	ctx := context.Background()
	if _, err := r.f.super.Exec(ctx, "INSERT INTO device_status (device_id, organization_id, last_contact_at) VALUES ($1, $2, $3)",
		r.dev, r.f.org, r.clock); err != nil {
		t.Fatal(err)
	}
	r.round(t)
	start := r.clock
	for k, want := range []int{0, 0, 1, 1} {
		r.clock = start.Add(time.Duration(k+1) * 10 * time.Minute)
		at := r.clock
		if _, err := r.f.super.Exec(ctx, "UPDATE device_status SET last_contact_at = $2 WHERE device_id = $1", r.dev, at.Add(-time.Minute)); err != nil {
			t.Fatal(err)
		}
		r.src.results = []ports.PolicyResult{{Key: inventory.PolicyAgentBinaryKnown, Passing: true}}
		r.src.unanswered, r.src.evaluatedAt = []string{inventory.PolicyAgentRunning}, &at
		r.src.vulnState = at.String() // every round reads all hosts, so the unanswered gauge is set
		r.round(t)
		if n := r.f.count(t, "SELECT count(*) FROM action WHERE code = $1 AND target ->> 'id' = $2", agentNotRunningCode, r.dev.String()); n != want {
			t.Fatalf("evaluation %d: %d events, want %d", k+1, n, want)
		}
	}
	if g := testutil.ToFloat64(metricPolicyUnanswered.WithLabelValues(inventory.PolicyAgentRunning)); g < 1 {
		t.Fatalf("the unanswered gauge stopped counting the host: %v", g)
	}
}
