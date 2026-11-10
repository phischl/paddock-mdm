package agent

import (
	"context"
	"net/http"
	"os"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/apply"
	"github.com/phischl/paddock-mdm/agent/internal/buildinfo"
	"github.com/phischl/paddock-mdm/agent/internal/config"
	"github.com/phischl/paddock-mdm/agent/internal/health"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile/fakesys"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/agent/internal/testgw"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

func newAgent(t *testing.T, g *testgw.Gateway) *Agent {
	t.Helper()
	l, key := g.Enrolled(t)
	trust, err := config.LoadTrust(l.Trust())
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.LoadAgent(l.AgentConfig())
	a, err := New(Deps{Layout: l, Config: cfg, Trust: trust, Key: key, Client: g.Client(key), Rand: func() float64 { return 0.5 },
		Applier: apply.New(fakesys.New(), &reconcile.Managed{Files: map[string]string{}}, nil)})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestCycleSuccess(t *testing.T) {
	g := testgw.New(t)
	g.Checkin.NextCheckinS = 280
	a := newAgent(t, g)
	if d := a.Cycle(context.Background()); d != 280*time.Second {
		t.Fatalf("next check-in in %v", d)
	}
	if d := a.Cycle(context.Background()); d != 280*time.Second {
		t.Fatalf("next check-in in %v", d)
	}
	if len(g.Checkins) != 2 || g.Checkins[0].Seq != 0 || g.Checkins[1].Seq != 1 {
		t.Fatalf("check-ins %+v: the device must send the last received sequence number", g.Checkins)
	}
	req := g.Checkins[0].Req
	if req.AgentVersion != buildinfo.Version || req.Arch == "" || !slices.Equal(req.SchemaVersions, []int{1, 2}) {
		t.Fatalf("check-in request %+v", req)
	}
	st, _ := state.Load(a.d.Layout.State())
	if st.Seq != 2 || st.LastCheckinAt == nil {
		t.Fatalf("persisted state %+v", st)
	}
	if _, err := os.Stat(a.d.Layout.LastCheckin()); err != nil {
		t.Fatalf("last-checkin marker: %v", err)
	}
	if r := a.d.Health.Report(); r.Status != health.StatusOK || r.LastCheckinAt == nil {
		t.Fatalf("health %+v", r)
	}
}

func TestCycleFailureBackoff(t *testing.T) {
	g := testgw.New(t)
	g.CheckinFail = http.StatusServiceUnavailable
	a := newAgent(t, g)
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute}
	for _, w := range want {
		if d := a.Cycle(context.Background()); d != w {
			t.Fatalf("back-off %v, want %v", d, w)
		}
	}
	if r := a.d.Health.Report(); r.Status != health.StatusDegraded || r.LastError == "" {
		t.Fatalf("health %+v", r)
	}
	g.Mu.Lock()
	g.CheckinFail = 0
	g.Mu.Unlock()
	a.Cycle(context.Background())
	if a.failures != 0 || a.d.Health.Report().Status != health.StatusOK {
		t.Fatalf("failures not reset: %d", a.failures)
	}
	// Unreachable server: the same back-off, the agent keeps running.
	g.Close()
	if d := a.Cycle(context.Background()); d != 30*time.Second {
		t.Fatalf("unreachable: %v", d)
	}
}

func TestRunChecksInAtStartAndOnTrigger(t *testing.T) {
	g := testgw.New(t)
	g.Checkin.NextCheckinS = 3600
	a := newAgent(t, g)
	trig := make(chan struct{}, 1)
	a.d.Triggers = trig
	a.d.Rand = func() float64 { return 0 }
	var offset atomic.Int64 // fake clock: real time plus offset
	a.d.Now = func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	waitWithin(t, servedAtOnce, func() bool { return checkins(g) == 1 })
	// A trigger right after a check-in waits for the one-minute gap; advance the clock past it.
	offset.Store(int64(TriggerMinGap))
	trig <- struct{}{}
	waitWithin(t, servedAtOnce, func() bool { return checkins(g) == 2 })
	r, err := health.Get(ctx, a.d.Layout.Socket())
	if err != nil || r.Status != health.StatusOK || r.Version != buildinfo.Version {
		t.Fatalf("health socket: %+v, %v", r, err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}
}

func checkins(g *testgw.Gateway) int {
	g.Mu.Lock()
	defer g.Mu.Unlock()
	return len(g.Checkins)
}

// waitFor polls cond until it holds; hangGuard only catches a hang.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	waitWithin(t, hangGuard, cond)
}

// waitWithin polls cond until it holds and fails after bound.
func waitWithin(t *testing.T, bound time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(bound)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("condition not met within %s", bound)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// hangGuard bounds a wait for something the real run loop does on its own clock (check-ins every second, a worker's
// collection) when the time itself is not under test: a 5 s bound failed under a loaded host with a correct agent
// (PDK-883).
const hangGuard = time.Minute

// servedAtOnce is the bound a check-in the agent owes at once must meet. Here the bound is the assertion: a check-in
// delayed by the trigger's jitter (up to TriggerMaxDelay) or gap (TriggerMinGap) would miss it.
const servedAtOnce = TriggerMaxDelay / 3

// TestRunRecoversNSSShield (PDK-983, decisions §45): an agent that starts after its predecessor died during a package
// transaction finds the shield's marker, starts himmelblaud again and reports the hold once as recovered.
func TestRunRecoversNSSShield(t *testing.T) {
	g := testgw.New(t)
	g.Checkin.NextCheckinS = 3600
	a := newAgent(t, g)
	sys := fakesys.New()
	for _, u := range []string{"himmelblaud.service", "himmelblaud-tasks.service"} {
		sys.Units[u] = &fakesys.Unit{State: "enabled"}
	}
	sys.Files[reconcile.NSSShieldMarker] = &fakesys.File{Data: []byte(`{"action":"apt-get install","started_at":"2026-11-10T17:00:00Z"}`), Mode: 0o600}
	a.d.Shield = &reconcile.NSSShield{Sys: sys, Events: &reconcile.Events{Emit: a.event}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	waitWithin(t, servedAtOnce, func() bool { return slices.Contains(g.EventTypes(), protocol.EventLoginNSSShield) })
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}
	if !sys.Units["himmelblaud.service"].Active || !sys.Units["himmelblaud-tasks.service"].Active || sys.Files[reconcile.NSSShieldMarker] != nil {
		t.Errorf("himmelblaud %v, tasks %v, marker %v", sys.Units["himmelblaud.service"].Active,
			sys.Units["himmelblaud-tasks.service"].Active, sys.Files[reconcile.NSSShieldMarker] != nil)
	}
}
