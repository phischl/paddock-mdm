package agent

import (
	"context"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paddock-mdm/paddock/agent/internal/buildinfo"
	"github.com/paddock-mdm/paddock/agent/internal/config"
	"github.com/paddock-mdm/paddock/agent/internal/health"
	"github.com/paddock-mdm/paddock/agent/internal/state"
	"github.com/paddock-mdm/paddock/agent/internal/testgw"
)

func newAgent(t *testing.T, g *testgw.Gateway) *Agent {
	t.Helper()
	l, key := g.Enrolled(t)
	trust, err := config.LoadTrust(l.Trust())
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.LoadAgent(l.AgentConfig())
	a, err := New(Deps{Layout: l, Config: cfg, Trust: trust, Key: key, Client: g.Client(key), Rand: func() float64 { return 0.5 }})
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
	if req.AgentVersion != buildinfo.Version || req.Arch == "" || len(req.SchemaVersions) != 1 {
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
	waitFor(t, func() bool { return checkins(g) == 1 })
	// A trigger right after a check-in waits for the one-minute gap; advance the clock past it.
	offset.Store(int64(TriggerMinGap))
	trig <- struct{}{}
	waitFor(t, func() bool { return checkins(g) == 2 })
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

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within 5 s")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
