package agent

import (
	"context"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile/fakesys"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/agent/internal/testgw"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

const (
	fleetToken  = "0b6e8a0c-1d2f-4a3b-9c4d-5e6f7a8b9c0d"
	fleetToken2 = "7f1e2d3c-4b5a-4968-8776-655443322110"
)

// lastCheckin returns the request of the gateway's latest check-in.
func lastCheckin(t *testing.T, g *testgw.Gateway) protocol.CheckinRequest {
	t.Helper()
	g.Mu.Lock()
	defer g.Mu.Unlock()
	if len(g.Checkins) == 0 {
		t.Fatal("no check-in")
	}
	return g.Checkins[len(g.Checkins)-1].Req
}

// TestCheckinFleetDeviceToken (ADR 0057, H3): fleetd's device token is sent when valid and new, not again after a
// check-in that returned HTTP 200, again after a failed check-in and after a change, and never when missing or
// malformed.
func TestCheckinFleetDeviceToken(t *testing.T) {
	g := testgw.New(t)
	a := newAgent(t, g)
	sys := fakesys.New()
	a.d.Sys = sys
	ctx := context.Background()
	sent := func(step string, want string) {
		t.Helper()
		a.Cycle(ctx)
		if got := lastCheckin(t, g).FleetDeviceToken; got != want {
			t.Fatalf("%s: token %q, want %q", step, got, want)
		}
	}
	sent("missing", "")
	sys.Files[reconcile.FleetdDeviceTokenFile] = &fakesys.File{Data: []byte(fleetToken + "\n")}
	sent("new", fleetToken)
	sent("acknowledged", "")
	sys.Files[reconcile.FleetdDeviceTokenFile] = &fakesys.File{Data: []byte(fleetToken2)}
	g.Mu.Lock()
	g.CheckinFail = 503
	g.Mu.Unlock()
	sent("changed, check-in fails", fleetToken2)
	g.Mu.Lock()
	g.CheckinFail = 0
	g.Mu.Unlock()
	sent("after the failed check-in", fleetToken2)
	sent("acknowledged again", "")
	for name, data := range map[string]string{
		"upper case": "0B6E8A0C-1D2F-4A3B-9C4D-5E6F7A8B9C0D", "trailing garbage": fleetToken + "x",
		"two lines": fleetToken + "\n" + fleetToken2, "empty": "",
	} {
		sys.Files[reconcile.FleetdDeviceTokenFile] = &fakesys.File{Data: []byte(data)}
		sent(name, "")
	}
}

// TestInventoryEnrollmentResetAnnounced (ADR 0057, H14): the announced reset is persisted, survives an agent restart,
// rides on every check-in until one carried a token written after the reset was acknowledged, and ends after 24 hours.
func TestInventoryEnrollmentResetAnnounced(t *testing.T) {
	g := testgw.New(t)
	a := newAgent(t, g)
	sys := fakesys.New()
	now := time.Now().UTC().Truncate(time.Second)
	reset := now.Add(-time.Minute)
	if err := a.announceFleetReset(reset); err != nil {
		t.Fatal(err)
	}
	if st, err := state.Load(a.d.Layout.State()); err != nil || st.FleetResetAt == nil || !st.FleetResetAt.Equal(reset) {
		t.Fatalf("persisted %+v %v", st.FleetResetAt, err)
	}

	restarted, err := New(a.d)
	if err != nil {
		t.Fatal(err)
	}
	a = restarted
	a.d.Sys = sys
	a.d.Now = func() time.Time { return now }
	ctx := context.Background()
	announced := func(step string, want bool) {
		t.Helper()
		a.Cycle(ctx)
		if got := lastCheckin(t, g).FleetEnrollmentResetAt; (got != nil) != want || want && !got.Equal(reset) {
			t.Fatalf("%s: announced %v, want %v", step, got, want)
		}
	}
	announced("after the restart, no token", true)
	sys.Files[reconcile.FleetdDeviceTokenFile] = &fakesys.File{Data: []byte(fleetToken), ModTime: reset.Add(-time.Hour)}
	announced("token from before the reset", true)
	sys.Files[reconcile.FleetdDeviceTokenFile] = &fakesys.File{Data: []byte(fleetToken2), ModTime: reset.Add(time.Second)}
	announced("new token", true)
	announced("acknowledged", false)
	if st, err := state.Load(a.d.Layout.State()); err != nil || st.FleetResetAt != nil {
		t.Fatalf("still persisted %+v %v", st.FleetResetAt, err)
	}

	reset = now.Add(-fleetResetAnnounce + time.Second)
	if err := a.announceFleetReset(reset); err != nil {
		t.Fatal(err)
	}
	announced("just inside 24 hours", true)
	a.d.Now = func() time.Time { return now.Add(time.Second) }
	announced("24 hours", false)
}
