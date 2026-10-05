package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/paddock-mdm/paddock/agent/internal/apply"
	"github.com/paddock-mdm/paddock/agent/internal/reconcile"
	"github.com/paddock-mdm/paddock/agent/internal/reconcile/fakesys"
	"github.com/paddock-mdm/paddock/agent/internal/state"
	"github.com/paddock-mdm/paddock/agent/internal/testgw"
	"github.com/paddock-mdm/paddock/pkg/bundle"
	"github.com/paddock-mdm/paddock/pkg/protocol"
)

// withSystem gives the agent an applier on a fake system with timesyncd running.
func withSystem(t *testing.T, a *Agent) *fakesys.System {
	t.Helper()
	sys := fakesys.New()
	sys.Packages["systemd-timesyncd"] = true
	sys.Units["systemd-timesyncd.service"] = &fakesys.Unit{State: "enabled", Active: true}
	sys.NTP = true
	m, err := reconcile.LoadManaged(a.d.Layout.Managed())
	if err != nil {
		t.Fatal(err)
	}
	a.d.Events = &reconcile.Events{Emit: a.event}
	a.d.Applier = apply.New(sys, m, a.d.Events)
	a.d.Sys = sys
	return sys
}

func testBundle(t *testing.T, version int64, device string, content string) bundle.Bundle {
	t.Helper()
	tr, _ := bundle.TimeResource(bundle.TimeSpec{NTP: true})
	fr, _ := bundle.FileResource(bundle.FileSpec{Path: "/etc/motd", Mode: "0644", Owner: "root", Group: "root", Content: content})
	return bundle.Bundle{
		SchemaVersion: 1, BundleVersion: version, DeviceID: device, OrganizationID: testgw.OrgID,
		IssuedAt: time.Now(), Resources: []bundle.Resource{fr, tr},
	}
}

func eventsOf(g *testgw.Gateway, typ string) []protocol.Event {
	g.Mu.Lock()
	defer g.Mu.Unlock()
	var out []protocol.Event
	for _, e := range g.Events {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

func TestBundleApplyAndEvents(t *testing.T) {
	ctx := context.Background()
	g := testgw.New(t)
	a := newAgent(t, g)
	sys := withSystem(t, a)
	g.OfferBundle(testgw.SignedBundleOffer(t, testBundle(t, 4, testgw.DeviceID, "hello\n")))

	a.Cycle(ctx)
	if string(sys.Files["/etc/motd"].Data) != "hello\n" || a.st.AppliedBundleVersion != 4 {
		t.Fatalf("bundle not applied: applied %d", a.st.AppliedBundleVersion)
	}
	applied := eventsOf(g, protocol.EventBundleApplied)
	if len(applied) != 1 || string(applied[0].Data) != `{"version":4,"changed":1,"errors":[]}` {
		t.Fatalf("bundle.applied events %+v", applied)
	}
	if pending, _ := a.d.Spool.Pending(); len(pending) != 0 {
		t.Fatalf("accepted events still spooled: %+v", pending)
	}
	st, _ := state.Load(a.d.Layout.State())
	if st.AppliedBundleVersion != 4 || st.EventSeq != 1 {
		t.Fatalf("persisted state %+v", st)
	}
	if _, err := os.Stat(a.d.Layout.Bundle()); err != nil {
		t.Fatalf("bundle not cached: %v", err)
	}

	// The next check-ins offer the same version: nothing is downloaded or applied again.
	sys.TakeCalls()
	a.Cycle(ctx)
	if calls := sys.TakeCalls(); len(calls) != 0 || len(eventsOf(g, protocol.EventBundleApplied)) != 1 {
		t.Fatalf("applied again: %v", calls)
	}

	// A restarted agent picks up the cached bundle for the drift loop.
	b, err := New(a.d)
	if err != nil || b.current == nil || b.current.BundleVersion != 4 {
		t.Fatalf("restart: current %+v, %v", b.current, err)
	}
}

func TestBundleRejected(t *testing.T) {
	ctx := context.Background()
	g := testgw.New(t)
	a := newAgent(t, g)
	sys := withSystem(t, a)
	g.OfferBundle(testgw.SignedBundleOffer(t, testBundle(t, 2, "0190f000-0000-7000-8000-0000000000ee", "x")))
	a.Cycle(ctx)
	a.Cycle(ctx)
	rejected := eventsOf(g, protocol.EventBundleRejected)
	if len(rejected) != 1 || string(rejected[0].Data) != `{"reason":"wrong_device","version":2}` {
		t.Fatalf("bundle.rejected events (want exactly one) %+v", rejected)
	}
	if a.st.AppliedBundleVersion != 0 || len(sys.TakeCalls()) != 0 {
		t.Fatal("a rejected bundle changed state or system")
	}

	env, _ := testgw.SignedBundle(t, testBundle(t, 3, testgw.DeviceID, "x"))
	g.OfferBundle(3, env, "0000")
	a.Cycle(ctx)
	if r := eventsOf(g, protocol.EventBundleRejected); len(r) != 2 || string(r[1].Data) != `{"reason":"sha256_mismatch","version":3}` {
		t.Fatalf("sha256 mismatch: %+v", r)
	}
}

// TestBundleWithUnknownResourceType: a bundle with a resource type the agent has no reconciler for is rejected as a
// whole; none of its known resources is applied (plan M3b decision 4).
func TestBundleWithUnknownResourceType(t *testing.T) {
	ctx := context.Background()
	g := testgw.New(t)
	a := newAgent(t, g)
	sys := withSystem(t, a)
	b := testBundle(t, 2, testgw.DeviceID, "x")
	b.SchemaVersion = bundle.SchemaVersion2
	b.Resources = append(b.Resources, bundle.Resource{ID: "firewall", Type: "firewall", Spec: json.RawMessage(`{}`)})
	g.OfferBundle(testgw.SignedBundleOffer(t, b))
	a.Cycle(ctx)
	rejected := eventsOf(g, protocol.EventBundleRejected)
	if len(rejected) != 1 || string(rejected[0].Data) != `{"reason":"unknown_resource_type","version":2}` {
		t.Fatalf("bundle.rejected events %+v", rejected)
	}
	if a.st.AppliedBundleVersion != 0 || len(sys.TakeCalls()) != 0 {
		t.Fatal("a bundle with an unknown resource type was applied partially")
	}
}

func TestEventsStaySpooledUntilAccepted(t *testing.T) {
	ctx := context.Background()
	g := testgw.New(t)
	a := newAgent(t, g)
	withSystem(t, a)
	g.EventsFail = http.StatusServiceUnavailable
	g.OfferBundle(testgw.SignedBundleOffer(t, testBundle(t, 1, testgw.DeviceID, "x")))
	a.Cycle(ctx)
	if pending, _ := a.d.Spool.Pending(); len(pending) != 1 {
		t.Fatalf("spool %+v", pending)
	}
	g.Mu.Lock()
	g.EventsFail = 0
	g.Mu.Unlock()
	a.Cycle(ctx)
	a.Cycle(ctx)
	if pending, _ := a.d.Spool.Pending(); len(pending) != 0 || len(eventsOf(g, protocol.EventBundleApplied)) != 1 {
		t.Fatalf("spool %+v, sent %v", pending, g.EventTypes())
	}
}

func TestDriftLoop(t *testing.T) {
	ctx := context.Background()
	g := testgw.New(t)
	a := newAgent(t, g)
	sys := withSystem(t, a)
	g.OfferBundle(testgw.SignedBundleOffer(t, testBundle(t, 1, testgw.DeviceID, "managed\n")))
	a.Cycle(ctx)
	a.drift(ctx)
	if pending, _ := a.d.Spool.Pending(); len(pending) != 0 {
		t.Fatalf("drift without changes spooled %+v", pending)
	}
	sys.Files["/etc/motd"].Data = []byte("local edit\n")
	sys.NTP = false
	a.drift(ctx)
	if string(sys.Files["/etc/motd"].Data) != "managed\n" || !sys.NTP {
		t.Fatal("drift not corrected")
	}
	pending, _ := a.d.Spool.Pending()
	if len(pending) != 1 || pending[0].Type != protocol.EventConfigDriftCorrected {
		t.Fatalf("spool %+v", pending)
	}
	var data struct {
		ResourceIDs []string `json:"resource_ids"`
	}
	_ = json.Unmarshal(pending[0].Data, &data)
	if !slices.Equal(data.ResourceIDs, []string{"time", "file:/etc/motd"}) {
		t.Fatalf("resource_ids %v", data.ResourceIDs)
	}
}

// TestSessionLogins: a directory user's session is reported once per 24 h with username and time only; local
// accounts and the greeter are never reported (plan M3b decision 11).
func TestSessionLogins(t *testing.T) {
	ctx := context.Background()
	g := testgw.New(t)
	a := newAgent(t, g)
	sys := withSystem(t, a)
	sys.Files["/etc/passwd"] = &fakesys.File{Data: []byte("paddock:x:1000:1000::/home/paddock:/bin/bash\n"), Mode: 0o644}
	// Himmelblau lists users of its domain by their short name.
	sys.Sessions = []fakesys.Session{
		{ID: "c1", UID: 60578, User: "gdm-greeter", Class: "greeter"},
		{ID: "4", UID: 1000, User: "paddock", Class: "user"},
		{ID: "7", UID: 811622788, User: "dave", Class: "user"},
	}
	now := time.Date(2026, 10, 4, 8, 0, 0, 0, time.UTC)
	a.d.Now = func() time.Time { return now }
	a.trackSessions(ctx)
	if pending, _ := a.d.Spool.Pending(); len(pending) != 0 {
		t.Fatalf("reported without a login resource: %+v", pending)
	}
	login, err := bundle.LoginResource(bundle.LoginSpec{Provider: bundle.ProviderHimmelblau, Himmelblau: bundle.HimmelblauSpec{Domain: "acme.test"}})
	if err != nil {
		t.Fatal(err)
	}
	a.current = &bundle.Bundle{Resources: []bundle.Resource{login}}
	a.trackSessions(ctx)
	a.trackSessions(ctx)
	pending, _ := a.d.Spool.Pending()
	if len(pending) != 1 || pending[0].Type != protocol.EventSessionLogin || string(pending[0].Data) != `{"username":"dave@acme.test","at":"2026-10-04T08:00:00Z"}` {
		t.Fatalf("spool %+v", pending)
	}
	st, _ := state.Load(a.d.Layout.State())
	if !st.SessionsReported["dave"].Equal(now) {
		t.Fatalf("persisted %v", st.SessionsReported)
	}
	now = now.Add(24 * time.Hour)
	a.trackSessions(ctx)
	if pending, _ := a.d.Spool.Pending(); len(pending) != 2 {
		t.Fatalf("not reported again after 24 h: %+v", pending)
	}
}

// TestCheckinReportsSudoFlavor: the check-in health carries the active sudo implementation.
func TestCheckinReportsSudoFlavor(t *testing.T) {
	ctx := context.Background()
	g := testgw.New(t)
	a := newAgent(t, g)
	sys := withSystem(t, a)
	a.Cycle(ctx)
	sys.Links = map[string]string{"/usr/bin/sudo": "/usr/lib/cargo/bin/sudo", "/usr/sbin/visudo": "/usr/lib/cargo/bin/visudo"}
	sys.SudoVersions = map[string]string{"/usr/lib/cargo/bin/sudo": "sudo-rs 0.2.13-0ubuntu1.2\n"}
	a.Cycle(ctx)
	var flavors []string
	for _, c := range g.Checkins {
		var h struct {
			SudoFlavor string `json:"sudo_flavor"`
		}
		if err := json.Unmarshal(c.Req.Health, &h); err != nil {
			t.Fatalf("health %s: %v", c.Req.Health, err)
		}
		flavors = append(flavors, h.SudoFlavor)
	}
	if !slices.Equal(flavors, []string{"classic", "sudo-rs"}) {
		t.Fatalf("sudo flavors %v", flavors)
	}
}
