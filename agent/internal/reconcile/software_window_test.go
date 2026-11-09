package reconcile_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile/fakesys"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// nightly is a window of every weekday night, 22:00 to 01:00 in Berlin.
var nightly = bundle.SoftwareWindow{Days: []int{1, 2, 3, 4, 5}, StartMinute: 22 * 60, DurationMinutes: 180, Timezone: "Europe/Berlin"}

func windowedResource(t *testing.T, windows []bundle.SoftwareWindow, sources []bundle.SoftwareSource, pkgs ...bundle.SoftwarePackage) bundle.Resource {
	t.Helper()
	s := bundle.SoftwareSpec{Sources: sources, Packages: pkgs, Windows: windows}
	if err := bundle.ValidateSoftware(s); err != nil {
		t.Fatal(err)
	}
	r, err := bundle.SoftwareResource(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// clock sets the reconciler's clock to *now.
func clock(s *reconcile.Software, at time.Time) *time.Time {
	now := at
	s.Now = func() time.Time { return now }
	return &now
}

func berlin(t *testing.T) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skip("no Europe/Berlin zone on this host")
	}
	return loc
}

// TestSoftwareOutsideWindow (plan M13c decision 6, §3.7 "Deferral by window"): outside the window an installation and
// a removal of the policy wait as pending/outside_window while the source files are written; the first pass inside the
// window executes both.
func TestSoftwareOutsideWindow(t *testing.T) {
	sys, s, events, _ := softwareFixture(t)
	ctx := context.Background()
	sys.Packages["vim"], sys.Versions["vim"] = true, "9.1"
	now := clock(s, time.Date(2026, 11, 10, 14, 0, 0, 0, berlin(t))) // Tuesday afternoon
	r := windowedResource(t, []bundle.SoftwareWindow{nightly}, []bundle.SoftwareSource{vendorSource(t)}, required("nano", "vendor"),
		bundle.SoftwarePackage{Package: "vim", Intent: bundle.SoftwareUninstall, CatalogEntryID: otherEntry})
	if res := s.Apply(ctx, r); res.Status == reconcile.Error {
		t.Fatalf("apply outside the window %+v", res)
	}
	if slices.ContainsFunc(aptCalls(sys), func(c string) bool { return strings.Contains(c, "install") || strings.Contains(c, "remove") }) {
		t.Fatalf("apt ran outside the window: %q", aptCalls(sys))
	}
	if sys.Files[vendorList] == nil || sys.Files[vendorKey] == nil {
		t.Fatal("the source files waited for the window")
	}
	for _, pkg := range []string{"nano", "vim"} {
		if it := status(t, s, pkg); it.State != protocol.SoftwareStatePending || it.Reason != protocol.SoftwareOutsideWindow {
			t.Fatalf("%s outside the window: %+v", pkg, it)
		}
	}
	if sys.Packages["nano"] || !sys.Packages["vim"] || len(*events) != 0 {
		t.Fatalf("packages changed outside the window, events %+v", *events)
	}

	*now = time.Date(2026, 11, 10, 23, 30, 0, 0, berlin(t))
	if res := s.Apply(ctx, r); res.Status != reconcile.Changed {
		t.Fatalf("apply inside the window %+v", res)
	}
	if !sys.Packages["nano"] || sys.Packages["vim"] {
		t.Fatalf("inside the window: calls %q", aptCalls(sys))
	}
	if it := status(t, s, "nano"); it.State != protocol.SoftwareStateInstalled {
		t.Fatalf("nano %+v", it)
	}
	if it := status(t, s, "vim"); it.State != protocol.SoftwareStateAbsent {
		t.Fatalf("vim %+v", it)
	}
}

// TestSoftwareUrgentIgnoresWindow (plan M13c decision 7): an urgent package runs outside the window, the others wait;
// an urgent removal still waits for the server (design contract 8).
func TestSoftwareUrgentIgnoresWindow(t *testing.T) {
	sys, s, _, reachable := softwareFixture(t)
	ctx := context.Background()
	sys.Packages["vim"], sys.Versions["vim"] = true, "9.1"
	clock(s, time.Date(2026, 11, 10, 14, 0, 0, 0, berlin(t)))
	urgentNano := required("nano", "")
	urgentNano.Urgent = true
	urgentVim := bundle.SoftwarePackage{Package: "vim", Intent: bundle.SoftwareForbid, CatalogEntryID: otherEntry, Urgent: true}
	r := windowedResource(t, []bundle.SoftwareWindow{nightly}, nil, urgentNano, required("curl", ""), urgentVim)
	*reachable = false
	s.Apply(ctx, r)
	if !sys.Packages["nano"] || sys.Packages["curl"] || !sys.Packages["vim"] {
		t.Fatalf("offline urgent pass: calls %q", aptCalls(sys))
	}
	if it := status(t, s, "curl"); it.Reason != protocol.SoftwareOutsideWindow {
		t.Fatalf("curl %+v", it)
	}
	if it := status(t, s, "vim"); it.Reason != protocol.SoftwareDeferredOffline {
		t.Fatalf("an urgent removal while offline %+v", it)
	}
	*reachable = true
	s.Apply(ctx, r)
	if sys.Packages["vim"] || sys.Packages["curl"] {
		t.Fatalf("online urgent pass: calls %q", aptCalls(sys))
	}
}

// TestSoftwareWindowOnDSTDay: the zone decides the local time: a window from Saturday 22:00 for six hours spans the
// night the clocks spring forward and is still open at 04:30 CEST, closed at 05:30.
func TestSoftwareWindowOnDSTDay(t *testing.T) {
	sys, s, _, _ := softwareFixture(t)
	loc := berlin(t)
	night := bundle.SoftwareWindow{Days: []int{6}, StartMinute: 22 * 60, DurationMinutes: 360, Timezone: "Europe/Berlin"}
	r := windowedResource(t, []bundle.SoftwareWindow{night}, nil, required("nano", ""))
	now := clock(s, time.Date(2026, 3, 29, 5, 30, 0, 0, loc))
	s.Apply(context.Background(), r)
	if sys.Packages["nano"] {
		t.Fatal("installed after the window")
	}
	*now = time.Date(2026, 3, 29, 4, 30, 0, 0, loc)
	s.Apply(context.Background(), r)
	if !sys.Packages["nano"] {
		t.Fatalf("not installed inside the window: %q", aptCalls(sys))
	}
}

// TestSoftwareWindowTimezoneUnknown (§3.8 L3): a zone the device does not know is evaluated in UTC, and the status
// note names it.
func TestSoftwareWindowTimezoneUnknown(t *testing.T) {
	sys, s, _, _ := softwareFixture(t)
	mars := bundle.SoftwareWindow{Days: []int{2}, StartMinute: 12 * 60, DurationMinutes: 60, Timezone: "Mars/Olympus_Mons"}
	r := windowedResource(t, []bundle.SoftwareWindow{mars}, nil, required("nano", ""))
	now := clock(s, time.Date(2026, 11, 10, 14, 0, 0, 0, time.UTC))
	res := s.Apply(context.Background(), r)
	if sys.Packages["nano"] || !strings.Contains(res.Message, "window_timezone_unknown: Mars/Olympus_Mons") {
		t.Fatalf("outside the UTC fallback: %+v", res)
	}
	*now = time.Date(2026, 11, 10, 12, 30, 0, 0, time.UTC)
	if res := s.Apply(context.Background(), r); !sys.Packages["nano"] || res.Status != reconcile.Changed {
		t.Fatalf("inside the UTC fallback: %+v", res)
	}
}

// TestSoftwareSelfServiceIgnoresWindow (plan M13c decision 6): a user's own installation is never deferred.
func TestSoftwareSelfServiceIgnoresWindow(t *testing.T) {
	sys, s, _, _ := softwareFixture(t)
	clock(s, time.Date(2026, 11, 10, 14, 0, 0, 0, berlin(t)))
	sp := bundle.SoftwareSpec{Packages: []bundle.SoftwarePackage{availableApt("code")}, Windows: []bundle.SoftwareWindow{nightly}}
	if res := s.InstallOne(context.Background(), sp, availableApt("code"), 200001); res.Failed() || !sys.Packages["code"] {
		t.Fatalf("self-service outside the window: %+v", res)
	}
}

// TestFlatpakOutsideWindow: a required Flatpak application and a forbidden one wait outside the window while the mask
// is still written; an urgent application installs.
func TestFlatpakOutsideWindow(t *testing.T) {
	sys, s, _, _ := flatpakFixture(t)
	ctx := context.Background()
	sys.FlatpakSystem = fakesys.NewFlatpakInstallation()
	sys.FlatpakSystem.Apps["org.example.Old"] = "1.0"
	now := clock(s, time.Date(2026, 11, 10, 14, 0, 0, 0, berlin(t)))
	gimpApp := flatpakApp(gimp, bundle.SoftwareRequired, "flathub", bundle.SoftwareScopeSystem)
	old := bundle.SoftwarePackage{FlatpakRef: "org.example.Old", Intent: bundle.SoftwareForbid, CatalogEntryID: nanoEntry}
	r := windowedResource(t, []bundle.SoftwareWindow{nightly}, []bundle.SoftwareSource{flathubSource(t)}, flatpakRuntime(), gimpApp, old)
	s.Apply(ctx, r)
	if len(flatpakCalls(sys, "flatpak install")) != 0 || len(flatpakCalls(sys, "flatpak uninstall")) != 0 {
		t.Fatalf("flatpak ran outside the window: %q", sys.FlatpakCalls)
	}
	if !sys.FlatpakSystem.Masks["org.example.Old"] || sys.FlatpakSystem.Remotes[flathubRemote] == nil {
		t.Fatal("the mask and the remote waited for the window")
	}
	for _, key := range []string{gimpItem, "flatpak:org.example.Old"} {
		if it := status(t, s, key); it.State != protocol.SoftwareStatePending || it.Reason != protocol.SoftwareOutsideWindow {
			t.Fatalf("%s %+v", key, it)
		}
	}

	gimpApp.Urgent = true
	r = windowedResource(t, []bundle.SoftwareWindow{nightly}, []bundle.SoftwareSource{flathubSource(t)}, flatpakRuntime(), gimpApp, old)
	s.Apply(ctx, r)
	if _, ok := sys.FlatpakSystem.Apps[gimp]; !ok {
		t.Fatalf("urgent application not installed: %q", sys.FlatpakCalls)
	}
	if _, ok := sys.FlatpakSystem.Apps["org.example.Old"]; !ok {
		t.Fatal("a non-urgent removal ran outside the window")
	}
	*now = time.Date(2026, 11, 10, 22, 5, 0, 0, berlin(t))
	s.Apply(ctx, r)
	if _, ok := sys.FlatpakSystem.Apps["org.example.Old"]; ok {
		t.Fatalf("not removed inside the window: %q", sys.FlatpakCalls)
	}
}
