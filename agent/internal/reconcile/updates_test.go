package reconcile_test

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile/fakesys"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// updatesFixture is a device with unattended-upgrades and the distribution's apt timers.
func updatesFixture(t *testing.T) (*fakesys.System, *reconcile.Updates, *[]event) {
	t.Helper()
	sys := fakesys.New()
	sys.Packages["unattended-upgrades"] = true
	sys.Units["apt-daily.timer"] = &fakesys.Unit{State: "enabled", Active: true}
	sys.Units["apt-daily-upgrade.timer"] = &fakesys.Unit{State: "enabled", Active: true}
	var events []event
	u := &reconcile.Updates{Sys: sys, Events: &reconcile.Events{Emit: func(typ string, data any) {
		b, _ := json.Marshal(data)
		events = append(events, event{typ, string(b)})
	}}}
	return sys, u, &events
}

func updatesResource(t *testing.T, change func(*bundle.UpdatesSpec)) bundle.Resource {
	t.Helper()
	s := bundle.UpdatesSpec{SecurityDailyAt: "03:00", RegularSchedule: "Sat 04:00", RegularUpdatesEnabled: true, MaxRandomDelayMin: 60}
	if change != nil {
		change(&s)
	}
	r, err := bundle.UpdatesResource(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func ver(v string) *string { return &v }

func fileContent(t *testing.T, sys *fakesys.System, path string) string {
	t.Helper()
	f := sys.Files[path]
	if f == nil {
		t.Fatalf("%s missing", path)
	}
	return string(f.Data)
}

func TestUpdatesApply(t *testing.T) {
	sys, u, _ := updatesFixture(t)
	ctx := context.Background()
	r := updatesResource(t, func(s *bundle.UpdatesSpec) {
		s.Holds = []bundle.Hold{{Package: "libstdc++6"}, {Package: "openssl", Version: ver("3.0.13-0ubuntu3.4")}}
	})
	if res := u.Apply(ctx, r); res.Status != reconcile.Changed {
		t.Fatalf("apply %+v", res)
	}
	unattended := fileContent(t, sys, reconcile.UnattendedConf)
	for _, want := range []string{
		"#clear Unattended-Upgrade::Allowed-Origins;", "#clear Unattended-Upgrade::Origins-Pattern;",
		`"${distro_id}:${distro_codename}-security";`, `"^libstdc[+][+]6$";`, `"^openssl$";`,
		`Unattended-Upgrade::Automatic-Reboot "false";`,
	} {
		if !strings.Contains(unattended, want) {
			t.Errorf("unattended configuration lacks %q:\n%s", want, unattended)
		}
	}
	if dropIn := fileContent(t, sys, reconcile.UpgradeTimerDropIn); !strings.Contains(dropIn, "OnCalendar=\nOnCalendar=*-*-* 03:00\nRandomizedDelaySec=60m\n") {
		t.Errorf("drop-in:\n%s", dropIn)
	}
	if pins := fileContent(t, sys, reconcile.PinFile); !strings.Contains(pins, "Package: openssl\nPin: version 3.0.13-0ubuntu3.4\nPin-Priority: 1001\n") ||
		strings.Contains(pins, "libstdc") {
		t.Errorf("pins:\n%s", pins)
	}
	if timer := fileContent(t, sys, reconcile.RegularTimer); !strings.Contains(timer, "OnCalendar=Sat 04:00\nRandomizedDelaySec=60m\nPersistent=true\n") {
		t.Errorf("timer:\n%s", timer)
	}
	if svc := fileContent(t, sys, reconcile.RegularService); !strings.Contains(svc, "ExecStart=/opt/paddock/agent/current/paddockd updates run\n") {
		t.Errorf("service:\n%s", svc)
	}
	if !sys.Held["libstdc++6"] || sys.Held["openssl"] {
		t.Errorf("apt-mark holds %v", sys.Held)
	}
	if u := sys.Units[reconcile.RegularTimerUnit]; u == nil || u.State != "enabled" || !u.Active {
		t.Errorf("regular timer %+v", u)
	}
	calls := sys.TakeCalls()
	for _, want := range []string{"systemctl daemon-reload", "apt-mark hold -- libstdc++6", "systemctl enable paddock-updates.timer",
		"systemctl restart apt-daily-upgrade.timer"} {
		if !slices.Contains(calls, want) {
			t.Errorf("calls %v lack %q", calls, want)
		}
	}
	// Idempotent: nothing to plan, nothing to do.
	if changes, err := u.Plan(ctx, r); err != nil || len(changes) != 0 {
		t.Fatalf("plan after apply %v %v", changes, err)
	}
	if res := u.Apply(ctx, r); res.Status != reconcile.OK {
		t.Fatalf("second apply %+v", res)
	}
	if calls := sys.TakeCalls(); len(calls) != 0 {
		t.Errorf("second apply changed %v", calls)
	}
}

func TestUpdatesReleasesOnlyItsOwnHolds(t *testing.T) {
	sys, u, _ := updatesFixture(t)
	ctx := context.Background()
	sys.Held["zsh"] = true // held locally, not by Paddock
	u.Apply(ctx, updatesResource(t, func(s *bundle.UpdatesSpec) {
		s.Holds = []bundle.Hold{{Package: "curl"}, {Package: "openssl", Version: ver("3.0.13")}}
	}))
	if !sys.Held["curl"] {
		t.Fatal("curl not held")
	}
	sys.TakeCalls()
	res := u.Apply(ctx, updatesResource(t, nil))
	if res.Status != reconcile.Changed || sys.Held["curl"] || !sys.Held["zsh"] {
		t.Fatalf("after removing the holds: %+v, held %v", res, sys.Held)
	}
	if _, ok := sys.Files[reconcile.PinFile]; ok {
		t.Error("pin file kept without versioned holds")
	}
	if unattended := fileContent(t, sys, reconcile.UnattendedConf); strings.Contains(unattended, "curl") || strings.Contains(unattended, "openssl") {
		t.Errorf("blacklist kept released packages:\n%s", unattended)
	}
	if calls := sys.TakeCalls(); !slices.Contains(calls, "apt-mark unhold -- curl") || slices.ContainsFunc(calls, func(c string) bool { return strings.Contains(c, "zsh") }) {
		t.Errorf("calls %v", calls)
	}
}

func TestUpdatesRegularDisabled(t *testing.T) {
	sys, u, _ := updatesFixture(t)
	ctx := context.Background()
	u.Apply(ctx, updatesResource(t, nil))
	sys.TakeCalls()
	res := u.Apply(ctx, updatesResource(t, func(s *bundle.UpdatesSpec) { s.RegularUpdatesEnabled = false; s.RegularSchedule = "Mon,Thu 12:30" }))
	if timer := sys.Units[reconcile.RegularTimerUnit]; res.Status != reconcile.Changed || timer.State != "disabled" || timer.Active {
		t.Fatalf("%+v timer %+v", res, timer)
	}
	if calls := sys.TakeCalls(); slices.Contains(calls, "systemctl restart paddock-updates.timer") {
		t.Errorf("a disabled timer was restarted: %v", calls)
	}
}

func TestUpdatesDriftIsRestoredAndReported(t *testing.T) {
	sys, u, events := updatesFixture(t)
	ctx := context.Background()
	r := updatesResource(t, nil)
	u.Apply(ctx, r)
	sys.Files[reconcile.UnattendedConf].Data = []byte("Unattended-Upgrade::Allowed-Origins { \"*\"; };\n")
	if changes, err := u.Plan(ctx, r); err != nil || !slices.Equal(changes, []string{"file " + reconcile.UnattendedConf}) {
		t.Fatalf("plan %v %v", changes, err)
	}
	if res := u.Apply(ctx, r); res.Status != reconcile.Changed {
		t.Fatalf("%+v", res)
	}
	if len(*events) != 1 || (*events)[0].typ != protocol.EventTamperProtectedFileChanged || !strings.Contains((*events)[0].data, "52paddock") {
		t.Fatalf("events %+v", *events)
	}
}

func TestUpdatesWithoutUnattendedUpgrades(t *testing.T) {
	sys, u, _ := updatesFixture(t)
	delete(sys.Packages, "unattended-upgrades")
	res := u.Apply(context.Background(), updatesResource(t, nil))
	if res.Status != reconcile.Error || !strings.Contains(res.Message, "unattended-upgrades is not installed") {
		t.Fatalf("%+v", res)
	}
	if _, ok := sys.Files[reconcile.RegularTimer]; !ok {
		t.Error("the rest was not applied")
	}
}

func TestUpdatesRejectsInvalidSpec(t *testing.T) {
	_, u, _ := updatesFixture(t)
	r := updatesResource(t, func(s *bundle.UpdatesSpec) { s.Holds = []bundle.Hold{{Package: "-oAPT::x"}} })
	if res := u.Apply(context.Background(), r); res.Status != reconcile.Error {
		t.Fatalf("%+v", res)
	}
	r = updatesResource(t, func(s *bundle.UpdatesSpec) { s.RegularSchedule = "Sat 04:00\nExecStart=/bin/sh" })
	if _, err := u.Plan(context.Background(), r); err == nil {
		t.Fatal("plan accepted an injected schedule")
	}
}
