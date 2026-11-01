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

func watchFixture(t *testing.T) (*fakesys.System, *reconcile.Watch, *[]event) {
	t.Helper()
	sys := fakesys.New()
	sys.Units["wazuh-agent.service"] = &fakesys.Unit{State: "enabled", Active: true}
	sys.Units["falcon-sensor.service"] = &fakesys.Unit{State: "disabled", Active: true}
	var events []event
	emit := func(typ string, data any) {
		b, err := json.Marshal(data)
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, event{typ, string(b)})
	}
	return sys, &reconcile.Watch{Sys: sys, Events: &reconcile.Events{Emit: emit}}, &events
}

func watchResource(t *testing.T, units ...string) bundle.Resource {
	t.Helper()
	r, err := bundle.WatchResource(bundle.WatchSpec{Units: units})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func stopped(unit, state string) event {
	return event{protocol.EventTamperServiceStopped, `{"unit":"` + unit + `","state":"` + state + `"}`}
}

// applyWatch applies r and fails unless the result is OK: reporting is not a change.
func applyWatch(t *testing.T, w *reconcile.Watch, r bundle.Resource) {
	t.Helper()
	if res := w.Apply(context.Background(), r); res.Status != reconcile.OK {
		t.Fatalf("apply: %+v", res)
	}
}

// TestWatchReportsOncePerStop (plan M9 decision 40): a watched unit that stops is reported once with its state, again
// only after it ran in between; the reconciler never changes a unit.
func TestWatchReportsOncePerStop(t *testing.T) {
	ctx := context.Background()
	sys, w, events := watchFixture(t)
	r := watchResource(t, "falcon-sensor.service", "wazuh-agent.service")
	if w.Type() != bundle.TypeWatch {
		t.Fatalf("type %q", w.Type())
	}

	applyWatch(t, w, r)
	if got := takeEvents(events); len(got) != 0 {
		t.Fatalf("running units reported: %v", got)
	}
	if plan, err := w.Plan(ctx, r); err != nil || len(plan) != 0 {
		t.Fatalf("plan of running units %v (%v)", plan, err)
	}

	sys.Units["wazuh-agent.service"].Active = false
	if plan, err := w.Plan(ctx, r); err != nil || !slices.Equal(plan, []string{"report wazuh-agent.service inactive"}) {
		t.Fatalf("plan %v (%v)", plan, err)
	}
	applyWatch(t, w, r)
	if got := takeEvents(events); !slices.Equal(got, []event{stopped("wazuh-agent.service", "inactive")}) {
		t.Fatalf("events %v", got)
	}

	// Still stopped: nothing to plan, nothing to report.
	if plan, err := w.Plan(ctx, r); err != nil || len(plan) != 0 {
		t.Fatalf("plan while still stopped %v (%v)", plan, err)
	}
	applyWatch(t, w, r)
	if got := takeEvents(events); len(got) != 0 {
		t.Fatalf("a second apply reported again: %v", got)
	}

	// Running again clears the report; the next stop is a second event.
	sys.Units["wazuh-agent.service"].Active = true
	if plan, err := w.Plan(ctx, r); err != nil || !slices.Equal(plan, []string{"clear wazuh-agent.service"}) {
		t.Fatalf("plan after restart %v (%v)", plan, err)
	}
	applyWatch(t, w, r)
	sys.Units["wazuh-agent.service"].Active = false
	applyWatch(t, w, r)
	if got := takeEvents(events); !slices.Equal(got, []event{stopped("wazuh-agent.service", "inactive")}) {
		t.Fatalf("events after the second stop %v", got)
	}

	if calls := sys.TakeCalls(); slices.ContainsFunc(calls, func(c string) bool { return strings.HasPrefix(c, "systemctl ") }) {
		t.Fatalf("the watch changed units: %v", calls)
	}
}

// TestWatchStates: a failed unit is reported as failed, an unknown unit as missing, a disabled or masked unit by its
// activity; the reconciler never starts, enables or unmasks one.
func TestWatchStates(t *testing.T) {
	sys, w, events := watchFixture(t)
	sys.Units["wazuh-agent.service"] = &fakesys.Unit{State: "enabled", Failed: true}
	sys.Units["falcon-sensor.service"] = &fakesys.Unit{State: "masked"}
	applyWatch(t, w, watchResource(t, "falcon-sensor.service", "gone.service", "wazuh-agent.service"))
	want := []event{
		stopped("falcon-sensor.service", "inactive"), stopped("gone.service", "missing"), stopped("wazuh-agent.service", "failed"),
	}
	if got := takeEvents(events); !slices.Equal(got, want) {
		t.Fatalf("events %v, want %v", got, want)
	}
	for _, c := range sys.TakeCalls() {
		for _, verb := range []string{"start", "stop", "restart", "enable", "disable", "mask", "unmask"} {
			if strings.HasPrefix(c, "systemctl "+verb+" ") {
				t.Fatalf("the watch ran %q", c)
			}
		}
	}
}

// TestWatchForgetsUnits: a unit that leaves the list is forgotten, so watching it again reports it again; Forget does
// the same for a bundle without watch section.
func TestWatchForgetsUnits(t *testing.T) {
	sys, w, events := watchFixture(t)
	sys.Units["wazuh-agent.service"].Active = false
	both := watchResource(t, "falcon-sensor.service", "wazuh-agent.service")
	applyWatch(t, w, both)
	applyWatch(t, w, watchResource(t, "falcon-sensor.service"))
	applyWatch(t, w, both)
	if got := takeEvents(events); !slices.Equal(got, []event{stopped("wazuh-agent.service", "inactive"), stopped("wazuh-agent.service", "inactive")}) {
		t.Fatalf("events %v", got)
	}
	w.Forget()
	applyWatch(t, w, both)
	if got := takeEvents(events); !slices.Equal(got, []event{stopped("wazuh-agent.service", "inactive")}) {
		t.Fatalf("events after Forget %v", got)
	}
}

// TestWatchRefusesInvalidUnits: a unit name the server would refuse is not passed to systemctl.
func TestWatchRefusesInvalidUnits(t *testing.T) {
	ctx := context.Background()
	sys, w, events := watchFixture(t)
	for _, units := range [][]string{{"--now"}, {"-x.service"}, {"--.service"}, {"paddockd.service"}, {"foo.timer"}, {"a b.service"}} {
		r := watchResource(t, units...)
		if _, err := w.Plan(ctx, r); err == nil {
			t.Errorf("plan of %v succeeded", units)
		}
		if res := w.Apply(ctx, r); res.Status != reconcile.Error {
			t.Errorf("apply of %v: %+v", units, res)
		}
	}
	if got := takeEvents(events); len(got) != 0 {
		t.Fatalf("events %v", got)
	}
	if calls := sys.TakeCalls(); len(calls) != 0 {
		t.Fatalf("calls %v", calls)
	}
}

// TestWatchQueryFailure: a systemd query that fails (here a bus error) is an error, never a missing unit, and keeps the
// unit's previous state: no event while it fails, no second event for a stop reported before it.
func TestWatchQueryFailure(t *testing.T) {
	ctx := context.Background()
	sys, w, events := watchFixture(t)
	r := watchResource(t, "wazuh-agent.service")
	sys.FailCmd = "systemctl show -p LoadState -p ActiveState -p SubState -- wazuh-agent.service"
	if _, err := w.Plan(ctx, r); err == nil {
		t.Fatal("plan succeeded while systemd fails")
	}
	if res := w.Apply(ctx, r); res.Status != reconcile.Error {
		t.Fatalf("apply while systemd fails: %+v", res)
	}
	if got := takeEvents(events); len(got) != 0 {
		t.Fatalf("a failing query was reported: %v", got)
	}

	sys.FailCmd = ""
	sys.Units["wazuh-agent.service"].Active = false
	applyWatch(t, w, r)
	sys.FailCmd = "systemctl show -p LoadState -p ActiveState -p SubState -- wazuh-agent.service"
	w.Apply(ctx, r)
	sys.FailCmd = ""
	applyWatch(t, w, r)
	if got := takeEvents(events); !slices.Equal(got, []event{stopped("wazuh-agent.service", "inactive")}) {
		t.Fatalf("events across a failing query %v", got)
	}
}

// TestWatchCrashLoop: a unit systemd restarts after it exited (activating, auto-restart) is a crash loop only when the
// next pass still sees it restarting: then it is reported once as failed; a single restart is not reported.
func TestWatchCrashLoop(t *testing.T) {
	ctx := context.Background()
	sys, w, events := watchFixture(t)
	r := watchResource(t, "wazuh-agent.service")
	u := sys.Units["wazuh-agent.service"]

	u.Active, u.Restarting = false, true
	if plan, err := w.Plan(ctx, r); err != nil || !slices.Equal(plan, []string{"observe wazuh-agent.service restarting"}) {
		t.Fatalf("plan of a first restart %v (%v)", plan, err)
	}
	applyWatch(t, w, r)
	u.Active, u.Restarting = true, false
	applyWatch(t, w, r)
	if got := takeEvents(events); len(got) != 0 {
		t.Fatalf("a single restart was reported: %v", got)
	}

	u.Active, u.Restarting = false, true
	applyWatch(t, w, r)
	if plan, err := w.Plan(ctx, r); err != nil || !slices.Equal(plan, []string{"report wazuh-agent.service failed"}) {
		t.Fatalf("plan of a crash loop %v (%v)", plan, err)
	}
	applyWatch(t, w, r)
	applyWatch(t, w, r)
	if got := takeEvents(events); !slices.Equal(got, []event{stopped("wazuh-agent.service", "failed")}) {
		t.Fatalf("events of a crash loop %v", got)
	}
}

// TestWatchTransitions: activating and deactivating keep the unit's state: a normal restart is no event, and a
// reported unit that is started and stopped again before a pass sees it running is not reported twice.
func TestWatchTransitions(t *testing.T) {
	ctx := context.Background()
	sys, w, events := watchFixture(t)
	r := watchResource(t, "wazuh-agent.service")
	show := func(active, sub string) {
		sys.Shows["wazuh-agent.service"] = "LoadState=loaded\nActiveState=" + active + "\nSubState=" + sub + "\n"
	}
	for _, st := range [][2]string{{"active", "running"}, {"deactivating", "stop-sigterm"}, {"activating", "start"}, {"active", "running"}} {
		show(st[0], st[1])
		if st[0] != "active" {
			if plan, err := w.Plan(ctx, r); err != nil || len(plan) != 0 {
				t.Fatalf("plan while %s: %v (%v)", st[0], plan, err)
			}
		}
		applyWatch(t, w, r)
	}
	if got := takeEvents(events); len(got) != 0 {
		t.Fatalf("a normal restart was reported: %v", got)
	}

	show("inactive", "dead")
	applyWatch(t, w, r)
	show("activating", "start")
	applyWatch(t, w, r)
	show("inactive", "dead")
	applyWatch(t, w, r)
	if got := takeEvents(events); !slices.Equal(got, []event{stopped("wazuh-agent.service", "inactive")}) {
		t.Fatalf("events %v", got)
	}
}

// TestWatchShowAnswers: an empty or garbled answer of systemctl show is an error and no event; a unit systemd no
// longer knows is missing even while its process still runs.
func TestWatchShowAnswers(t *testing.T) {
	ctx := context.Background()
	for _, out := range []string{"", "garbage\n", "ActiveState=inactive\n", "LoadState=loaded\n"} {
		sys, w, events := watchFixture(t)
		sys.Shows["wazuh-agent.service"] = out
		r := watchResource(t, "wazuh-agent.service")
		if _, err := w.Plan(ctx, r); err == nil {
			t.Errorf("plan of answer %q succeeded", out)
		}
		if res := w.Apply(ctx, r); res.Status != reconcile.Error {
			t.Errorf("apply of answer %q: %+v", out, res)
		}
		if got := takeEvents(events); len(got) != 0 {
			t.Errorf("answer %q reported: %v", out, got)
		}
	}
	sys, w, events := watchFixture(t)
	sys.Shows["wazuh-agent.service"] = "LoadState=not-found\nActiveState=active\nSubState=running\n"
	applyWatch(t, w, watchResource(t, "wazuh-agent.service"))
	if got := takeEvents(events); !slices.Equal(got, []event{stopped("wazuh-agent.service", "missing")}) {
		t.Fatalf("events %v", got)
	}
}

// TestWatchPlanSkipsFailingUnit: a unit whose state cannot be read does not hide another unit's change from the drift
// pass, and Apply still reports the other unit.
func TestWatchPlanSkipsFailingUnit(t *testing.T) {
	ctx := context.Background()
	sys, w, events := watchFixture(t)
	r := watchResource(t, "falcon-sensor.service", "wazuh-agent.service")
	sys.FailCmd = "systemctl show -p LoadState -p ActiveState -p SubState -- falcon-sensor.service"
	sys.Units["wazuh-agent.service"].Active = false
	if plan, err := w.Plan(ctx, r); err != nil || !slices.Equal(plan, []string{"report wazuh-agent.service inactive"}) {
		t.Fatalf("plan %v (%v)", plan, err)
	}
	if res := w.Apply(ctx, r); res.Status != reconcile.Error || !strings.Contains(res.Message, "falcon-sensor.service") {
		t.Fatalf("apply %+v", res)
	}
	if got := takeEvents(events); !slices.Equal(got, []event{stopped("wazuh-agent.service", "inactive")}) {
		t.Fatalf("events %v", got)
	}
}

// TestWatchDuplicateUnits: a unit listed twice is one event per stop.
func TestWatchDuplicateUnits(t *testing.T) {
	ctx := context.Background()
	sys, w, events := watchFixture(t)
	sys.Units["wazuh-agent.service"].Active = false
	r := watchResource(t, "wazuh-agent.service", "wazuh-agent.service")
	if plan, err := w.Plan(ctx, r); err != nil || !slices.Equal(plan, []string{"report wazuh-agent.service inactive"}) {
		t.Fatalf("plan %v (%v)", plan, err)
	}
	applyWatch(t, w, r)
	if got := takeEvents(events); !slices.Equal(got, []event{stopped("wazuh-agent.service", "inactive")}) {
		t.Fatalf("events %v", got)
	}
}
