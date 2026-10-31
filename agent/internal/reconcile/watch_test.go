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
	for _, units := range [][]string{{"--now"}, {"paddockd.service"}, {"foo.timer"}, {"a b.service"}} {
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
