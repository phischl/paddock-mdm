package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/policy"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// States of a watched unit that is not running, the state of tamper.service_stopped (plan M9 decision 40).
const (
	WatchInactive = "inactive"
	WatchFailed   = "failed"
	WatchMissing  = "missing"
)

// Observed states of a watched unit besides the reported ones.
const (
	watchRunning = ""
	// watchTransition is a plain start or stop in progress (activating, deactivating): the unit keeps its state.
	watchTransition = "transition"
	// watchRestarting is systemd waiting to restart the unit after it exited (SubState auto-restart).
	watchRestarting = "restarting"
)

// Watch is the organization's presence policy (plan M9 decision 40): it reports a watched third-party unit that is not
// running as tamper.service_stopped, once per stop, with its state. It only reads the units: starting, stopping,
// enabling, masking or installing them would make the agent act on its own initiative (agent design contract 8); a
// unit Paddock keeps running is a systemd_unit resource.
type Watch struct {
	Sys    System
	Events *Events

	// mu guards marks: the drift loop applies while the agent socket may plan.
	mu sync.Mutex
	// marks are the units reported as stopped and not seen running since, and the units seen restarting on the last
	// pass.
	marks map[string]watchMark
}

// watchMark is what the watch remembers of a unit between passes.
type watchMark struct {
	stopped    bool // reported, not seen running since
	restarting bool // seen in auto-restart on the last pass
}

// next is the mark after a pass that observed state, and the state to report ("" for none). A transition keeps the
// state; an auto-restart is a crash loop only when the next pass sees it again, so a single restart is not reported.
func (m watchMark) next(state string) (watchMark, string) {
	switch state {
	case watchRunning:
		return watchMark{}, ""
	case watchTransition:
		return watchMark{stopped: m.stopped}, ""
	case watchRestarting:
		switch {
		case m.stopped:
			return watchMark{stopped: true}, ""
		case m.restarting:
			return watchMark{stopped: true}, WatchFailed
		default:
			return watchMark{restarting: true}, ""
		}
	default:
		if m.stopped {
			return watchMark{stopped: true}, ""
		}
		return watchMark{stopped: true}, state
	}
}

// Type implements Reconciler.
func (w *Watch) Type() string { return bundle.TypeWatch }

// watchSpec decodes the watch section; a unit listed twice is watched once, so that a stop is one event.
func watchSpec(r bundle.Resource) (bundle.WatchSpec, error) {
	var s bundle.WatchSpec
	if err := json.Unmarshal(r.Spec, &s); err != nil {
		return s, fmt.Errorf("invalid watch spec: %w", err)
	}
	units := make([]string, 0, len(s.Units))
	for _, u := range s.Units {
		// The server refuses the same names; the agent checks again because a unit name becomes a systemctl argument,
		// and a leading '-' would read as an option.
		if policy.ValidateUnit(u) != nil || !strings.HasSuffix(u, ".service") || strings.HasPrefix(u, "-") {
			return s, fmt.Errorf("invalid watched unit %q", u)
		}
		if !slices.Contains(units, u) {
			units = append(units, u)
		}
	}
	s.Units = units
	return s, nil
}

// watchState returns the observed state of a watched unit: watchRunning, watchTransition, watchRestarting,
// WatchInactive, WatchFailed or WatchMissing. Only systemd's own "not-found" makes a unit missing: a query that fails
// (bus error, timeout) or an answer without LoadState and ActiveState is an error, so that a busy or restarting
// systemd is never reported as tampering.
func watchState(ctx context.Context, sys System, unit string) (string, error) {
	out, exit, err := sys.Systemctl(ctx, "show", "-p", "LoadState", "-p", "ActiveState", "-p", "SubState", "--", unit)
	if err != nil {
		return "", fmt.Errorf("systemctl show %s: %w", unit, err)
	}
	if exit != 0 {
		return "", fmt.Errorf("systemctl show %s: exit %d: %s", unit, exit, firstLine(out))
	}
	props := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			props[k] = v
		}
	}
	load, active, sub := props["LoadState"], props["ActiveState"], props["SubState"]
	switch {
	case load == "" || active == "":
		return "", fmt.Errorf("systemctl show %s: unexpected answer %q", unit, firstLine(out))
	case load == "not-found":
		return WatchMissing, nil
	case strings.HasPrefix(sub, "auto-restart"):
		return watchRestarting, nil
	case active == "failed":
		return WatchFailed, nil
	case active == "active" || active == "reloading" || active == "refreshing":
		return watchRunning, nil
	case active == "activating" || active == "deactivating":
		return watchTransition, nil
	default:
		return WatchInactive, nil
	}
}

// Plan implements Reconciler: a stop to report, a reported unit that runs again and a change of the restart mark are
// changes, so that the drift pass applies the resource. A unit whose state cannot be read is logged and skipped; the
// error is returned only when no unit has a change, because the applier drops the changes of a plan with an error.
func (w *Watch) Plan(ctx context.Context, r bundle.Resource) ([]string, error) {
	s, err := watchSpec(r)
	if err != nil {
		return nil, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	var changes []string
	var errs []error
	for _, u := range s.Units {
		state, err := watchState(ctx, w.Sys, u)
		if err != nil {
			slog.WarnContext(ctx, "watched unit state unknown", "unit", u, "error", err)
			errs = append(errs, err)
			continue
		}
		prev := w.marks[u]
		next, report := prev.next(state)
		switch {
		case report != "":
			changes = append(changes, "report "+u+" "+report)
		case prev.stopped && !next.stopped:
			changes = append(changes, "clear "+u)
		case next.restarting && !prev.restarting:
			changes = append(changes, "observe "+u+" restarting")
		case prev.restarting && !next.restarting:
			changes = append(changes, "clear "+u)
		}
	}
	if len(changes) == 0 {
		return nil, errors.Join(errs...)
	}
	return changes, nil
}

// Apply implements Reconciler. It reports and never changes the system, so its status is OK; a unit whose state
// cannot be read keeps its mark and is an error, and the other units are still checked.
func (w *Watch) Apply(ctx context.Context, r bundle.Resource) Result {
	s, err := watchSpec(r)
	if err != nil {
		return errorResult(r.ID, err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	marks := map[string]watchMark{}
	var errs []error
	for _, u := range s.Units {
		prev := w.marks[u]
		state, err := watchState(ctx, w.Sys, u)
		if err != nil {
			slog.WarnContext(ctx, "watched unit state unknown", "unit", u, "error", err)
			errs = append(errs, err)
			marks[u] = prev
			continue
		}
		next, report := prev.next(state)
		switch {
		case report != "":
			slog.WarnContext(ctx, "watched unit not running", "unit", u, "state", report)
			w.Events.emit(protocol.EventTamperServiceStopped, protocol.TamperServiceStopped{Unit: u, State: report})
		case prev.stopped && !next.stopped:
			slog.InfoContext(ctx, "watched unit running again", "unit", u)
		}
		marks[u] = next
	}
	w.marks = marks
	if err := errors.Join(errs...); err != nil {
		return errorResult(r.ID, err)
	}
	return Result{ID: r.ID, Status: OK}
}

// Forget drops every mark, for a bundle without watch section: a unit watched again later is reported anew.
func (w *Watch) Forget() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.marks = nil
}
