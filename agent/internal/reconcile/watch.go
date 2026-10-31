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

// Watch is the organization's presence policy (plan M9 decision 40): it reports a watched third-party unit that is not
// running as tamper.service_stopped, once per stop, with its state. It only reads the units: starting, stopping,
// enabling, masking or installing them would make the agent act on its own initiative (agent design contract 8); a
// unit Paddock keeps running is a systemd_unit resource.
type Watch struct {
	Sys    System
	Events *Events

	// mu guards stopped: the drift loop applies while the agent socket may plan.
	mu sync.Mutex
	// stopped holds the units reported as stopped and not seen running since.
	stopped map[string]bool
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

// watchState returns the state of a watched unit: "" while it runs, otherwise WatchInactive, WatchFailed or
// WatchMissing. Only systemd's own "not-found" makes a unit missing: a query that fails (bus error, timeout) is an
// error, so that a busy or restarting systemd is never reported as tampering.
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
	// A crash loop waits in activating/auto-restart between the attempts: it is not running.
	case active == "failed" || strings.HasPrefix(sub, "auto-restart"):
		return WatchFailed, nil
	case slices.Contains(activeStates, active):
		return "", nil
	default:
		return WatchInactive, nil
	}
}

// Plan implements Reconciler: a unit not running that was not reported yet is to be reported, a reported unit that
// runs again is to be cleared. Both are changes so that the drift pass applies the resource.
func (w *Watch) Plan(ctx context.Context, r bundle.Resource) ([]string, error) {
	s, err := watchSpec(r)
	if err != nil {
		return nil, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	var changes []string
	for _, u := range s.Units {
		state, err := watchState(ctx, w.Sys, u)
		if err != nil {
			return nil, err
		}
		switch {
		case state != "" && !w.stopped[u]:
			changes = append(changes, "report "+u+" "+state)
		case state == "" && w.stopped[u]:
			changes = append(changes, "clear "+u)
		}
	}
	return changes, nil
}

// Apply implements Reconciler. It reports and never changes the system, so its status is OK; a unit whose state
// cannot be read is an error and the other units are still checked.
func (w *Watch) Apply(ctx context.Context, r bundle.Resource) Result {
	s, err := watchSpec(r)
	if err != nil {
		return errorResult(r.ID, err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	seen := map[string]bool{}
	var errs []error
	for _, u := range s.Units {
		state, err := watchState(ctx, w.Sys, u)
		if err != nil {
			errs = append(errs, err)
			seen[u] = w.stopped[u]
			continue
		}
		switch {
		case state != "" && !w.stopped[u]:
			slog.WarnContext(ctx, "watched unit not running", "unit", u, "state", state)
			w.Events.emit(protocol.EventTamperServiceStopped, protocol.TamperServiceStopped{Unit: u, State: state})
			seen[u] = true
		case state != "":
			seen[u] = true
		case w.stopped[u]:
			slog.InfoContext(ctx, "watched unit running again", "unit", u)
		}
	}
	for u := range w.stopped {
		if !seen[u] {
			delete(w.stopped, u)
		}
	}
	for u, stopped := range seen {
		if stopped {
			if w.stopped == nil {
				w.stopped = map[string]bool{}
			}
			w.stopped[u] = true
		}
	}
	if err := errors.Join(errs...); err != nil {
		return errorResult(r.ID, err)
	}
	return Result{ID: r.ID, Status: OK}
}

// Forget drops every reported stop, for a bundle without watch section: a unit watched again later is reported anew.
func (w *Watch) Forget() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stopped = nil
}
