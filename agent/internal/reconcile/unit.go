package reconcile

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/policy"
)

// Unit reconciles systemd unit resources: enabled and active state.
type Unit struct{ Sys System }

// Type implements Reconciler.
func (u *Unit) Type() string { return bundle.TypeSystemdUnit }

func (u *Unit) spec(r bundle.Resource) (bundle.UnitSpec, error) {
	var s bundle.UnitSpec
	if err := json.Unmarshal(r.Spec, &s); err != nil {
		return s, fmt.Errorf("invalid unit spec: %w", err)
	}
	return s, policy.ValidateUnit(s.Unit) // defence in depth: never touch Paddock's own or protected units
}

// Plan implements Reconciler.
func (u *Unit) Plan(ctx context.Context, r bundle.Resource) ([]string, error) {
	s, err := u.spec(r)
	if err != nil {
		return nil, err
	}
	return unitChanges(ctx, u.Sys, s.Unit, s.Enabled, s.Active)
}

// Apply implements Reconciler.
func (u *Unit) Apply(ctx context.Context, r bundle.Resource) Result {
	return apply(ctx, r, u.Plan, func(changes []string) error { return run(ctx, u.Sys, changes) })
}

// activeStates are the `systemctl is-active` answers that count as running.
var activeStates = []string{"active", "activating", "reloading", "refreshing"}

// unitChanges returns the commands ("systemctl <verb> <unit>") that bring unit to the desired state.
func unitChanges(ctx context.Context, sys System, unit string, enabled, active bool) ([]string, error) {
	out, exit, err := sys.Systemctl(ctx, "is-enabled", unit)
	if err != nil {
		return nil, err
	}
	// Exit 0 means enabled in some form (enabled, static, alias, indirect, generated, ...).
	state := firstLine(out)
	switch {
	case state == "masked" || state == "masked-runtime":
		return nil, fmt.Errorf("unit %s is masked", unit)
	case exit != 0 && state != "disabled" && state != "linked" && state != "linked-runtime":
		return nil, fmt.Errorf("unknown unit %s: %s", unit, state)
	}
	var changes []string
	switch {
	case enabled && exit != 0:
		changes = append(changes, "systemctl enable "+unit)
	case !enabled && (state == "enabled" || state == "enabled-runtime"):
		changes = append(changes, "systemctl disable "+unit)
	}
	out, _, err = sys.Systemctl(ctx, "is-active", unit)
	if err != nil {
		return nil, err
	}
	isActive := slices.Contains(activeStates, firstLine(out))
	switch {
	case active && !isActive:
		changes = append(changes, "systemctl start "+unit)
	case !active && isActive:
		changes = append(changes, "systemctl stop "+unit)
	}
	return changes, nil
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(line)
}

// run executes planned commands; the first word selects the tool.
func run(ctx context.Context, sys System, changes []string) error {
	for _, c := range changes {
		f := strings.Fields(c)
		var out string
		var exit int
		var err error
		switch f[0] {
		case "systemctl":
			out, exit, err = sys.Systemctl(ctx, f[1:]...)
		case "timedatectl":
			out, exit, err = sys.Timedatectl(ctx, f[1:]...)
		default:
			return fmt.Errorf("unknown command %q", c)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", c, err)
		}
		if exit != 0 {
			return fmt.Errorf("%s: exit %d %s", c, exit, strings.TrimSpace(out))
		}
	}
	return nil
}
