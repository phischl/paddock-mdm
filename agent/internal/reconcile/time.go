package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/phischl/paddock-mdm/pkg/bundle"
)

// Time reconciles the time resource: a running NTP client (plan M2b decision 10).
type Time struct{ Sys System }

// Type implements Reconciler.
func (t *Time) Type() string { return bundle.TypeTime }

// Plan implements Reconciler. chrony wins when installed; otherwise systemd-timesyncd, switched on through
// timedated as well. NTP false leaves time synchronization alone (Paddock never switches it off).
func (t *Time) Plan(ctx context.Context, r bundle.Resource) ([]string, error) {
	var s bundle.TimeSpec
	if err := json.Unmarshal(r.Spec, &s); err != nil {
		return nil, fmt.Errorf("invalid time spec: %w", err)
	}
	if !s.NTP {
		return nil, nil
	}
	if t.Sys.PackageInstalled("chrony") {
		return unitChanges(ctx, t.Sys, "chrony.service", true, true)
	}
	if !t.Sys.PackageInstalled("systemd-timesyncd") {
		return nil, errors.New("neither chrony nor systemd-timesyncd is installed")
	}
	changes, err := unitChanges(ctx, t.Sys, "systemd-timesyncd.service", true, true)
	if err != nil {
		return nil, err
	}
	out, _, err := t.Sys.Timedatectl(ctx, "show", "--property=NTP", "--value")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(out) != "yes" {
		changes = append(changes, "timedatectl set-ntp true")
	}
	return changes, nil
}

// Apply implements Reconciler.
func (t *Time) Apply(ctx context.Context, r bundle.Resource) Result {
	return apply(ctx, r, t.Plan, func(changes []string) error { return run(ctx, t.Sys, changes) })
}
