// Package updates holds the rules of update management (plan M5b decisions 1–4 and 9): the organization's update
// settings with their defaults and limits, package holds and how the holds of a device are merged. The syntax of
// schedules, package names and versions is decided by pkg/bundle, shared with the agent.
package updates

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/bundle"
)

// Defaults of an organization that never changed its update settings.
const (
	DefaultSecurityDailyAt    = "03:00"
	DefaultRegularSchedule    = "Sat 04:00"
	DefaultMaxRandomDelayMin  = 60
	DefaultStalenessWarningH  = 24
	DefaultStalenessCriticalH = 168
)

// Limits of the staleness thresholds (hours) and of a hold's reason.
const (
	MinStalenessWarningH  = 1
	MaxStalenessWarningH  = 720
	MaxStalenessCriticalH = 2160
	MaxReasonLength       = 500
)

// Settings are an organization's update settings.
type Settings struct {
	SecurityDailyAt       string
	RegularSchedule       string
	RegularUpdatesEnabled bool
	MaxRandomDelayMin     int
	StalenessWarningH     int
	StalenessCriticalH    int
}

// Defaults returns the settings of an organization without a row.
func Defaults() Settings {
	return Settings{
		SecurityDailyAt: DefaultSecurityDailyAt, RegularSchedule: DefaultRegularSchedule, RegularUpdatesEnabled: true,
		MaxRandomDelayMin: DefaultMaxRandomDelayMin, StalenessWarningH: DefaultStalenessWarningH,
		StalenessCriticalH: DefaultStalenessCriticalH,
	}
}

// Validation errors. ErrSchedule is answered with 422 invalid_schedule, ErrSettings with 400 invalid_request.
var (
	ErrSchedule = errors.New("invalid schedule")
	ErrSettings = errors.New("invalid update settings")
	ErrHold     = errors.New("invalid package hold")
)

// Validate checks the settings: both times in the schedule syntax of pkg/bundle (ErrSchedule), the random delay and
// the staleness thresholds within their limits (ErrSettings).
func (s Settings) Validate() error {
	if !bundle.ValidTimeOfDay(s.SecurityDailyAt) {
		return fmt.Errorf("%w: security_daily_at must be HH:MM", ErrSchedule)
	}
	if !bundle.ValidSchedule(s.RegularSchedule) {
		return fmt.Errorf("%w: regular_schedule must be [Mon..Sun[,…]] HH:MM, e.g. \"Sat 04:00\"", ErrSchedule)
	}
	if s.MaxRandomDelayMin < 0 || s.MaxRandomDelayMin > bundle.MaxRandomDelayMin {
		return fmt.Errorf("%w: max_random_delay_min must be between 0 and %d", ErrSettings, bundle.MaxRandomDelayMin)
	}
	if s.StalenessWarningH < MinStalenessWarningH || s.StalenessWarningH > MaxStalenessWarningH {
		return fmt.Errorf("%w: staleness_warning_h must be between %d and %d", ErrSettings, MinStalenessWarningH, MaxStalenessWarningH)
	}
	if s.StalenessCriticalH <= s.StalenessWarningH || s.StalenessCriticalH > MaxStalenessCriticalH {
		return fmt.Errorf("%w: staleness_critical_h must be above staleness_warning_h and at most %d", ErrSettings, MaxStalenessCriticalH)
	}
	return nil
}

// Hold is a package hold: organization-wide (GroupID nil) or for one device group; Version nil holds the installed
// version, a version pins it.
type Hold struct {
	GroupID *uuid.UUID
	Package string
	Version *string
}

// ValidateHold checks the package name, the version and the reason of a hold.
func ValidateHold(pkg string, version *string, reason string) error {
	if !bundle.ValidPackage(pkg) {
		return fmt.Errorf("%w: package must match ^[a-z0-9][a-z0-9+.-]+$ (at most 128 characters)", ErrHold)
	}
	if version != nil && !bundle.ValidPackageVersion(*version) {
		return fmt.Errorf("%w: version must match ^[A-Za-z0-9.+:~-]+$ (at most 128 characters)", ErrHold)
	}
	if len([]rune(reason)) > MaxReasonLength {
		return fmt.Errorf("%w: reason must be at most %d characters", ErrHold, MaxReasonLength)
	}
	return nil
}

// Conflict is a package held with different versions for one device; Chosen is the version the device gets.
type Conflict struct {
	Package  string
	Versions []*string // sorted, nil (no version) first
	Chosen   *string
}

// Merge returns the holds of a device from the holds that apply to it (organization-wide and those of its device
// groups), one per package and sorted by package, and the conflicts (plan M5b decision 4): when a package is held with
// different versions, the lexicographically smallest version wins; a hold without a version sorts before any version.
func Merge(holds []Hold) ([]bundle.Hold, []Conflict) {
	byPackage := map[string][]*string{}
	for _, h := range holds {
		vs := byPackage[h.Package]
		if !slices.ContainsFunc(vs, func(v *string) bool { return sameVersion(v, h.Version) }) {
			byPackage[h.Package] = append(vs, h.Version)
		}
	}
	names := make([]string, 0, len(byPackage))
	for p := range byPackage {
		names = append(names, p)
	}
	slices.Sort(names)
	merged := make([]bundle.Hold, 0, len(names))
	var conflicts []Conflict
	for _, p := range names {
		vs := byPackage[p]
		slices.SortFunc(vs, compareVersions)
		merged = append(merged, bundle.Hold{Package: p, Version: vs[0]})
		if len(vs) > 1 {
			conflicts = append(conflicts, Conflict{Package: p, Versions: vs, Chosen: vs[0]})
		}
	}
	return merged, conflicts
}

func sameVersion(a, b *string) bool { return compareVersions(a, b) == 0 }

func compareVersions(a, b *string) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1
	case b == nil:
		return 1
	}
	return strings.Compare(*a, *b)
}

// Held returns the packages of pkgs that one of holds holds, in the order of pkgs.
func Held(holds []Hold, pkgs []string) []string {
	var out []string
	for _, p := range pkgs {
		if slices.ContainsFunc(holds, func(h Hold) bool { return h.Package == p }) {
			out = append(out, p)
		}
	}
	return out
}

// MaxInstallDevices bounds the devices of one install-now request for a device group (plan M5b decision 3).
const MaxInstallDevices = 500

// ErrInstall is wrapped by every invalid install-now request.
var ErrInstall = errors.New("invalid install request")

// NormalizeInstall validates the packages of an install-now request and removes duplicates: 1 to maxPackages valid
// package names.
func NormalizeInstall(pkgs []string, maxPackages int) ([]string, error) {
	var out []string
	for _, p := range pkgs {
		if !bundle.ValidPackage(p) {
			return nil, fmt.Errorf("%w: %q is not a package name", ErrInstall, p)
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	if len(out) == 0 || len(out) > maxPackages {
		return nil, fmt.Errorf("%w: between 1 and %d packages", ErrInstall, maxPackages)
	}
	return out, nil
}
