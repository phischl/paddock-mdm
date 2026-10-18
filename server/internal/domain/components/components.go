// Package components compares the component versions a device reports with the platform's targets (ADR 0037
// amendment 2026-10-17, plan M8d decisions 52–55).
package components

import (
	"slices"
	"strconv"
	"strings"

	"github.com/phischl/paddock-mdm/pkg/semver"
)

// The components a device reports in health.components, in the order the device page lists them.
const (
	Paddockd   = "paddockd"
	Supervisor = "paddock_supervisor"
	Revoke     = "paddock_revoke"
	Himmelblau = "himmelblau"
	Fleetd     = "fleetd"
)

// Names are the components in display order.
var Names = []string{Paddockd, Supervisor, Revoke, Himmelblau, Fleetd}

// Statuses of a component on a device.
const (
	StatusOK       = "ok"
	StatusOutdated = "outdated"
	StatusMissing  = "missing"
	StatusUnknown  = "unknown"
)

// Outdated returns the components, sorted, that are installed, have a target and are older than it. A component
// that is not installed ("") is never outdated: it is missing.
func Outdated(installed, targets map[string]string) []string {
	out := []string{}
	for name, version := range installed {
		if target, ok := targets[name]; ok && version != "" && older(name, version, target) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// Status is the status of one component: unknown when the device reported no components, missing when it is not
// installed, outdated when it is older than its target, otherwise ok (also without a target).
func Status(name string, installed map[string]string, targets map[string]string) string {
	if installed == nil {
		return StatusUnknown
	}
	version := installed[name]
	if version == "" {
		return StatusMissing
	}
	if target, ok := targets[name]; ok && older(name, version, target) {
		return StatusOutdated
	}
	return StatusOK
}

// older reports whether an installed version is older than the target. Paddock's own packages compare by SemVer with
// the Debian pre-release separator ~ read as -; Himmelblau and fleetd follow the rule of the login reconciler: the
// target itself or a Debian revision of it ("4.0.4-1" for "4.0.4") is current, otherwise the dotted numbers before
// the first - decide.
func older(name, installed, target string) bool {
	switch name {
	case Paddockd, Supervisor, Revoke:
		return semver.Compare(strings.ReplaceAll(installed, "~", "-"), strings.ReplaceAll(target, "~", "-")) < 0
	}
	if installed == target || strings.HasPrefix(installed, target+"-") {
		return false
	}
	return compareDotted(upstream(installed), upstream(target)) < 0
}

func upstream(v string) string {
	u, _, _ := strings.Cut(v, "-")
	return u
}

// compareDotted compares dotted integers field by field; a non-numeric field counts as 0.
func compareDotted(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := range max(len(as), len(bs)) {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}
