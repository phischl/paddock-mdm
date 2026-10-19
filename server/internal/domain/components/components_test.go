package components

import (
	"slices"
	"testing"
)

// TestOutdated (plan M8d decision 54).
func TestOutdated(t *testing.T) {
	targets := map[string]string{Paddockd: "0.1.0-alpha.4", Supervisor: "0.1.0-alpha.4", Himmelblau: "4.0.4", Fleetd: "1.43.0"}
	for _, tc := range []struct {
		name      string
		installed map[string]string
		want      []string
	}{
		{"Debian pre-release older", map[string]string{Paddockd: "0.1.0~alpha.3"}, []string{Paddockd}},
		{"Debian pre-release equal", map[string]string{Supervisor: "0.1.0~alpha.4"}, []string{}},
		{"Debian revision of the target", map[string]string{Himmelblau: "4.0.4-1"}, []string{}},
		{"older Himmelblau", map[string]string{Himmelblau: "4.0.3-1"}, []string{Himmelblau}},
		{"newer Himmelblau", map[string]string{Himmelblau: "4.1.0-1"}, []string{}},
		{"not installed", map[string]string{Paddockd: "", Fleetd: ""}, []string{}},
		{"no target", map[string]string{Revoke: "0.0.1"}, []string{}},
		{"sorted", map[string]string{Paddockd: "0.0.9", Fleetd: "1.42.9", Himmelblau: "4.0.0"}, []string{Fleetd, Himmelblau, Paddockd}},
		{"newer agent", map[string]string{Paddockd: "0.1.0"}, []string{}},
		// PDK-333: the target is the last completed release; a supervisor from a running rollout is newer, not outdated.
		{"supervisor of a running rollout", map[string]string{Supervisor: "0.1.0~alpha.5", Paddockd: "0.1.0-alpha.5"}, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Outdated(tc.installed, targets); !slices.Equal(got, tc.want) {
				t.Fatalf("Outdated = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestStatus(t *testing.T) {
	targets := map[string]string{Himmelblau: "4.0.4"}
	installed := map[string]string{Paddockd: "0.1.0", Himmelblau: "4.0.3-1", Revoke: ""}
	for name, want := range map[string]string{Paddockd: StatusOK, Himmelblau: StatusOutdated, Revoke: StatusMissing, Fleetd: StatusMissing} {
		if got := Status(name, installed, targets); got != want {
			t.Errorf("%s: %s, want %s", name, got, want)
		}
	}
	if got := Status(Paddockd, nil, targets); got != StatusUnknown {
		t.Fatalf("without a report: %s", got)
	}
	// PDK-333: newer than the target (the last completed release) is ok, never outdated.
	release := map[string]string{Supervisor: "0.1.0-alpha.4", Himmelblau: "4.0.4"}
	for name, version := range map[string]string{Supervisor: "0.1.0~alpha.5", Himmelblau: "4.1.0"} {
		if got := Status(name, map[string]string{name: version}, release); got != StatusOK {
			t.Errorf("%s %s newer than its target: %s, want ok", name, version, got)
		}
	}
}
