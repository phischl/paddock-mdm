package device

import (
	"errors"
	"strings"
	"testing"
)

func TestTransition(t *testing.T) {
	ok := map[Action]map[string]string{
		ActionApprove:           {StatePending: StateActive},
		ActionReject:            {StatePending: StateRejected},
		ActionReleaseQuarantine: {StateQuarantined: StateActive},
		ActionRetire:            {StateActive: StateRetired, StateQuarantined: StateRetired},
		ActionQuarantine:        {StateActive: StateQuarantined},
	}
	for action, allowed := range ok {
		for _, from := range States {
			to, err := Transition(action, from)
			want, isAllowed := allowed[from]
			switch {
			case isAllowed && (err != nil || to != want):
				t.Errorf("%s from %s: %q %v, want %s", action, from, to, err, want)
			case !isAllowed && !errors.Is(err, ErrInvalidTransition):
				t.Errorf("%s from %s allowed", action, from)
			}
		}
	}
	if _, err := Transition("explode", StateActive); !errors.Is(err, ErrInvalidTransition) {
		t.Error("unknown action allowed")
	}
}

func TestValidateReported(t *testing.T) {
	if err := ValidateReported("lt-alice-01", "4c4c4544-0042", "", "0.1.0"); err != nil {
		t.Fatal(err)
	}
	for _, c := range [][]string{{""}, {strings.Repeat("h", 254)}, {"host\nname"}, {"ok", strings.Repeat("x", 129)}, {"ok", "a\x00"}} {
		if !errors.Is(ValidateReported(c[0], c[1:]...), ErrInvalidEnrollment) {
			t.Errorf("%q accepted", c)
		}
	}
}

func TestReportedOSRelease(t *testing.T) {
	id, version, ok := ReportedOSRelease(map[string]string{"id": "ubuntu", "version_id": "24.04", "pretty_name": "ignored"})
	if !ok || id != "ubuntu" || version != "24.04" {
		t.Fatalf("%q %q %v", id, version, ok)
	}
	for name, in := range map[string]map[string]string{
		"nil":            nil,
		"no version":     {"id": "ubuntu"},
		"empty id":       {"id": "", "version_id": "24.04"},
		"space":          {"id": "ubuntu", "version_id": "24 04"},
		"control":        {"id": "ubuntu\n", "version_id": "24.04"},
		"quote":          {"id": "ubuntu", "version_id": "\"24.04\""},
		"non ASCII":      {"id": "ubüntu", "version_id": "24.04"},
		"too long":       {"id": strings.Repeat("a", 65), "version_id": "24.04"},
		"path separator": {"id": "ubuntu", "version_id": "../24"},
	} {
		if _, _, ok := ReportedOSRelease(in); ok {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestStoredOSReleaseValue(t *testing.T) {
	if StoredOSReleaseValue("24.04") != "24.04" {
		t.Fatal("a plain value was changed")
	}
	for _, v := range []string{"", "a\nb", strings.Repeat("x", 60000), "x y", "\x1b[31m"} {
		if got := StoredOSReleaseValue(v); got != "" {
			t.Errorf("%.20q recorded as %.20q", v, got)
		}
	}
}

func TestAdoption(t *testing.T) {
	cases := []struct{ asserted, method, mode string }{
		{"", EnrollmentUnknown, ConfigModeEnforce},
		{"autoinstall", EnrollmentAutoinstall, ConfigModeEnforce},
		{"adopted", EnrollmentAdopted, ConfigModeReportOnly},
	}
	for _, tc := range cases {
		method, mode, err := Adoption(tc.asserted)
		if err != nil || method != tc.method || mode != tc.mode {
			t.Errorf("Adoption(%q) = %q, %q, %v", tc.asserted, method, mode, err)
		}
	}
	for _, bad := range []string{"unknown", "manual", "Adopted"} {
		if _, _, err := Adoption(bad); !errors.Is(err, ErrInvalidEnrollmentMethod) {
			t.Errorf("Adoption(%q) = %v", bad, err)
		}
	}
}
