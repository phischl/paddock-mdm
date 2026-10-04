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
