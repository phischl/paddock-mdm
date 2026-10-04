// Package device holds the device identity lifecycle (architecture §6.5) and the enrollment input rules.
package device

import (
	"errors"
	"slices"
	"strings"
	"unicode/utf8"
)

// States of a device.
const (
	StatePending     = "pending"
	StateActive      = "active"
	StateRejected    = "rejected"
	StateQuarantined = "quarantined"
	StateRetired     = "retired"
)

// States are all device states.
var States = []string{StatePending, StateActive, StateRejected, StateQuarantined, StateRetired}

// Action is a lifecycle transition.
type Action string

// Lifecycle actions; ActionQuarantine is taken by the system on clone suspicion, the others by administrators.
const (
	ActionApprove           Action = "approve"
	ActionReject            Action = "reject"
	ActionReleaseQuarantine Action = "release_quarantine"
	ActionRetire            Action = "retire"
	ActionQuarantine        Action = "quarantine"
)

var transitions = map[Action]struct {
	from []string
	to   string
}{
	ActionApprove:           {[]string{StatePending}, StateActive},
	ActionReject:            {[]string{StatePending}, StateRejected},
	ActionReleaseQuarantine: {[]string{StateQuarantined}, StateActive},
	ActionRetire:            {[]string{StateActive, StateQuarantined}, StateRetired},
	ActionQuarantine:        {[]string{StateActive}, StateQuarantined},
}

// ErrInvalidTransition means the action is not allowed in the current state.
var ErrInvalidTransition = errors.New("the device is not in a state that allows this action")

// Transition returns the state after action, or ErrInvalidTransition.
func Transition(action Action, from string) (string, error) {
	t, ok := transitions[action]
	if !ok || !slices.Contains(t.from, from) {
		return "", ErrInvalidTransition
	}
	return t.to, nil
}

// Compiled reports whether the compiler renders bundles for a device in state (architecture §6.4: a quarantined
// device keeps checking in but receives nothing new).
func Compiled(state string) bool { return state == StateActive }

// Limits of the device-reported enrollment fields.
const (
	maxHostname = 253
	maxField    = 128
)

// ErrInvalidEnrollment means the device sent unusable identity fields.
var ErrInvalidEnrollment = errors.New("hostname must be 1 to 253 printable characters; hardware_uuid, machine_id and agent_version at most 128")

// ValidateReported checks hostname and the optional fingerprint fields reported at enrollment.
func ValidateReported(hostname string, fields ...string) error {
	if n := utf8.RuneCountInString(hostname); n < 1 || n > maxHostname || !printable(hostname) {
		return ErrInvalidEnrollment
	}
	for _, f := range fields {
		if utf8.RuneCountInString(f) > maxField || !printable(f) {
			return ErrInvalidEnrollment
		}
	}
	return nil
}

func printable(s string) bool {
	return utf8.ValidString(s) && !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}
