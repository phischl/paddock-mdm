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

// RetiredUninstalled is device.retired_reason of a device retired by its own removal report (plan M8d decision 41).
const RetiredUninstalled = "uninstalled"

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

// Enrollment methods (device.enrollment_method) and configuration modes (device.config_mode), plan M11 §3.1.
const (
	EnrollmentAutoinstall = "autoinstall"
	EnrollmentAdopted     = "adopted"
	EnrollmentUnknown     = "unknown"
	ConfigModeEnforce     = "enforce"
	ConfigModeReportOnly  = "report_only"
)

// ErrInvalidEnrollmentMethod means the device asserted an enrollment method other than autoinstall or adopted.
var ErrInvalidEnrollmentMethod = errors.New("enrollment_method must be autoinstall or adopted")

// Adoption returns the enrollment method and configuration mode a device is created with for the method it asserts
// ("" for agents that send none). The method is the device's own claim, so it only selects report-only for an adopted
// device (fail safe, plan M11 decision 40) and never grants anything.
func Adoption(asserted string) (method, mode string, err error) {
	switch asserted {
	case "":
		return EnrollmentUnknown, ConfigModeEnforce, nil
	case EnrollmentAutoinstall:
		return EnrollmentAutoinstall, ConfigModeEnforce, nil
	case EnrollmentAdopted:
		return EnrollmentAdopted, ConfigModeReportOnly, nil
	}
	return "", "", ErrInvalidEnrollmentMethod
}

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

// maxOSReleaseValue bounds one reported os-release value; real ID and VERSION_ID values are a few characters.
const maxOSReleaseValue = 64

// ReportedOSRelease returns the ID and VERSION_ID a check-in reports when both are plain identifiers (letters, digits,
// dot, underscore, hyphen). The values come from the device and select the software catalog entries of its release,
// so anything else is ignored as a whole and the stored value stays (PDK-695).
func ReportedOSRelease(in map[string]string) (id, versionID string, ok bool) {
	id, versionID = in["id"], in["version_id"]
	return id, versionID, plainOSReleaseValue(id) && plainOSReleaseValue(versionID)
}

// StoredOSReleaseValue returns a stored os-release value for an audit event: the value of the enrollment is not
// validated, so one that is not a plain identifier is recorded as "".
func StoredOSReleaseValue(s string) string {
	if plainOSReleaseValue(s) {
		return s
	}
	return ""
}

func plainOSReleaseValue(s string) bool {
	if s == "" || len(s) > maxOSReleaseValue {
		return false
	}
	return !strings.ContainsFunc(s, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '.' && r != '_' && r != '-'
	})
}
