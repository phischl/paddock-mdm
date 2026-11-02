// Package finding is the state machine of findings: tamper events and attention conditions of a device with a
// status, an assignee and a reason (plan M9 decisions 30–33).
package finding

import (
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

// Kind is the source of a finding.
type Kind string

// Kinds.
const (
	KindTamper    Kind = "tamper"
	KindAttention Kind = "attention"
)

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool { return k == KindTamper || k == KindAttention }

// Status is the state of a finding.
type Status string

// Statuses: open, acknowledged and in_progress are live; the three resolutions close a finding.
const (
	StatusOpen          Status = "open"
	StatusAcknowledged  Status = "acknowledged"
	StatusInProgress    Status = "in_progress"
	StatusResolved      Status = "resolved"
	StatusAcceptedRisk  Status = "accepted_risk"
	StatusFalsePositive Status = "false_positive"
)

// Valid reports whether s is a known status.
func (s Status) Valid() bool { return s.Live() || s.Resolution() }

// Live reports whether s is one of the statuses before a close.
func (s Status) Live() bool {
	return s == StatusOpen || s == StatusAcknowledged || s == StatusInProgress
}

// Resolution reports whether s closes a finding.
func (s Status) Resolution() bool {
	return s == StatusResolved || s == StatusAcceptedRisk || s == StatusFalsePositive
}

// Length limits of the texts an administrator gives (plan M9 decision 33).
const (
	MaxReason      = 1000
	MaxExternalRef = 200
)

// CanAcknowledge reports whether a finding in status from can be acknowledged: only an open one.
func CanAcknowledge(from Status) bool { return from == StatusOpen }

// CanAssign reports whether a finding in status from can be assigned or unassigned: any live one. It moves to
// in_progress, unassigning included.
func CanAssign(from Status) bool { return from.Live() }

// CanClose reports whether a finding in status from can be closed: any live one.
func CanClose(from Status) bool { return from.Live() }

// CanReopen reports whether a closed finding can be reopened: a tamper finding always, an attention finding only
// while its condition is still open (not cleared).
func CanReopen(from Status, kind Kind, cleared bool) bool {
	return from.Resolution() && (kind == KindTamper || !cleared)
}

// ValidReason reports whether reason is a reason of 1 to MaxReason characters that is not blank.
func ValidReason(reason string) bool {
	return strings.TrimSpace(reason) != "" && utf8.RuneCountInString(reason) <= MaxReason
}

// ValidExternalRef reports whether ref has at most MaxExternalRef characters.
func ValidExternalRef(ref string) bool { return utf8.RuneCountInString(ref) <= MaxExternalRef }

// TamperKey is the key of the tamper findings of one device, audit code and subject (the file, group, unit, … the
// event names; empty for codes without one).
func TamperKey(device uuid.UUID, code, subject string) string {
	return "tamper:" + device.String() + ":" + code + ":" + subject
}

// AttentionKey is the key of the attention finding of an attention condition.
func AttentionKey(conditionID string) string { return "attention:" + conditionID }
