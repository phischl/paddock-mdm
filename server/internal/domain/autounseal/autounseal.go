// Package autounseal holds the setting of the automatic unseal of OpenBao and the disclaimer a platform
// administrator acknowledges before it may be enabled (ADR 0035).
package autounseal

import (
	"errors"
	"slices"
	"time"
)

// DisclaimerVersion is the version (date) of the disclaimer text of plan M8u §6.6; a changed text gets a new date.
const DisclaimerVersion = "2026-10-17"

// Acknowledgements are the exact sentences, one per portal language, that acknowledge DisclaimerVersion.
var Acknowledgements = []string{
	"I understand and accept the risk",
	"Ich verstehe und akzeptiere das Risiko",
}

// State of the setting.
type State string

// States of the setting.
const (
	StateDisabled State = "disabled"
	StateEnabled  State = "enabled"
)

// Validation errors of ValidateAcknowledgement.
var (
	ErrDisclaimerOutdated      = errors.New("autounseal: disclaimer version is not the current one")
	ErrAcknowledgementMismatch = errors.New("autounseal: acknowledgement does not match")
)

// ValidateAcknowledgement reports whether version is DisclaimerVersion (else ErrDisclaimerOutdated) and
// acknowledgement is one of Acknowledgements byte for byte, without trimming (else ErrAcknowledgementMismatch).
func ValidateAcknowledgement(version, acknowledgement string) error {
	if version != DisclaimerVersion {
		return ErrDisclaimerOutdated
	}
	if !slices.Contains(Acknowledgements, acknowledgement) {
		return ErrAcknowledgementMismatch
	}
	return nil
}

// Setting is the row openbao_auto_unseal.
type Setting struct {
	State                 State
	DisclaimerVersion     string // "" while never enabled
	Acknowledgement       string
	AcknowledgedBy        string // display name of the platform administrator
	AcknowledgedBySubject string // Authentik subject
	AcknowledgedAt        time.Time
	DisabledBy            string
	DisabledAt            time.Time
	Report                Report
}

// Report is what the unsealer writes about itself.
type Report struct {
	SeenAt            time.Time
	SharesPresent     bool
	UnsealCount       int64
	LastUnsealAt      time.Time
	FailureCount      int64
	LastFailureAt     time.Time
	LastFailureReason string // one of the FailureReason* constants, "" when none
}

// UnsealerStaleAfter is how long after its last report the unsealer counts as not running (six 10 s ticks).
const UnsealerStaleAfter = 60 * time.Second

// UnsealerRunning reports whether the unsealer reported within UnsealerStaleAfter of now.
func (r Report) UnsealerRunning(now time.Time) bool {
	return !r.SeenAt.IsZero() && now.Sub(r.SeenAt) <= UnsealerStaleAfter
}

// SharesOnHost reports whether the shares count as present on the host: only the report of a running unsealer counts,
// because `./paddock auto-unseal disable` removes the unsealer before it deletes the file and nothing reports the
// deletion afterwards (plan M8u decisions 13 and 22, amended 2026-10-18).
func (r Report) SharesOnHost(now time.Time) bool {
	return r.SharesPresent && r.UnsealerRunning(now)
}

// Failure reasons the unsealer reports (never a share, never an OpenBao error text).
const (
	FailureReasonUnreachable  = "unreachable"
	FailureReasonInvalidShare = "invalid_share"
	FailureReasonStillSealed  = "still_sealed"
)
