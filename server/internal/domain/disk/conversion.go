package disk

import (
	"strings"
	"time"
	"unicode"

	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// Phases of an in-place encryption on the server (ADR 0039, plan M8e §3.1).
const (
	PhaseRequested  = "requested"  // command issued, not delivered
	PhasePrepared   = "prepared"   // escrow stored, initrd built, waiting for the restart
	PhaseEncrypting = "encrypting" // the init step succeeded, the background phase runs or is paused
	PhaseCompleted  = "completed"
	PhaseFailed     = "failed"
	PhaseCancelled  = "cancelled"
)

// Open reports whether a conversion in phase can still change the disk: at most one of a device is open.
func Open(phase string) bool {
	return phase == PhaseRequested || phase == PhasePrepared || phase == PhaseEncrypting
}

// CompletedFailSafe is how long after a completion a device whose health carries no conversion counts as converting
// (plan M8e amendment 2026-10-21, rule d).
const CompletedFailSafe = 30 * 24 * time.Hour

// ConversionActive reports whether a device's in-place encryption is active (plan M8e §14.5 decision 36 as amended on
// 2026-10-21): (a) its latest conversion is open; (b) its last health reports the disk encrypting, whatever the
// conversion says; (c) its last health reports key_on_boot, whatever the conversions say — the conversion key is still
// the initrd's unlock path (decision 52, I1); (d) fail safe, a conversion completed less than
// CompletedFailSafe ago and the health is missing or carries no conversion. A compliant disk ends (d): it is never
// reported before the initrd was regenerated (decision 3). phase is "" without a conversion, health nil without a
// disk report, completedAt nil without a completed conversion.
func ConversionActive(phase string, health *protocol.DiskHealth, completedAt *time.Time, now time.Time) bool {
	switch {
	case Open(phase):
		return true
	case health != nil && health.State == protocol.DiskEncrypting:
		return true
	case health != nil && health.Conversion != nil && health.Conversion.KeyOnBoot:
		return true
	case completedAt == nil, health != nil && health.Conversion != nil:
		return false
	case health != nil && health.State == protocol.DiskCompliant:
		return false
	}
	return now.Sub(*completedAt) < CompletedFailSafe
}

// reportedPreparing is the phase health.disk.conversion reports while the device prepares; the server's phase is still
// requested then.
const reportedPreparing = "preparing"

// ConversionNotes is what the last check-in reports beside the progress (plan M8e amendment 2026-10-21, items 17 to
// 19): a wait, why an unfinished cleanup did not finish, and why the initrd work cannot go on. Every field is empty
// where it does not apply.
type ConversionNotes struct {
	PausedReason      string
	PausedSince       *time.Time
	CleanupError      string
	InitrdIssue       string
	InitrdIssueKernel string
	BootSpaceNeeded   int64
	BootSpaceFree     int64
}

// Notes takes the notes of a conversion in phase from health.disk.conversion c of the last check-in: the wait while
// the device encrypts or, with the server still at requested, prepares; the cleanup's reason only once the conversion
// failed or was cancelled, the only phases that leave a cleanup; the initrd issue in every phase, since the
// preparation, the regeneration and the cleanup all report it. c is nil without a report.
func Notes(phase string, c *protocol.DiskConversion) ConversionNotes {
	if c == nil {
		return ConversionNotes{}
	}
	n := ConversionNotes{InitrdIssue: noteText(c.InitrdIssue), InitrdIssueKernel: noteText(c.InitrdIssueKernel),
		BootSpaceNeeded: c.BootSpaceNeeded, BootSpaceFree: c.BootSpaceFree}
	if phase == PhaseEncrypting || (phase == PhaseRequested && c.Phase == reportedPreparing) {
		n.PausedReason, n.PausedSince = noteText(c.PausedReason), c.PausedSince
	}
	if phase == PhaseFailed || phase == PhaseCancelled {
		n.CleanupError = noteText(c.CleanupError)
	}
	return n
}

// maxNoteText is the bound the agent applies to cleanup_error (plan M8e amendment 2026-10-21, item 17).
const maxNoteText = 200

// noteText bounds a device-reported text like failure_reason: the health is device input and cleanup_error is free
// text the portal shows, so only its first line, without control characters, at most maxNoteText runes.
func noteText(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	if r := []rune(s); len(r) > maxNoteText {
		s = string(r[:maxNoteText])
	}
	return strings.TrimSpace(s)
}
