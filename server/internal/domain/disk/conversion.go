package disk

import (
	"time"

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
