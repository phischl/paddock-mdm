// Package state is /var/lib/paddock/state/state.json: enrollment, sequence numbers, the applied bundle version and
// the event sequence (plan M2b decisions 6 and 12). Every save is atomic.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/paddock-mdm/paddock/agent/internal/fsutil"
)

// Enrollment states.
const (
	StatusPending  = "pending"
	StatusActive   = "active"
	StatusRejected = "rejected"
)

// State is the persistent agent state.
type State struct {
	EnrollmentID string `json:"enrollment_id,omitempty"`
	DeviceID     string `json:"device_id,omitempty"`
	Status       string `json:"status,omitempty"`
	// Seq is the last sequence number received from the server (sent back as Paddock-Seq).
	Seq int64 `json:"seq"`
	// AppliedBundleVersion is the version of the last bundle whose resources were all attempted.
	AppliedBundleVersion int64 `json:"applied_bundle_version"`
	// RejectedBundleVersion is the last bundle version that failed verification (reported once).
	RejectedBundleVersion int64 `json:"rejected_bundle_version,omitempty"`
	// EventSeq is the last event sequence number assigned.
	EventSeq      int64      `json:"event_seq"`
	LastCheckinAt *time.Time `json:"last_checkin_at,omitempty"`
	// FailedUpdateVersion is the last agent version whose update failed; it is not offered to the supervisor again.
	FailedUpdateVersion string `json:"failed_update_version,omitempty"`
	// ReportedUpdateAt is the "at" of the update result already turned into an event.
	ReportedUpdateAt *time.Time `json:"reported_update_at,omitempty"`
	// SessionsReported is the last session.login per directory user (at most one per 24 h, plan M3b decision 11).
	SessionsReported map[string]time.Time `json:"sessions_reported,omitempty"`
}

// Load reads state.json; a missing file is the empty state.
func Load(path string) (State, error) {
	var s State
	data, err := os.ReadFile(path) //nolint:gosec // path of the agent layout
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, fmt.Errorf("read state: %w", err)
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return s, fmt.Errorf("parse state %s: %w", path, err)
	}
	return s, nil
}

// Save writes state.json atomically.
func Save(path string, s State) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFile(path, append(data, '\n'), 0o600, 0o700)
}
