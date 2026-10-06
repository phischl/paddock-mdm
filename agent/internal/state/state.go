// Package state is /var/lib/paddock/state/state.json: enrollment, sequence numbers, the applied bundle version and
// the event sequence (plan M2b decisions 6 and 12). Every save is atomic.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/fsutil"
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
	// ExecutedCommands are the IDs of the commands this device started, with the time, kept 60 days so a command is
	// never executed twice (plan M4a decision 3).
	ExecutedCommands map[string]time.Time `json:"executed_commands,omitempty"`
	// CommandResults are the results the server has not accepted yet.
	CommandResults []CommandResult `json:"command_results,omitempty"`
	// LocalAdmin is the managed local administrator (plan M4a decision 15).
	LocalAdmin LocalAdmin `json:"local_admin"`
	// LUKS is the disk encryption of the root volume (plan M4b decisions 8–12).
	LUKS LUKS `json:"luks"`
}

// LUKS is the persistent state of the luks reconciler. Secrets — the recovery key, the install passphrase — are
// never stored here.
type LUKS struct {
	// Keyslots are the keyslot kinds the agent recorded last (sorted); any other set is reported as tampering.
	Keyslots []string `json:"keyslots,omitempty"`
	// RecoveryAttempted is the highest recovery key generation the agent enrolled, RecoveryStored the highest one the
	// server stored. A recovery keyslot with RecoveryAttempted > RecoveryStored whose key is no longer in memory is
	// replaced.
	RecoveryAttempted int64 `json:"recovery_attempted,omitempty"`
	RecoveryStored    int64 `json:"recovery_stored,omitempty"`
	// HeaderAttempted is the highest header generation uploaded; HeaderStored the highest one stored, and
	// HeaderDigest the hex SHA-256 of the LUKS2 metadata it was taken from.
	HeaderAttempted int64  `json:"header_attempted,omitempty"`
	HeaderStored    int64  `json:"header_stored,omitempty"`
	HeaderDigest    string `json:"header_digest,omitempty"`
	// PassphraseSlot is the keyslot of the install passphrase, recorded before the first change; RecoverySlot the
	// keyslot of the agent's current recovery key. Only these slots are ever removed (plan M4b.1 decision 3).
	PassphraseSlot *int `json:"passphrase_slot,omitempty"`
	RecoverySlot   *int `json:"recovery_slot,omitempty"`
}

// LocalAdmin is the persistent state of the managed local administrator. The password itself is never stored.
type LocalAdmin struct {
	Username string `json:"username,omitempty"`
	// Generation is the password generation the device set last; 0 before the first rotation.
	Generation int64 `json:"generation,omitempty"`
	// Attempted is the highest generation uploaded for escrow; a new rotation uses Attempted+1, so a generation
	// the server stored late is never reused.
	Attempted int64      `json:"attempted,omitempty"`
	RotatedAt *time.Time `json:"rotated_at,omitempty"`
	// ShadowSHA256 is the hex SHA-256 of the account's /etc/shadow hash field after the last rotation.
	ShadowSHA256 string `json:"shadow_sha256,omitempty"`
	// Tampered are the fields reported as changed and not yet repaired (each is reported once).
	Tampered []string `json:"tampered,omitempty"`
	// Commands are rotate_admin_password commands waiting for the result of the next rotation.
	Commands []string `json:"commands,omitempty"`
	// RetryAt delays an automatic rotation after a failed one.
	RetryAt *time.Time `json:"retry_at,omitempty"`
}

// CommandResult is the result of an executed command, kept until the server accepted it.
type CommandResult struct {
	CommandID string          `json:"command_id"`
	Status    string          `json:"status"`
	Result    json.RawMessage `json:"result,omitempty"`
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
