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
	// UpdateRequestHandledAt is the requested_at of the last update-now request the agent staged (plan M8d decision
	// 28): each request overrides the update policy and a failed version once.
	UpdateRequestHandledAt *time.Time `json:"update_request_handled_at,omitempty"`
	// ReportedUpdateAt is the "at" of the update result already turned into an event.
	ReportedUpdateAt *time.Time `json:"reported_update_at,omitempty"`
	// FailedSupervisorVersion is the last supervisor package version whose upgrade failed or was rolled back; it is
	// not installed again (plan M8d decision 32). ReportedSupervisorUpgradeAt is the "at" of the supervisor upgrade
	// result already turned into an event.
	FailedSupervisorVersion     string     `json:"failed_supervisor_version,omitempty"`
	ReportedSupervisorUpgradeAt *time.Time `json:"reported_supervisor_upgrade_at,omitempty"`
	// SupervisorRetry is the supervisor package version rolled back only because the server was unreachable, with
	// its attempts and the earliest next attempt (design contract 8, ADR 0037 amendment 2026-10-18).
	SupervisorRetry *SupervisorRetry `json:"supervisor_retry,omitempty"`
	// ReportedRegularAt and ReportedSecurityAt are the ends of the last regular and security update runs reported as
	// updates.run (plan M5b decision 6).
	ReportedRegularAt  *time.Time `json:"reported_regular_at,omitempty"`
	ReportedSecurityAt *time.Time `json:"reported_security_at,omitempty"`
	// SessionsReported is the last session.login per directory user (at most one per 24 h, plan M3b decision 11),
	// and while the login history is on one entry per reported session, keyed "<user>\x00<session ID>" and pruned
	// when the session ends (plan M8d decision 17).
	SessionsReported map[string]time.Time `json:"sessions_reported,omitempty"`
	// ExecutedCommands are the IDs of the commands this device started, with the time, kept 60 days so a command is
	// never executed twice (plan M4a decision 3).
	ExecutedCommands map[string]time.Time `json:"executed_commands,omitempty"`
	// HandedRevocations are the SHA-256 (hex) of the revocation envelopes handed to paddock-revoke, with the time,
	// so each is handed once (plan M4c decision 11); kept 31 days, longer than a token lives.
	HandedRevocations map[string]time.Time `json:"handed_revocations,omitempty"`
	// PendingInstalls are the install_now commands accepted but not finished; a restarted agent reports them as
	// interrupted.
	PendingInstalls []PendingInstall `json:"pending_installs,omitempty"`
	// PendingUninstall is the accepted uninstall command whose removal the agent starts once its result was accepted
	// (plan M8d decision 39).
	PendingUninstall *PendingUninstall `json:"pending_uninstall,omitempty"`
	// CommandResults are the results the server has not accepted yet.
	CommandResults []CommandResult `json:"command_results,omitempty"`
	// LocalAdmin is the managed local administrator (plan M4a decision 15).
	LocalAdmin LocalAdmin `json:"local_admin"`
	// LUKS is the disk encryption of the root volume (plan M4b decisions 8–12).
	LUKS LUKS `json:"luks"`
	// Conversion is the in-place encryption of the root volume (plan M8e §6.3); nil without one.
	Conversion *DiskConversion `json:"conversion,omitempty"`
}

// Phases of an in-place encryption on the device (plan M8e §3.1); the server's phase requested is preparing here.
const (
	ConversionPreparing  = "preparing"
	ConversionPrepared   = "prepared"
	ConversionEncrypting = "encrypting"
	ConversionCompleted  = "completed"
	ConversionFailed     = "failed"
	ConversionCancelled  = "cancelled"
)

// Failure stages of an in-place encryption (plan M8e decision 3).
const (
	StagePreflight = "preflight"
	StagePrepare   = "prepare"
	StageInit      = "init"
	StageResume    = "resume"
)

// DiskConversion is the in-place encryption in progress on this device (ADR 0039, plan M8e §6.3). Secrets are never
// stored here.
type DiskConversion struct {
	ID          string     `json:"id"`
	CommandID   string     `json:"command_id"`
	Phase       string     `json:"phase"`
	RequestedAt time.Time  `json:"requested_at"`
	PreparedAt  *time.Time `json:"prepared_at,omitempty"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Layout      string     `json:"layout,omitempty"`
	LUKSUUID    string     `json:"luks_uuid,omitempty"`
	Mapping     string     `json:"mapping,omitempty"`
	Partition   string     `json:"partition,omitempty"`
	DataBytes   int64      `json:"data_bytes,omitempty"`
	// KeyEscrowGeneration is the recovery key generation the server stored the conversion key as (decision 13 step 4).
	KeyEscrowGeneration int64  `json:"key_escrow_generation,omitempty"`
	InitrdRegenerated   bool   `json:"initrd_regenerated,omitempty"`
	ResumeFailures      int    `json:"resume_failures,omitempty"`
	FailureStage        string `json:"failure_stage,omitempty"`
	FailureReason       string `json:"failure_reason,omitempty"`
	// AbortRequested is an encrypt_disk_abort received while preparing (decision 27); AbortCommandID is that command,
	// whose result the agent posts once the worker aborted.
	AbortRequested bool   `json:"abort_requested,omitempty"`
	AbortCommandID string `json:"abort_command_id,omitempty"`
	// Notified is the last restart notification per graphical session ID (decision 28).
	Notified map[string]time.Time `json:"notified,omitempty"`
	// CleanupPending is an unfinished cleanup: an initrd may still carry the module (invariant I3 of plan M8e §14.10).
	CleanupPending bool `json:"cleanup_pending,omitempty"`
	// ModuleWritten is set before step 7 writes the module (decision 13): from then on any initrd may carry the module
	// and the key, so the cleanup must verify every initrd before it deletes them (invariant I3).
	ModuleWritten bool `json:"module_written,omitempty"`
	// ModuleRestorePending is set when an adoption found the module, its dracut configuration or plan.env removed by a
	// cleanup: they are reinstalled and the initrds rebuilt before the initrd regeneration or the background phase
	// runs (plan M8e decision 18, invariant I2).
	ModuleRestorePending bool `json:"module_restore_pending,omitempty"`
	// CleanupError is why the last attempt of the pending cleanup did not finish (its first line); it is cleared whenever
	// CleanupPending is set or cleared, so that it never names an earlier cleanup (PDK-376).
	CleanupError string `json:"cleanup_error,omitempty"`
	// InitrdIssue is why the initrd work (cleanup, reinstall, regeneration) cannot go on: boot_space_low with
	// BootSpaceNeeded and BootSpaceFree, or no_bootable_kernel; "" otherwise (plan M8e amendment 2026-10-21, item 19).
	InitrdIssue     string `json:"initrd_issue,omitempty"`
	BootSpaceNeeded int64  `json:"boot_space_needed,omitempty"`
	BootSpaceFree   int64  `json:"boot_space_free,omitempty"`
	// InitrdIssueKernel is the kernel of kernel_not_buildable.
	InitrdIssueKernel string `json:"initrd_issue_kernel,omitempty"`
	// PackagesBusySince is when the preparation began to wait for a package run holding dpkg's locks (step 8); nil
	// while it does not wait (plan M8e amendment 2026-10-21, item 18).
	PackagesBusySince *time.Time `json:"packages_busy_since,omitempty"`
	// RevokedAt is a revocation hand-over after the conversion started encrypting: the conversion is terminal on the
	// device from then on (plan M8e amendment 2026-10-21, item 10).
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	// TransientErrors counts the passes of the preparation that ended on a tool error outside the closed set of
	// reasons; the preparation fails once encrypt.TransientRetries are used up.
	TransientErrors int `json:"transient_errors,omitempty"`
}

// PendingInstall is an install_now command waiting for the install worker.
type PendingInstall struct {
	CommandID string   `json:"command_id"`
	Packages  []string `json:"packages"`
}

// SupervisorRetry is a supervisor package version waiting for another attempt.
type SupervisorRetry struct {
	Version   string    `json:"version"`
	Attempts  int       `json:"attempts"`
	NotBefore time.Time `json:"not_before"`
	// Deferrals counts the upgrades of Version dpkg refused because another package run held its lock; they count
	// toward no failure.
	Deferrals int `json:"deferrals,omitempty"`
}

// PendingUninstall is an accepted uninstall command; Reported is set once the server accepted its result (2xx),
// LaunchedAt once the removal was started.
type PendingUninstall struct {
	CommandID  string     `json:"command_id"`
	Mode       string     `json:"mode"`
	Reported   bool       `json:"reported,omitempty"`
	LaunchedAt *time.Time `json:"launched_at,omitempty"`
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
	// InstallSlot is the keyslot of the install passphrase, recorded before the first change; RecoverySlot the
	// keyslot of the agent's current recovery key. Only these slots are ever removed (plan M4b.1 decision 3).
	// Both hold keyslot numbers, never key material; the JSON name passphrase_slot stays so existing state files load.
	InstallSlot  *int `json:"passphrase_slot,omitempty"`
	RecoverySlot *int `json:"recovery_slot,omitempty"`
	// Volumes are the LUKS volumes of /etc/crypttab other than the root volume, by LUKS UUID (PDK-009). Their header
	// generations share the counter HeaderAttempted with the root volume.
	Volumes map[string]*LUKSVolume `json:"volumes,omitempty"`
	// EnrollmentExpected is set by the agent once an in-place encryption completed without a TPM keyslot and cleared
	// once the keyslots are recorded with one: until then the first-boot disk setup's TPM keyslot is the expected
	// enrollment, no tampering (plan M8e amendment 2026-10-22, item 22).
	EnrollmentExpected bool `json:"enrollment_expected,omitempty"`
}

// LUKSVolume is the persistent state of a LUKS volume other than the root volume: the keyslot kinds recorded last
// (sorted), and the highest header generation the server stored with the digest of the metadata it was taken from.
// RefusedAt is when the server refused the volume's header (too many volumes, review round 2) and RefusedSet the
// volume set of /etc/crypttab then: the volume is not escrowed again for a day unless that set changed.
type LUKSVolume struct {
	Keyslots     []string   `json:"keyslots,omitempty"`
	HeaderStored int64      `json:"header_stored,omitempty"`
	HeaderDigest string     `json:"header_digest,omitempty"`
	RefusedAt    *time.Time `json:"refused_at,omitempty"`
	RefusedSet   string     `json:"refused_set,omitempty"`
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
