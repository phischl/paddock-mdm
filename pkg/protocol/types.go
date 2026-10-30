package protocol

import (
	"encoding/json"
	"time"
)

// Problem codes of the device API (RFC 9457 "code" member).
const (
	CodeInvalidRequest   = "invalid_request"
	CodeInvalidSignature = "invalid_signature"
	CodeClockSkew        = "clock_skew"
	CodeReplay           = "replay"
	CodeInvalidToken     = "invalid_token"
	CodeIdentityRevoked  = "identity_revoked"
	CodeUnknownEventType = "unknown_event_type"
	CodeNotFound         = "not_found"
	CodeRateLimited      = "rate_limited"
	CodeBackpressure     = "backpressure"
	CodePayloadTooLarge  = "payload_too_large"
	CodeConflict         = "conflict"
)

// Problem is the RFC 9457 body of device API errors. 401 responses carry ServerTime.
type Problem struct {
	Type       string     `json:"type"`
	Title      string     `json:"title"`
	Status     int        `json:"status"`
	Code       string     `json:"code"`
	Detail     string     `json:"detail,omitempty"`
	Instance   string     `json:"instance,omitempty"`
	ServerTime *time.Time `json:"server_time,omitempty"`
}

// Key protection values of EnrollRequest.KeyProtection.
const (
	KeyProtectionTPM  = "tpm"
	KeyProtectionFile = "file"
)

// EnrollRequest is the body of POST /v1/enroll.
type EnrollRequest struct {
	Token         string            `json:"token"`
	PublicKey     string            `json:"public_key"` // standard base64 SubjectPublicKeyInfo DER
	KeyProtection string            `json:"key_protection"`
	Hostname      string            `json:"hostname"`
	HardwareUUID  string            `json:"hardware_uuid,omitempty"`
	MachineID     string            `json:"machine_id,omitempty"`
	OSRelease     map[string]string `json:"os_release,omitempty"`
	AgentVersion  string            `json:"agent_version"`
}

// EnrollAccepted is the 202 body of POST /v1/enroll.
type EnrollAccepted struct {
	EnrollmentID string `json:"enrollment_id"`
}

// Enrollment states of GET /v1/enroll/{id}.
const (
	EnrollProcessing = "processing"
	EnrollPending    = "pending"
	EnrollActive     = "active"
	EnrollRejected   = "rejected"
)

// EnrollStatus is the body of GET /v1/enroll/{id}.
type EnrollStatus struct {
	Status   string `json:"status"`
	DeviceID string `json:"device_id,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// CheckinRequest is the body of POST /v1/checkin.
type CheckinRequest struct {
	AppliedBundleVersion int64           `json:"applied_bundle_version"`
	AgentVersion         string          `json:"agent_version"`
	SchemaVersions       []int           `json:"schema_versions"`
	Health               json.RawMessage `json:"health,omitempty"`
	EventSeqHigh         int64           `json:"event_seq_high"`
	Arch                 string          `json:"arch,omitempty"` // runtime.GOARCH: ArchAMD64 or ArchARM64
}

// Agent architectures of CheckinRequest.Arch.
const (
	ArchAMD64 = "amd64"
	ArchARM64 = "arm64"
)

// AgentUpdate offers an agent release to an eligible device (plan M2b decision 21).
type AgentUpdate struct {
	Version string `json:"version"`
	URL     string `json:"url"`     // presigned GET of the paddockd binary
	SHA256  string `json:"sha256"`  // hex SHA-256 of the binary
	Size    int64  `json:"size"`    // bytes
	Minisig string `json:"minisig"` // standard base64 of the .minisig file
	// Requested is set when an administrator asked this device to install the release now (plan M8d decision 27):
	// the offer ignores the rollout wave, and the agent ignores its update policy for it. Older agents ignore it. A
	// device that already runs the release gets its own version marked requested while the request is open, so that
	// it may upgrade paddock-supervisor and fleetd under the manual policy.
	Requested bool `json:"requested,omitempty"`
	// RequestedAt is when the request was made; the agent handles each request once.
	RequestedAt *time.Time `json:"requested_at,omitempty"`
}

// BundleRef points to a bundle newer than the applied one.
type BundleRef struct {
	Version int64  `json:"version"`
	SHA256  string `json:"sha256"` // hex SHA-256 of the DSSE envelope object
	URL     string `json:"url"`    // presigned GET, valid for 120 s
}

// CheckinResponse is the 200 body of POST /v1/checkin.
type CheckinResponse struct {
	Seq          int64        `json:"seq"`
	ServerTime   time.Time    `json:"server_time"`
	Bundle       *BundleRef   `json:"bundle"`
	NextCheckinS int          `json:"next_checkin_s"`
	AgentUpdate  *AgentUpdate `json:"agent_update"`
	// Commands are the device's pending commands, each a DSSE envelope verified with pkg/command (plan M4a
	// decision 3).
	Commands []json.RawMessage `json:"commands"`
	// TimeTicket is the organization's newest time ticket (DSSE, pkg/timeticket), absent until the first one was
	// issued (plan M4c decision 14).
	TimeTicket json.RawMessage `json:"time_ticket,omitempty"`
}

// Command result statuses of CommandResult.Status.
const (
	CommandSucceeded = "succeeded"
	CommandFailed    = "failed"
)

// MaxCommandResult bounds the result object of POST /v1/commands/{command_id}/result.
const MaxCommandResult = 4 << 10

// CommandResult is the body of POST /v1/commands/{command_id}/result. Result is a JSON object of at most
// MaxCommandResult bytes; it never carries secrets.
type CommandResult struct {
	Status string          `json:"status"`
	Result json.RawMessage `json:"result,omitempty"`
}

// Device event types accepted by POST /v1/events (closed set, plan M2a decision 14, M2b decision 23, M3a decision
// 10, M3b decision 5).
const (
	EventBundleApplied        = "bundle.applied"
	EventBundleRejected       = "bundle.rejected"
	EventConfigDriftCorrected = "config.drift_corrected"
	EventAgentUpdated         = "agent.updated"
	EventAgentUpdateFailed    = "agent.update_failed"
	EventAgentRolledBack      = "agent.rolled_back"
	EventAgentEventsDropped   = "agent.events_dropped"
	EventSessionLogin         = "session.login"
	// Identity and privileges on the device (plan M3b decision 5).
	EventLoginApplied               = "login.applied"
	EventLoginApplyFailed           = "login.apply_failed"
	EventUserLockApplied            = "user.lock_applied"
	EventLoginsSuspensionApplied    = "logins.suspension_applied"
	EventSudoApplyFailed            = "sudo.apply_failed"
	EventSudoUserUnresolved         = "sudo.user_unresolved"
	EventTamperSudoGroupMember      = "tamper.sudo_group_member"
	EventTamperSudoersDFile         = "tamper.sudoers_d_file"
	EventTamperSudoersChanged       = "tamper.sudoers_changed"
	EventTamperProtectedFileChanged = "tamper.protected_file_changed"
	// Managed local administrator (plan M4a decisions 15, 16 and 18).
	EventLocalAdminRotated        = "local_admin.rotated"
	EventLocalAdminRotationFailed = "local_admin.rotation_failed"
	EventLocalAdminLogin          = "local_admin.login"
	EventTamperLocalAdminChanged  = "tamper.local_admin_changed"
	// Disk encryption (plan M4b decision 12).
	EventTamperKeyslotChanged = "tamper.keyslot_changed"
	// Revocation (plan M4c decision 3): a device enrolled before M4c pinned the revocation keys of its first bundle
	// that carried them (trust on first use).
	EventRevocationTrustPinnedTOFU = "revocation.trust_pinned_tofu"
	// paddock-revoke refused a revocation token; nothing changed on the device (plan M4c decision 11).
	EventRevocationRefused = "revocation.refused"
	// Mutual watch (plan M5a decision 5): a unit Paddock keeps running (fleetd's orbit.service) was found stopped;
	// the agent starts it again.
	EventTamperServiceStopped = "tamper.service_stopped"
	// Update management (plan M5b decision 6): one finished run of regular or security updates.
	EventUpdatesRun = "updates.run"
	// Supervisor package update (plan M8d decision 33): the outcome of one installation of the current release's
	// paddock-supervisor package; only sent by agents that received supervisor_packages in a bundle.
	EventAgentSupervisorUpdated = "agent.supervisor_updated"
	// Uninstall (plan M8d decision 40): the final report of `paddockd uninstall`, sent once after the command
	// uninstall; the device is retired by it.
	EventAgentUninstalled = "agent.uninstalled"
	// In-place encryption (plan M8e decision 9): the phases of a conversion; each event carries conversion_id.
	EventDiskConversionPrepared  = "disk.conversion_prepared"  // data: {conversion_id, layout, volume, data_bytes}
	EventDiskConversionStarted   = "disk.conversion_started"   // data: {conversion_id, volume, init_s, init_result, after_cancel}
	EventDiskConversionCompleted = "disk.conversion_completed" // data: {conversion_id, volume, data_bytes, duration_s}
	EventDiskConversionFailed    = "disk.conversion_failed"    // data: {conversion_id, stage, reason, volume}
	EventDiskConversionAborted   = "disk.conversion_aborted"   // data: {conversion_id, by}
	// The abort could not neutralize the prepared initrds (plan M8e item 18, amendment 2026-10-30): a restart before
	// the cleanup finished may still encrypt the disk.
	EventDiskConversionNeutralizeFailed = "disk.conversion_neutralize_failed" // data: {conversion_id, reason}
	// The unlock path of a converted disk could not be reinstalled after a cleanup had removed it (plan M8e decision 18,
	// amendment 2026-10-30): an initrd the disarm of a cancelled conversion neutralized cannot open the disk until then.
	EventDiskConversionUnlockRestoreFailed = "disk.conversion_unlock_restore_failed" // data: {conversion_id, reason}
)

// Outcomes of EventAgentUninstalled: completed when every step is done or skipped, else partial; helper_failed when
// the removal did not start.
const (
	UninstallCompleted = "completed"
	UninstallPartial   = "partial"
	// UninstallHelperFailed: the agent could not start the removal; nothing was removed.
	UninstallHelperFailed = "helper_failed"
)

// MaxUninstallSteps bounds the steps of EventAgentUninstalled.
const MaxUninstallSteps = 32

// AgentUninstalled is the data of agent.uninstalled.
type AgentUninstalled struct {
	CommandID  string            `json:"command_id"`
	Mode       string            `json:"mode"`
	Outcome    string            `json:"outcome"`
	LocalAdmin string            `json:"local_admin"` // removed, kept, kept_last_admin
	TPM        string            `json:"tpm"`         // cleared, requested_at_next_boot, skipped_in_use, not_requested, failed
	Steps      map[string]string `json:"steps"`       // step name → done, skipped or failed:<message>
}

// Outcomes of EventAgentSupervisorUpdated.
const (
	SupervisorOutcomeUpdated       = "updated"
	SupervisorOutcomeInstallFailed = "install_failed"
	SupervisorOutcomeRolledBack    = "rolled_back"
	// SupervisorOutcomeRolledBackUnreachable: the new supervisor ran stable, but the agent could not reach the server
	// within the wait, so the helper rolled back; the agent retries the version later (design contract 8, ADR 0037
	// amendment 2026-10-18).
	SupervisorOutcomeRolledBackUnreachable = "rolled_back_unreachable"
)

// Kinds and results of UpdatesRun.
const (
	UpdatesKindRegular   = "regular"
	UpdatesKindSecurity  = "security"
	UpdatesResultOK      = "ok"
	UpdatesResultFailed  = "failed"
	UpdatesResultTimeout = "timeout"
)

// MaxHeldBack bounds UpdatesRun.HeldBack.
const MaxHeldBack = 50

// UpdatesRun is the data of updates.run: a finished run of regular updates (paddockd updates run) or of the daily
// security updates (unattended-upgrades). HeldBack are the packages the run kept back, at most MaxHeldBack.
type UpdatesRun struct {
	Kind           string    `json:"kind"`
	StartedAt      time.Time `json:"started_at"`
	FinishedAt     time.Time `json:"finished_at"`
	Upgraded       int       `json:"upgraded"`
	HeldBack       []string  `json:"held_back"`
	RebootRequired bool      `json:"reboot_required"`
	Result         string    `json:"result"`
	Error          string    `json:"error,omitempty"`
}

// TamperServiceStopped is the data of tamper.service_stopped.
type TamperServiceStopped struct {
	Unit string `json:"unit"`
}

// EventTypes is the closed set of event types.
var EventTypes = []string{
	EventBundleApplied, EventBundleRejected, EventConfigDriftCorrected, EventAgentUpdated, EventAgentUpdateFailed,
	EventAgentRolledBack, EventAgentEventsDropped, EventSessionLogin,
	EventLoginApplied, EventLoginApplyFailed, EventUserLockApplied, EventLoginsSuspensionApplied, EventSudoApplyFailed,
	EventSudoUserUnresolved, EventTamperSudoGroupMember, EventTamperSudoersDFile, EventTamperSudoersChanged,
	EventTamperProtectedFileChanged,
	EventLocalAdminRotated, EventLocalAdminRotationFailed, EventLocalAdminLogin, EventTamperLocalAdminChanged,
	EventTamperKeyslotChanged,
	EventRevocationTrustPinnedTOFU, EventRevocationRefused,
	EventTamperServiceStopped,
	EventUpdatesRun,
	EventAgentSupervisorUpdated,
	EventAgentUninstalled,
	EventDiskConversionPrepared, EventDiskConversionStarted, EventDiskConversionCompleted, EventDiskConversionFailed,
	EventDiskConversionAborted, EventDiskConversionNeutralizeFailed, EventDiskConversionUnlockRestoreFailed,
}

// SudoGroupMemberKeptLastAdmin is the reason of a TamperSudoGroupMember whose member was kept because no break-glass
// account is a member of the group (ADR 0008 amendment 2026-10-17).
const SudoGroupMemberKeptLastAdmin = "last_admin"

// Disk states of DiskHealth (plan M4b decision 8), from the least to the most complete.
const (
	DiskNotEncrypted  = "not_encrypted"   // the root file system is not on LUKS
	DiskEncrypting    = "encrypting"      // an online reencryption of the root volume is unfinished (ADR 0039)
	DiskUnmanaged     = "unmanaged"       // encrypted, but not installed with the Paddock autoinstall
	DiskTPMMissing    = "tpm_missing"     // no TPM 2.0: the disk keeps its passphrase
	DiskTPMPINMissing = "tpm_pin_missing" // the boot PIN was skipped: the disk keeps its passphrase
	// DiskUnlockModeMismatch: the disk is enrolled for the other unlock mode than its policy (plan M8d decision 48).
	DiskUnlockModeMismatch = "unlock_mode_mismatch"
	DiskEscrowPending      = "escrow_pending" // recovery key, a header or the keyslot set not yet as required
	DiskCompliant          = "compliant"      // the mode's TPM keyslot and the recovery key only, escrowed with the current header of every volume
)

// DiskStates are the states in DiskHealth.
var DiskStates = []string{DiskNotEncrypted, DiskEncrypting, DiskUnmanaged, DiskTPMMissing, DiskTPMPINMissing, DiskUnlockModeMismatch,
	DiskEscrowPending, DiskCompliant}

// DiskHealth is the disk encryption of the device in the check-in health (health.disk, plan M4b decision 8).
// State, LUKSVersion, Tokens and Keyslots are those of the root volume; Volumes lists every LUKS volume, the root
// volume first (PDK-009 decision 4), and Unresolved the /etc/crypttab entries that could not be classified.
type DiskHealth struct {
	State       string       `json:"state"`
	LUKSVersion int          `json:"luks_version,omitempty"`
	Tokens      []string     `json:"tokens,omitempty"` // kind of every keyslot, sorted: tpm2+pin, recovery, password, …
	Keyslots    int          `json:"keyslots"`
	Volumes     []DiskVolume `json:"volumes,omitempty"`
	Unresolved  []string     `json:"unresolved,omitempty"`
	// UnlockMode is the unlock mode the agent applied (tpm_pin or tpm_only, plan M8d decision 48); "" from older
	// agents.
	UnlockMode string `json:"unlock_mode,omitempty"`
	// BootSeparate tells, in state not_encrypted only, whether /boot is a file system of its own (the layout an
	// in-place encryption could convert, ADR 0038).
	BootSeparate *bool `json:"boot_separate,omitempty"`
	// Conversion is the in-place encryption of the root volume (plan M8e decision 3); nil from older agents and on
	// devices that neither are unencrypted nor convert.
	Conversion *DiskConversion `json:"conversion,omitempty"`
}

// DiskConversion is the in-place encryption of the root volume in health.disk (ADR 0039): the eligibility of an
// unencrypted device and, from the preparation on, the phase and the progress.
type DiskConversion struct {
	Eligible bool     `json:"eligible"`
	Reasons  []string `json:"reasons,omitempty"` // the closed preflight reasons (plan M8e decision 2), sorted
	Release  string   `json:"release,omitempty"` // VERSION_ID of /etc/os-release (24.04 or 26.04)
	Layout   string   `json:"layout,omitempty"`  // lvm | plain
	// Initramfs is the installed initramfs generator: dracut when dpkg-query reports it installed, else
	// initramfs-tools (plan M8e decision 34).
	Initramfs string `json:"initramfs,omitempty"`
	// InitramfsRemoves is, under initramfs-tools only, what installing dracut would remove (the simulated apt
	// removal set, sorted; empty when the simulation failed).
	InitramfsRemoves []string `json:"initramfs_removes,omitempty"`
	// KeyOnBoot is true from the preparation until the initrd was regenerated: the conversion key lies in the
	// initrd on the unencrypted /boot (plan M8e decision 52).
	KeyOnBoot bool `json:"key_on_boot,omitempty"`
	// EnrollmentDeferred is set while the converted header is marked for the reencryption and no TPM keyslot exists:
	// reencrypt while encrypting (the boot PIN or the TPM unlock waits for the completion), reencrypt_after_completed
	// once completed (stop condition S15) (plan M8e amendment 2026-10-22, item 22).
	EnrollmentDeferred string `json:"enrollment_deferred,omitempty"`
	// CleanupError is why the last attempt of an unfinished cleanup (reason cleanup_pending) did not finish, its first
	// line (plan M8e amendment 2026-10-21, item 17).
	CleanupError string `json:"cleanup_error,omitempty"`
	Phase        string `json:"phase,omitempty"`      // prepared | encrypting | completed | failed
	DataBytes    int64  `json:"data_bytes,omitempty"` // bytes to encrypt (the partition minus the header)
	DoneBytes    int64  `json:"done_bytes,omitempty"`
	ETASeconds   int64  `json:"eta_s,omitempty"`
	PausedReason string `json:"paused_reason,omitempty"` // on_battery | helper_not_running | packages_busy
	// InitrdIssue is why the initrd work of a conversion cannot go on: boot_space_low (BootSpaceNeeded bytes needed,
	// BootSpaceFree free in /boot), no_bootable_kernel, kernel_not_buildable, orphan_initrd_removed,
	// key_material_hardlinked or key_material_shared_bootable (plan M8e amendment 2026-10-21, item 19).
	InitrdIssue     string `json:"initrd_issue,omitempty"`
	BootSpaceNeeded int64  `json:"boot_space_needed,omitempty"`
	BootSpaceFree   int64  `json:"boot_space_free,omitempty"`
	// InitrdIssueKernel names the kernel of initrd_issue kernel_not_buildable or key_material_shared_bootable (plan M8e
	// amendment 2026-10-21, item 19).
	InitrdIssueKernel string `json:"initrd_issue_kernel,omitempty"`
	// PausedSince is when a preparation began to wait with packages_busy (plan M8e amendment 2026-10-21, item 18).
	PausedSince   *time.Time `json:"paused_since,omitempty"`
	FailureStage  string     `json:"failure_stage,omitempty"` // preflight | prepare | init | resume
	FailureReason string     `json:"failure_reason,omitempty"`
	UpdatedAt     *time.Time `json:"updated_at,omitempty"`
}

// DiskVolume is one LUKS volume in health.disk. Escrowed is true when the server stored a header of its current
// keyslots; HeaderGeneration is the newest stored header generation of the volume (0: none).
type DiskVolume struct {
	UUID             string   `json:"uuid"`
	Device           string   `json:"device"`
	Root             bool     `json:"root,omitempty"`
	LUKSVersion      int      `json:"luks_version,omitempty"`
	Tokens           []string `json:"tokens,omitempty"`
	Keyslots         int      `json:"keyslots"`
	Escrowed         bool     `json:"escrowed"`
	HeaderGeneration int64    `json:"header_generation,omitempty"`
	// SharedUUID marks a volume whose LUKS UUID another volume or the root volume has (a cloned header): it is
	// neither escrowed nor tracked; a Destroy erases it, a Lock does not (PDK-009 review round 2).
	SharedUUID bool `json:"shared_uuid,omitempty"`
	// Refused marks a volume whose header the server refused (more volumes than a token carries).
	Refused bool `json:"refused,omitempty"`
}

// TamperKeyslotChanged is the data of tamper.keyslot_changed: the keyslots of a LUKS volume differ from those the
// agent recorded (plan M4b decision 12, PDK-009 decision 3). Volume is the LUKS UUID of the volume ("" when the
// root volume reported none); Before and After list the kind of every keyslot (tpm2+pin, recovery, password, …),
// sorted.
type TamperKeyslotChanged struct {
	Volume string   `json:"volume,omitempty"`
	Before []string `json:"before"`
	After  []string `json:"after"`
}

// The data of the managed local administrator's events (plan M4a decision 18). They never carry passwords,
// ciphertexts, terminals or remote hosts.
type (
	// LocalAdminRotated: the device set the password of generation, which the server had stored.
	LocalAdminRotated struct {
		Generation int64 `json:"generation"`
	}
	// LocalAdminRotationFailed: a rotation to generation did not happen; the previous password stays valid.
	LocalAdminRotationFailed struct {
		Generation int64  `json:"generation"`
		Reason     string `json:"reason"` // one of the RotationFailure constants
	}
	// LocalAdminLogin: a session of the local administrator was opened through the PAM service (e.g. sshd, login).
	LocalAdminLogin struct {
		Service string    `json:"service"`
		At      time.Time `json:"at"`
	}
	// TamperLocalAdminChanged: the account changed outside Paddock; Field is one of the LocalAdminField constants.
	TamperLocalAdminChanged struct {
		Field string `json:"field"`
	}
)

// Reasons of LocalAdminRotationFailed.
const (
	RotationEscrowFailed  = "escrow_failed"  // the server refused to store the password
	RotationEscrowTimeout = "escrow_timeout" // not stored within 15 minutes
	RotationApplyFailed   = "apply_failed"   // chpasswd failed
)

// Fields of TamperLocalAdminChanged.
const (
	LocalAdminFieldPassword = "password"
	LocalAdminFieldShell    = "shell"
	LocalAdminFieldGroup    = "group"
	LocalAdminFieldLocked   = "locked"
	LocalAdminFieldMissing  = "missing"
)

// SessionLogin is the data of a session.login event: a user logged in on the device. It carries only the username
// and the time, never process or command data (architecture §9.4); the server records it without an audit event.
type SessionLogin struct {
	Username string    `json:"username"`
	At       time.Time `json:"at"`
}

// The data of the identity and privilege events (plan M3b decision 5). They carry usernames and file names only,
// never process, command or session content.
type (
	// LoginApplied: the login reconciler changed the device; Changed lists what ("package", "config",
	// "deny_list").
	LoginApplied struct {
		Changed []string `json:"changed"`
	}
	// LoginApplyFailed: a stage of the login reconciler failed (Stage is one of the LoginStage constants).
	LoginApplyFailed struct {
		Stage   string `json:"stage"`
		Message string `json:"message"`
		// Reason classifies some failures, e.g. LoginFailureTimeout of stage apt.
		Reason string `json:"reason,omitempty"`
	}
	// UserLockApplied: a newly locked user is blocked on the device and its sessions were locked or terminated.
	UserLockApplied struct {
		Username           string `json:"username"`
		SessionsLocked     int    `json:"sessions_locked"`
		SessionsTerminated int    `json:"sessions_terminated"`
	}
	// LoginsSuspensionApplied: logins were suspended and the directory users' sessions terminated.
	LoginsSuspensionApplied struct {
		SessionsTerminated int `json:"sessions_terminated"`
	}
	// SudoApplyFailed: the sudoers file of a user (or the sudoers configuration as a whole, Username empty) could
	// not be applied; the previous state was kept or restored.
	SudoApplyFailed struct {
		Username string `json:"username,omitempty"`
		Message  string `json:"message"`
	}
	// SudoUserUnresolved: a user with a sudo entry has no UID on the device yet (never logged in).
	SudoUserUnresolved struct {
		Username string `json:"username"`
	}
	// TamperSudoGroupMember: a member of a privileged local group that is no break-glass account. Reason is
	// SudoGroupMemberKeptLastAdmin when the member was kept because no break-glass account is a member of the group.
	TamperSudoGroupMember struct {
		Group    string `json:"group"`
		Username string `json:"username"`
		Removed  bool   `json:"removed"`
		Reason   string `json:"reason,omitempty"`
	}
	// TamperSudoersDFile: an unexpected file in /etc/sudoers.d was moved to quarantine.
	TamperSudoersDFile struct {
		File          string `json:"file"`
		QuarantinedAs string `json:"quarantined_as"`
	}
	// TamperSudoersChanged: /etc/sudoers changed since the agent last recorded it (hex SHA-256).
	TamperSudoersChanged struct {
		SHA256Before string `json:"sha256_before"`
		SHA256After  string `json:"sha256_after"`
	}
	// TamperProtectedFileChanged: a protected file was changed outside Paddock: one the agent cannot restore itself
	// (e.g. a PAM file), or one of fleetd's files, which it restores (plan M5a decision 5).
	TamperProtectedFileChanged struct {
		File string `json:"file"`
	}
)

// LoginFailureTimeout is the Reason of a package operation the agent killed at its timeout (plan M4b.1 step 6).
const LoginFailureTimeout = "timeout"

// Stages of LoginApplyFailed.
const (
	LoginStageApt      = "apt"
	LoginStageConfig   = "config"
	LoginStageRestart  = "restart"
	LoginStageDenyList = "deny_list"
	LoginStagePAM      = "pam"
	LoginStageSessions = "sessions"
	LoginStageNotice   = "notice"
)

// MaxEventsPerBatch bounds POST /v1/events.
const MaxEventsPerBatch = 500

// Event is one device event.
type Event struct {
	EventSeq   int64           `json:"event_seq"`
	Type       string          `json:"type"`
	OccurredAt time.Time       `json:"occurred_at"`
	Data       json.RawMessage `json:"data,omitempty"`
}

// EventsRequest is the body of POST /v1/events.
type EventsRequest struct {
	Events []Event `json:"events"`
}

// BundleKey is a trusted bundle-signing public key.
type BundleKey struct {
	KeyID     string `json:"key_id"`     // e.g. "bundle-signing:v1"
	PublicKey string `json:"public_key"` // standard base64 raw Ed25519 public key
}

// EnrollmentConfig is the document an administrator receives once when creating an enrollment token; the device
// pins BundleKeys as its trust anchor, and RevocationKeys (the revocation-signing public keys, same shape) as the
// trust anchor of paddock-revoke (plan M4c decision 3). Configurations created before M4c have no RevocationKeys.
type EnrollmentConfig struct {
	ServerURL      string      `json:"server_url"`
	OrganizationID string      `json:"organization_id"`
	Token          string      `json:"token"`
	BundleKeys     []BundleKey `json:"bundle_keys"`
	RevocationKeys []BundleKey `json:"revocation_keys,omitempty"`
}
