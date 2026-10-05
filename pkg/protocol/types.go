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
)

// EventTypes is the closed set of event types.
var EventTypes = []string{
	EventBundleApplied, EventBundleRejected, EventConfigDriftCorrected, EventAgentUpdated, EventAgentUpdateFailed,
	EventAgentRolledBack, EventAgentEventsDropped, EventSessionLogin,
	EventLoginApplied, EventLoginApplyFailed, EventUserLockApplied, EventLoginsSuspensionApplied, EventSudoApplyFailed,
	EventSudoUserUnresolved, EventTamperSudoGroupMember, EventTamperSudoersDFile, EventTamperSudoersChanged,
	EventTamperProtectedFileChanged,
}

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
	// TamperSudoGroupMember: a member of a privileged local group that is no break-glass account.
	TamperSudoGroupMember struct {
		Group    string `json:"group"`
		Username string `json:"username"`
		Removed  bool   `json:"removed"`
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
	// TamperProtectedFileChanged: a protected file the agent cannot restore itself was changed (e.g. a PAM file).
	TamperProtectedFileChanged struct {
		File string `json:"file"`
	}
)

// Stages of LoginApplyFailed.
const (
	LoginStageApt      = "apt"
	LoginStageConfig   = "config"
	LoginStageRestart  = "restart"
	LoginStageDenyList = "deny_list"
	LoginStagePAM      = "pam"
	LoginStageSessions = "sessions"
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
// pins BundleKeys as its trust anchor.
type EnrollmentConfig struct {
	ServerURL      string      `json:"server_url"`
	OrganizationID string      `json:"organization_id"`
	Token          string      `json:"token"`
	BundleKeys     []BundleKey `json:"bundle_keys"`
}
