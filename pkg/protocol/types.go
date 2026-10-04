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
}

// Device event types accepted by POST /v1/events (closed set, plan M2a decision 14 and M2b decision 23).
const (
	EventBundleApplied        = "bundle.applied"
	EventBundleRejected       = "bundle.rejected"
	EventConfigDriftCorrected = "config.drift_corrected"
	EventAgentUpdated         = "agent.updated"
	EventAgentUpdateFailed    = "agent.update_failed"
	EventAgentRolledBack      = "agent.rolled_back"
	EventAgentEventsDropped   = "agent.events_dropped"
)

// EventTypes is the closed set of event types.
var EventTypes = []string{
	EventBundleApplied, EventBundleRejected, EventConfigDriftCorrected, EventAgentUpdated, EventAgentUpdateFailed,
	EventAgentRolledBack, EventAgentEventsDropped,
}

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
