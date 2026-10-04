// Package ingest defines the messages the gateway publishes to exchange paddock.ingest and the worker consumes
// (architecture §8.1). The AMQP message_id is the natural key of each message.
package ingest

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/pkg/protocol"
)

// Enroll is an accepted enrollment request (routing key ingest.enroll.<org>, message_id = EnrollmentID). The
// gateway has verified proof of possession and that the token was usable at that time.
type Enroll struct {
	EnrollmentID   uuid.UUID         `json:"enrollment_id"`
	OrganizationID uuid.UUID         `json:"organization_id"`
	TokenSHA256    []byte            `json:"token_sha256"`
	KeyID          string            `json:"key_id"`
	PublicKey      []byte            `json:"public_key"` // SubjectPublicKeyInfo DER
	KeyProtection  string            `json:"key_protection"`
	Hostname       string            `json:"hostname"`
	HardwareUUID   string            `json:"hardware_uuid,omitempty"`
	MachineID      string            `json:"machine_id,omitempty"`
	OSRelease      map[string]string `json:"os_release,omitempty"`
	AgentVersion   string            `json:"agent_version"`
	ReceivedAt     time.Time         `json:"received_at"`
}

// Heartbeat is one check-in (routing key ingest.heartbeat.<org>, message_id random). Seq is the sequence number the
// gateway issued; ReportedSeq the Paddock-Seq the device sent. CloneSuspected is set when ReportedSeq is older than
// the last issued value minus one (architecture §6.4).
type Heartbeat struct {
	DeviceID             uuid.UUID       `json:"device_id"`
	OrganizationID       uuid.UUID       `json:"organization_id"`
	ReceivedAt           time.Time       `json:"received_at"`
	AppliedBundleVersion int64           `json:"applied_bundle_version"`
	AgentVersion         string          `json:"agent_version"`
	SchemaVersions       []int           `json:"schema_versions,omitempty"`
	Health               json.RawMessage `json:"health,omitempty"`
	EventSeqHigh         int64           `json:"event_seq_high"`
	Seq                  int64           `json:"seq"`
	ReportedSeq          int64           `json:"reported_seq"`
	CloneSuspected       bool            `json:"clone_suspected"`
}

// Events is a batch of device events (routing key ingest.event.<org>, message_id random).
type Events struct {
	DeviceID       uuid.UUID        `json:"device_id"`
	OrganizationID uuid.UUID        `json:"organization_id"`
	ReceivedAt     time.Time        `json:"received_at"`
	Events         []protocol.Event `json:"events"`
}
