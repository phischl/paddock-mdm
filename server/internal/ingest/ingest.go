// Package ingest defines the messages the gateway publishes to exchange paddock.ingest and the worker consumes
// (architecture §8.1). The AMQP message_id is the natural key of each message.
package ingest

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/protocol"
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
	// DeliveredCommands are the commands the check-in response carried (plan M4a decision 3).
	DeliveredCommands []uuid.UUID `json:"delivered_commands,omitempty"`
}

// Events is a batch of device events (routing key ingest.event.<org>, message_id random).
type Events struct {
	DeviceID       uuid.UUID        `json:"device_id"`
	OrganizationID uuid.UUID        `json:"organization_id"`
	ReceivedAt     time.Time        `json:"received_at"`
	Events         []protocol.Event `json:"events"`
}

// Escrow is an escrowed secret uploaded by a device (routing key ingest.escrow.<org>, message_id = EscrowID, plan M4a
// decision 12). Ciphertext is the RSA-OAEP ciphertext; only OpenBao can decrypt it.
type Escrow struct {
	DeviceID       uuid.UUID `json:"device_id"`
	OrganizationID uuid.UUID `json:"organization_id"`
	EscrowID       uuid.UUID `json:"escrow_id"`
	Kind           string    `json:"kind"`
	Generation     int64     `json:"generation"`
	KeyVersion     int       `json:"key_version"`
	Ciphertext     []byte    `json:"ciphertext"`
	ReceivedAt     time.Time `json:"received_at"`
}

// CommandResult is the result of a device command (routing key ingest.command_result.<org>, message_id = CommandID +
// ":" + Status). The gateway checked that the command was pending for the device.
type CommandResult struct {
	DeviceID       uuid.UUID       `json:"device_id"`
	OrganizationID uuid.UUID       `json:"organization_id"`
	CommandID      uuid.UUID       `json:"command_id"`
	Status         string          `json:"status"`
	Result         json.RawMessage `json:"result,omitempty"`
	ReceivedAt     time.Time       `json:"received_at"`
}
