// Package ingest defines the messages the gateway publishes to exchange paddock.ingest and the worker consumes
// (architecture §8.1). The AMQP message_id is the natural key of each message.
package ingest

import (
	"time"

	"github.com/google/uuid"
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
