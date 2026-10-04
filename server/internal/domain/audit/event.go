// Package audit defines the audit event schema paddock.audit.v1 and the closed code registry (architecture §14).
// Events are never translated or rewritten.
package audit

import (
	"time"

	"github.com/google/uuid"
)

// Schema is the value of Event.Schema.
const Schema = "paddock.audit.v1"

// PlatformOrganizationID is the platform pseudo-organization of platform-level events.
var PlatformOrganizationID = uuid.Nil

// Outcome is the result of a privileged action.
type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
	OutcomeDenied  Outcome = "denied"
	OutcomeUnknown Outcome = "unknown"
)

// Actor types.
const (
	ActorAdmin         = "admin"
	ActorPlatformAdmin = "platform_admin"
	ActorSystem        = "system"
	ActorAnonymous     = "anonymous"
	ActorDevice        = "device"
)

// Sources.
const (
	SourcePortal   = "portal"
	SourcePlatform = "platform"
	SourceSystem   = "system"
	SourceDevice   = "device"
)

// Actor is who performed the action.
type Actor struct {
	Type    string `json:"type"` // "admin" | "platform_admin" | "system" | "anonymous" | "device"
	ID      string `json:"id,omitempty"`
	Display string `json:"display,omitempty"`
	IP      string `json:"ip,omitempty"`
	StepUp  bool   `json:"step_up"`
}

// Target is what the action was performed on.
type Target struct {
	Type    string `json:"type"` // "organization" | "device_group" | "admin_account" | "device" | "enrollment_token" | "managed_file" | "managed_unit"
	ID      string `json:"id"`
	Display string `json:"display,omitempty"`
}

// Event is one audit event. RecordedAt is set by the audit writer and omitted in the outbox payload.
type Event struct {
	Schema         string         `json:"schema"`
	EventID        uuid.UUID      `json:"event_id"`
	OrganizationID uuid.UUID      `json:"organization_id"`
	OccurredAt     time.Time      `json:"occurred_at"`
	RecordedAt     time.Time      `json:"recorded_at,omitzero"`
	Code           Code           `json:"code"`
	Outcome        Outcome        `json:"outcome"`
	Actor          Actor          `json:"actor"`
	Target         *Target        `json:"target,omitempty"`
	Source         string         `json:"source"`
	Params         map[string]any `json:"params"`
	ErrorCode      string         `json:"error_code,omitempty"`
	CorrelationID  string         `json:"correlation_id"`
}

// SourceForActor derives the event source from the actor type.
func SourceForActor(actorType string) string {
	switch actorType {
	case ActorAdmin, ActorAnonymous:
		return SourcePortal
	case ActorPlatformAdmin:
		return SourcePlatform
	case ActorDevice:
		return SourceDevice
	default:
		return SourceSystem
	}
}

// Subject is the outbox subject audit.<organization_id>.<source>.
func Subject(org uuid.UUID, source string) string { return "audit." + org.String() + "." + source }

// RoutingKey is the RabbitMQ routing key audit.<source>.<organization_id> (architecture §5 rule 7).
func RoutingKey(org uuid.UUID, source string) string { return "audit." + source + "." + org.String() }

// Timestamp normalizes t to UTC with millisecond precision.
func Timestamp(t time.Time) time.Time { return t.UTC().Truncate(time.Millisecond) }
