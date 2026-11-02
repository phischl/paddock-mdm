package outbound

import (
	"time"

	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
)

// MessageSchema is the value of Message.Schema.
const MessageSchema = "paddock.notification.v1"

// Kinds of a message.
const (
	KindEvents     = "events"
	KindHeartbeat  = "heartbeat"
	KindTest       = "test"
	KindCheckpoint = "checkpoint"
)

// PlatformOrganization is Message.Organization for the platform scope.
const PlatformOrganization = "platform"

// Message is the envelope paddock.notification.v1 (plan M9 §6.4). Heartbeat and test messages carry an empty,
// non-nil Events; a checkpoint (M12) carries none.
type Message struct {
	Schema         string         `json:"schema"`
	Kind           string         `json:"kind"`
	DeliveryID     string         `json:"delivery_id"`
	DestinationID  string         `json:"destination_id"`
	OrganizationID string         `json:"organization_id"`
	Organization   string         `json:"organization"`
	SentAt         time.Time      `json:"sent_at"`
	ForwardSeq     *SeqRange      `json:"forward_seq,omitempty"`
	Cursor         *int64         `json:"cursor,omitempty"`
	Events         []MessageEvent `json:"events,omitzero"`
	Day            string         `json:"day,omitempty"`
	EventCount     int            `json:"event_count,omitempty"`
	ManifestSHA256 string         `json:"manifest_sha256,omitempty"`
	Signature      string         `json:"signature,omitempty"`
	KeyVersion     int            `json:"key_version,omitempty"`
}

// SeqRange is the forward sequence of a message: From and To for events, Last for a heartbeat.
type SeqRange struct {
	From int64  `json:"from,omitzero"`
	To   int64  `json:"to,omitzero"`
	Last *int64 `json:"last,omitempty"`
}

// MessageEvent is one forwarded audit event.
type MessageEvent struct {
	ForwardSeq int64       `json:"forward_seq"`
	CommitSeq  int64       `json:"commit_seq"`
	Links      *Links      `json:"links,omitempty"`
	Event      audit.Event `json:"event"`
}

// Links point into the portal; Device only for events whose target is a device.
type Links struct {
	Device string `json:"device,omitempty"`
}

// Heartbeat returns the heartbeat message after forward sequence last at audit cursor cursor; the caller sets the
// delivery fields.
func Heartbeat(last, cursor int64) Message {
	return Message{
		Schema: MessageSchema, Kind: KindHeartbeat,
		ForwardSeq: &SeqRange{Last: &last}, Cursor: &cursor, Events: []MessageEvent{},
	}
}

// Checkpoint returns the daily checkpoint message of plan M9 §6.4 (sent from M12); the caller sets the delivery
// fields.
func Checkpoint(day string, eventCount int, manifestSHA256, signature string, keyVersion int) Message {
	return Message{
		Schema: MessageSchema, Kind: KindCheckpoint, Day: day, EventCount: eventCount,
		ManifestSHA256: manifestSHA256, Signature: signature, KeyVersion: keyVersion,
	}
}
