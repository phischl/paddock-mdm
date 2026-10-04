// Package worker is the worker role: it consumes the ingest queues, turns device messages into database changes
// through the use cases, and keeps the device cache in Valkey in step with PostgreSQL (architecture §3.2, plan M2a
// decisions 10, 12 and 14).
package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/paddock-mdm/paddock/server/internal/platform/httpx"
	"github.com/paddock-mdm/paddock/server/internal/principal"
	"github.com/paddock-mdm/paddock/server/internal/problem"
)

// Prefetch is the consumer prefetch of every ingest queue (architecture §8.1).
const Prefetch = 100

// RetryPause delays the requeue of a message that failed for a transient reason (database or Valkey down).
const RetryPause = 5 * time.Second

// outcome is how a delivery is settled.
type outcome int

const (
	ack    outcome = iota // processed (or permanently rejected and recorded)
	retry                 // transient failure: requeue after RetryPause
	poison                // not a valid message: dead-letter at once
)

// systemContext is the context of one message: a system principal of the message's organization and the message
// ID as correlation ID of audit events.
func systemContext(ctx context.Context, org uuid.UUID, messageID string) context.Context {
	ctx = principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker", OrganizationID: org})
	return httpx.WithRequestID(ctx, messageID)
}

// permanent reports whether err is a rejection that a retry cannot change (a 4xx problem).
func permanent(err error) bool {
	var p *problem.Error
	return errors.As(err, &p) && p.Status < 500
}

// consume settles every delivery with handle until the channel closes or ctx ends (mq.ConsumeFunc).
func consume(ctx context.Context, deliveries <-chan amqp.Delivery, pause time.Duration,
	handle func(ctx context.Context, d amqp.Delivery) outcome) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case d, ok := <-deliveries:
			if !ok {
				return errors.New("delivery channel closed")
			}
			if err := settle(ctx, d, handle(ctx, d), pause); err != nil {
				return err
			}
		}
	}
}

func settle(ctx context.Context, d amqp.Delivery, o outcome, pause time.Duration) error {
	switch o {
	case ack:
		return d.Ack(false)
	case poison:
		slog.ErrorContext(ctx, "invalid ingest message dead-lettered", "queue_key", d.RoutingKey, "message_id", d.MessageId)
		return d.Reject(false)
	default:
		select {
		case <-ctx.Done():
		case <-time.After(pause):
		}
		// The quorum queue's delivery limit dead-letters a message that keeps failing.
		return d.Nack(false, true)
	}
}

// decode parses a message body strictly.
func decode(body []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
