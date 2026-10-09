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

	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
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

// HandleTimeout bounds the handling of one message by consumeConcurrently, whose handlers do not end with the loops.
const HandleTimeout = 2 * time.Minute

// consumeConcurrently runs n consume loops over the same deliveries until all of them have returned and returns the
// first error; for queues whose messages may be settled in any order. A failing loop ends the receiving of the others,
// not a message they are handling: a handler runs until it is done or HandleTimeout has passed.
func consumeConcurrently(ctx context.Context, deliveries <-chan amqp.Delivery, n int, pause time.Duration,
	handle func(ctx context.Context, d amqp.Delivery) outcome) error {
	detached := func(ctx context.Context, d amqp.Delivery) outcome {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), HandleTimeout)
		defer cancel()
		return handle(ctx, d)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, n)
	for range n {
		go func() {
			err := consume(ctx, deliveries, pause, detached)
			cancel() // one failed loop (closed channel, failed ack) ends the others, so the consumer reconnects
			errs <- err
		}()
	}
	var first error
	for range n {
		if err := <-errs; first == nil {
			first = err
		}
	}
	return first
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
