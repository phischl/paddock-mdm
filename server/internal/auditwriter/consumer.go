package auditwriter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
)

// Batching parameters (plan M0 step 6).
const (
	Prefetch     = 1000
	MaxBatch     = 500
	MaxBatchWait = 5 * time.Second
	RetryPause   = 5 * time.Second
)

// Handle is an mq.ConsumeFunc: it collects batches of up to MaxBatch messages or MaxBatchWait, writes them and
// acknowledges them after the database commit. On any error it pauses RetryPause and nacks the batch with
// requeue=true; the quorum queue's delivery limit dead-letters poison messages. Messages that are not valid audit
// events are rejected without requeue (dead-lettered immediately).
func (w *Writer) Handle(ctx context.Context, ch *amqp.Channel, deliveries <-chan amqp.Delivery) error {
	return w.consume(ctx, deliveries, nil)
}

// consume is Handle; retire, when set, runs for every organization.audit_retirement_requested of a batch after the
// batch is written and before it is acknowledged, so a failed retirement is retried with the redelivered batch.
func (w *Writer) consume(ctx context.Context, deliveries <-chan amqp.Delivery, retire func(ctx context.Context, org uuid.UUID) error) error {
	for {
		batch, open := collect(ctx, deliveries)
		if len(batch) > 0 {
			if err := w.process(ctx, batch, retire); err != nil {
				return err
			}
		}
		if !open || ctx.Err() != nil {
			return errors.New("delivery channel closed")
		}
	}
}

// collect waits for the first delivery, then gathers more until MaxBatch or MaxBatchWait.
func collect(ctx context.Context, deliveries <-chan amqp.Delivery) ([]amqp.Delivery, bool) {
	var batch []amqp.Delivery
	select {
	case <-ctx.Done():
		return nil, false
	case d, ok := <-deliveries:
		if !ok {
			return nil, false
		}
		batch = append(batch, d)
	}
	timer := time.NewTimer(MaxBatchWait)
	defer timer.Stop()
	for len(batch) < MaxBatch {
		select {
		case <-ctx.Done():
			return batch, false
		case <-timer.C:
			return batch, true
		case d, ok := <-deliveries:
			if !ok {
				return batch, false
			}
			batch = append(batch, d)
		}
	}
	return batch, true
}

func (w *Writer) process(ctx context.Context, batch []amqp.Delivery, retire func(ctx context.Context, org uuid.UUID) error) error {
	events := make([]audit.Event, 0, len(batch))
	valid := make([]amqp.Delivery, 0, len(batch))
	for _, d := range batch {
		var ev audit.Event
		err := json.Unmarshal(d.Body, &ev)
		if err == nil {
			err = Validate(ev)
		}
		if err == nil && d.MessageId != "" && d.MessageId != ev.EventID.String() {
			err = errors.New("message_id differs from event_id")
		}
		if err != nil {
			slog.ErrorContext(ctx, "invalid audit message dead-lettered", "message_id", d.MessageId, "error", err)
			if rerr := d.Reject(false); rerr != nil {
				return rerr
			}
			continue
		}
		events = append(events, ev)
		valid = append(valid, d)
	}
	if len(valid) == 0 {
		return nil
	}
	last := valid[len(valid)-1]
	n, err := w.WriteBatch(ctx, events)
	if err == nil && retire != nil {
		err = retireRequested(ctx, events, retire)
	}
	if err != nil {
		slog.ErrorContext(ctx, "audit batch failed; requeueing", "events", len(events), "error", err)
		select {
		case <-ctx.Done():
		case <-time.After(RetryPause):
		}
		for _, d := range valid {
			if nerr := d.Nack(false, true); nerr != nil {
				return nerr
			}
		}
		return nil
	}
	slog.DebugContext(ctx, "audit batch committed", "messages", len(valid), "new_events", n)
	for _, d := range valid {
		if d.DeliveryTag > last.DeliveryTag {
			last = d
		}
	}
	return ackUpTo(valid, last)
}

// ackUpTo acknowledges every valid delivery. Rejected deliveries in between are already settled, so a multiple
// ack is only used when the batch has no gaps.
func ackUpTo(valid []amqp.Delivery, last amqp.Delivery) error {
	if uint64(len(valid)) == last.DeliveryTag-valid[0].DeliveryTag+1 {
		return last.Ack(true)
	}
	for _, d := range valid {
		if err := d.Ack(false); err != nil {
			return err
		}
	}
	return nil
}

// retireRequested calls retire for the organization of every organization.audit_retirement_requested in events. Only
// the platform pseudo-organization's successful request counts: an organization's own events reach the platform
// pseudo-organization only through the platform scope of ActionRunner. A request without a valid organization_id is
// logged and skipped, so it does not block the queue.
func retireRequested(ctx context.Context, events []audit.Event, retire func(ctx context.Context, org uuid.UUID) error) error {
	for _, ev := range events {
		if ev.Code != audit.CodeOrganizationAuditRetirementRequested || ev.OrganizationID != audit.PlatformOrganizationID ||
			ev.Outcome != audit.OutcomeSuccess {
			continue
		}
		raw, _ := ev.Params["organization_id"].(string)
		org, err := uuid.Parse(raw)
		if err != nil || org == uuid.Nil || org == audit.PlatformOrganizationID {
			slog.ErrorContext(ctx, "audit retirement request without a valid organization_id skipped", "event_id", ev.EventID)
			continue
		}
		if err := retire(ctx, org); err != nil {
			return fmt.Errorf("retire organization %s: %w", org, err)
		}
	}
	return nil
}
