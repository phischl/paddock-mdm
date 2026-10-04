package compiler

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/paddock-mdm/paddock/server/internal/domain/statechange"
)

// Batching of state changes: the compiler waits until a partition has been quiet for Debounce (at most MaxWait), so
// a bulk change produces one version per device (architecture §7.1).
const (
	Prefetch   = 500
	Debounce   = 2 * time.Second
	MaxWait    = 10 * time.Second
	RetryPause = 5 * time.Second
)

// Handle is the mq.ConsumeFunc of one state partition queue. A batch is acknowledged after all of its devices are
// published; a failure requeues the whole batch (content-equal devices are skipped on retry).
func (c *Compiler) Handle(ctx context.Context, _ *amqp.Channel, deliveries <-chan amqp.Delivery) error {
	for {
		batch, open := collect(ctx, deliveries, Debounce, MaxWait, Prefetch)
		if len(batch) > 0 {
			if err := c.process(ctx, batch); err != nil {
				return err
			}
		}
		if !open || ctx.Err() != nil {
			return errors.New("delivery channel closed")
		}
	}
}

func (c *Compiler) process(ctx context.Context, batch []amqp.Delivery) error {
	var events []statechange.Event
	var valid []amqp.Delivery
	oldest := time.Now()
	for _, d := range batch {
		var ev statechange.Event
		if err := json.Unmarshal(d.Body, &ev); err != nil || !ev.Valid() {
			slog.ErrorContext(ctx, "invalid state change dead-lettered", "message_id", d.MessageId)
			if err := d.Reject(false); err != nil {
				return err
			}
			continue
		}
		events = append(events, ev)
		valid = append(valid, d)
		if !d.Timestamp.IsZero() && d.Timestamp.Before(oldest) {
			oldest = d.Timestamp
		}
	}
	if len(valid) == 0 {
		return nil
	}
	if err := c.Compile(ctx, events); err != nil {
		slog.WarnContext(ctx, "compile failed; requeueing", "state_changes", len(valid), "error", err)
		select {
		case <-ctx.Done():
		case <-time.After(RetryPause):
		}
		for _, d := range valid {
			if err := d.Nack(false, true); err != nil {
				return err
			}
		}
		return nil
	}
	metricLatency.Observe(time.Since(oldest).Seconds())
	for _, d := range valid {
		if err := d.Ack(false); err != nil {
			return err
		}
	}
	return nil
}

// collect waits for the first delivery, then gathers more until none arrived for quiet, maxWait passed or max
// deliveries are collected.
func collect(ctx context.Context, deliveries <-chan amqp.Delivery, quiet, maxWait time.Duration, maxCount int) ([]amqp.Delivery, bool) {
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
	deadline := time.NewTimer(maxWait)
	defer deadline.Stop()
	for len(batch) < maxCount {
		idle := time.NewTimer(quiet)
		select {
		case <-ctx.Done():
			idle.Stop()
			return batch, false
		case <-deadline.C:
			idle.Stop()
			return batch, true
		case <-idle.C:
			return batch, true
		case d, ok := <-deliveries:
			idle.Stop()
			if !ok {
				return batch, false
			}
			batch = append(batch, d)
		}
	}
	return batch, true
}
