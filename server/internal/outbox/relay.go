// Package outbox moves outbox rows from PostgreSQL to RabbitMQ (at-least-once, publisher confirms) and finalizes
// stuck actions (reaper). Role: outbox-relay.
package outbox

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/paddock-mdm/paddock/server/internal/adapters/postgres/pgstore"
	"github.com/paddock-mdm/paddock/server/internal/platform/db"
	"github.com/paddock-mdm/paddock/server/internal/platform/mq"
)

var (
	metricUnpublished = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "paddock_outbox_unpublished", Help: "Outbox rows not yet published.",
	})
	metricPublished = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "paddock_outbox_publish_total", Help: "Outbox publish attempts per message by result.",
	}, []string{"result"})
)

// Publisher is the subset of mq.Publisher the relay needs.
type Publisher interface {
	PublishBatch(ctx context.Context, exchange string, msgs []mq.Message) ([]error, error)
}

// Relay publishes outbox rows in id order.
type Relay struct {
	pool      *db.RelayPool
	pub       Publisher
	batchSize int32
	poll      time.Duration
	// afterConfirm runs after all confirms arrived and before published_at is written (tests simulate a crash).
	afterConfirm func() error
}

// NewRelay creates a relay with the plan defaults (batches of 500, 1 s poll fallback).
func NewRelay(pool *db.RelayPool, pub Publisher) *Relay {
	return &Relay{pool: pool, pub: pub, batchSize: 500, poll: time.Second}
}

// errPartial means some rows of a batch were not confirmed; they stay unpublished and are retried.
var errPartial = errors.New("outbox: some messages were not confirmed")

// Run publishes until ctx ends: on LISTEN notifications, every poll interval, and with back-off 1 s → 30 s after
// failures.
func (r *Relay) Run(ctx context.Context) error {
	notify := make(chan struct{}, 1)
	go r.listen(ctx, notify)
	go r.gauge(ctx)

	backoff := time.Second
	for {
		n, err := r.PublishOnce(ctx)
		switch {
		case ctx.Err() != nil:
			return nil
		case err != nil:
			slog.WarnContext(ctx, "outbox publish failed; retrying", "error", err, "backoff", backoff)
			if !sleep(ctx, backoff) {
				return nil
			}
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		backoff = time.Second
		if n == int(r.batchSize) {
			continue // more rows are waiting
		}
		select {
		case <-ctx.Done():
			return nil
		case <-notify:
		case <-time.After(r.poll):
		}
	}
}

// PublishOnce publishes one batch. Rows are marked published only after the broker confirmed and routed them.
func (r *Relay) PublishOnce(ctx context.Context) (int, error) {
	var claimed int
	var failed int
	err := r.pool.InRelay(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		rows, err := q.ClaimOutboxBatch(ctx, r.batchSize)
		if err != nil {
			return err
		}
		claimed = len(rows)
		if len(rows) == 0 {
			return nil
		}
		msgs := make([]mq.Message, len(rows))
		for i, row := range rows {
			rk, err := routingKey(row.Subject)
			if err != nil {
				return err
			}
			msgs[i] = mq.Message{RoutingKey: rk, MessageID: row.MsgID, Body: row.Payload}
		}
		results, err := r.pub.PublishBatch(ctx, mq.ExchangeAudit, msgs)
		if err != nil {
			metricPublished.WithLabelValues("error").Add(float64(len(msgs)))
			return err
		}
		if r.afterConfirm != nil {
			if err := r.afterConfirm(); err != nil {
				return err
			}
		}
		ids := make([]int64, 0, len(rows))
		for i, res := range results {
			switch {
			case res == nil:
				ids = append(ids, rows[i].ID)
				metricPublished.WithLabelValues("success").Inc()
			case errors.Is(res, mq.ErrReturned):
				failed++
				metricPublished.WithLabelValues("returned").Inc()
				slog.ErrorContext(ctx, "outbox message unroutable", "msg_id", rows[i].MsgID, "subject", rows[i].Subject)
			default:
				failed++
				metricPublished.WithLabelValues("nack").Inc()
				slog.WarnContext(ctx, "outbox message not confirmed", "msg_id", rows[i].MsgID, "error", res)
			}
		}
		if len(ids) > 0 {
			if _, err := q.MarkOutboxPublished(ctx, ids); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if failed > 0 {
		return claimed, fmt.Errorf("%w: %d of %d", errPartial, failed, claimed)
	}
	return claimed, nil
}

// Cleanup deletes rows published more than retention ago.
func (r *Relay) Cleanup(ctx context.Context, retention time.Duration) (int64, error) {
	var n int64
	before := time.Now().Add(-retention)
	err := r.pool.InRelay(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		n, err = q.DeletePublishedOutbox(ctx, &before)
		return err
	})
	return n, err
}

// RunCleanup deletes rows published more than 7 days ago, hourly.
func (r *Relay) RunCleanup(ctx context.Context) {
	for {
		if n, err := r.Cleanup(ctx, 7*24*time.Hour); err != nil {
			slog.WarnContext(ctx, "outbox cleanup failed", "error", err)
		} else if n > 0 {
			slog.InfoContext(ctx, "outbox cleanup", "deleted", n)
		}
		if !sleep(ctx, time.Hour) {
			return
		}
	}
}

func (r *Relay) listen(ctx context.Context, notify chan<- struct{}) {
	for ctx.Err() == nil {
		if err := r.pool.Listen(ctx, "outbox", notify); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "outbox LISTEN failed; polling continues", "error", err)
			sleep(ctx, 5*time.Second)
		}
	}
}

func (r *Relay) gauge(ctx context.Context) {
	for {
		_ = r.pool.InRelay(ctx, func(ctx context.Context, q *pgstore.Queries) error {
			n, err := q.CountUnpublishedOutbox(ctx)
			if err == nil {
				metricUnpublished.Set(float64(n))
			}
			return err
		})
		if !sleep(ctx, 10*time.Second) {
			return
		}
	}
}

// routingKey turns the subject audit.<organization_id>.<source> into the routing key audit.<source>.<organization_id>.
func routingKey(subject string) (string, error) {
	parts := strings.Split(subject, ".")
	if len(parts) != 3 || parts[0] != "audit" {
		return "", fmt.Errorf("outbox: unexpected subject %q", subject)
	}
	return "audit." + parts[2] + "." + parts[1], nil
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
