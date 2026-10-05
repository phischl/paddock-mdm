package worker

import (
	"context"
	"log/slog"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/paddock-mdm/paddock/server/internal/app"
	"github.com/paddock-mdm/paddock/server/internal/devicecache"
	"github.com/paddock-mdm/paddock/server/internal/ingest"
)

// Escrow consumes ingest.escrow: it stores each upload and publishes its status to esc:<escrow_id> (plan M4a
// decision 12). Ciphertexts are never logged.
type Escrow struct {
	escrow *app.Escrow
	cache  *devicecache.Cache
	pause  time.Duration
}

// NewEscrow creates the consumer.
func NewEscrow(escrow *app.Escrow, cache *devicecache.Cache) *Escrow {
	return &Escrow{escrow: escrow, cache: cache, pause: RetryPause}
}

// Handle is the mq.ConsumeFunc of queue ingest.escrow.
func (e *Escrow) Handle(ctx context.Context, _ *amqp.Channel, deliveries <-chan amqp.Delivery) error {
	return consume(ctx, deliveries, e.pause, func(ctx context.Context, d amqp.Delivery) outcome {
		return e.process(ctx, d.MessageId, d.Body)
	})
}

func (e *Escrow) process(ctx context.Context, messageID string, body []byte) outcome {
	var m ingest.Escrow
	if err := decode(body, &m); err != nil {
		return poison
	}
	ctx = systemContext(ctx, m.OrganizationID, messageID)
	status, err := e.escrow.Store(ctx, m)
	if err != nil {
		slog.WarnContext(ctx, "storing escrow upload failed; retrying", "device_id", m.DeviceID, "escrow_id", m.EscrowID, "error", err)
		return retry
	}
	if err := e.cache.PutEscrowStatus(ctx, m.EscrowID, m.DeviceID, status); err != nil {
		slog.WarnContext(ctx, "publishing escrow status failed; retrying", "escrow_id", m.EscrowID, "error", err)
		return retry
	}
	slog.InfoContext(ctx, "escrow upload processed", "device_id", m.DeviceID, "escrow_id", m.EscrowID, "kind", m.Kind,
		"generation", m.Generation, "status", status)
	return ack
}
