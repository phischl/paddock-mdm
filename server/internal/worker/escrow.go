package worker

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// EscrowInterval is the period of the header round: pending LUKS headers are verified against their uploaded
// objects (plan M4b decision 10).
const EscrowInterval = 10 * time.Second

// escrowLockKey is the advisory lock of the header round ("paddesc").
const escrowLockKey = 0x70616464657363

// Escrow consumes ingest.escrow: it stores each upload and publishes its status to esc:<escrow_id> (plan M4a
// decision 12); the header round publishes the status of LUKS headers once their objects are verified. Ciphertexts
// are never logged.
type Escrow struct {
	escrow   *app.Escrow
	cache    *devicecache.Cache
	pool     *db.OrgPool
	platform *db.PlatformPool
	pause    time.Duration
	interval time.Duration
}

// NewEscrow creates the consumer and the header round.
func NewEscrow(escrow *app.Escrow, cache *devicecache.Cache, pool *db.OrgPool, platform *db.PlatformPool) *Escrow {
	return &Escrow{escrow: escrow, cache: cache, pool: pool, platform: platform, pause: RetryPause, interval: EscrowInterval}
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
	// A pending header gets its status from the header round.
	if status != escrow.StatusPending {
		if err := e.cache.PutEscrowStatus(ctx, m.EscrowID, m.DeviceID, status); err != nil {
			slog.WarnContext(ctx, "publishing escrow status failed; retrying", "escrow_id", m.EscrowID, "error", err)
			return retry
		}
	}
	slog.InfoContext(ctx, "escrow upload processed", "device_id", m.DeviceID, "escrow_id", m.EscrowID, "kind", m.Kind,
		"generation", m.Generation, "status", status)
	return ack
}

// Run runs the header round at start and then every interval until ctx ends; only the replica holding the lock
// acts.
func (e *Escrow) Run(ctx context.Context) error {
	tick := time.NewTicker(e.interval)
	defer tick.Stop()
	for {
		if err := e.Round(ctx); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "escrow header round failed; retrying next round", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// Round verifies the pending headers of every organization and publishes the status of those that finished.
func (e *Escrow) Round(ctx context.Context) error {
	sys := principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker"})
	_, err := e.platform.WithLeaderLock(sys, escrowLockKey, func(ctx context.Context) error {
		orgs, err := e.pool.OrganizationIDs(ctx)
		if err != nil {
			return err
		}
		for _, org := range orgs {
			outcomes, err := e.escrow.VerifyHeaders(systemContext(ctx, org, "escrow-round"))
			for _, o := range outcomes {
				if perr := e.cache.PutEscrowStatus(ctx, o.EscrowID, o.DeviceID, o.Status); perr != nil {
					return perr
				}
			}
			if err != nil {
				return fmt.Errorf("organization %s: %w", org, err)
			}
		}
		return nil
	})
	return err
}
