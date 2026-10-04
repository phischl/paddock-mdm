package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/paddock-mdm/paddock/server/internal/config"
	"github.com/paddock-mdm/paddock/server/internal/outbox"
	"github.com/paddock-mdm/paddock/server/internal/platform/db"
	"github.com/paddock-mdm/paddock/server/internal/platform/mq"
	"github.com/paddock-mdm/paddock/server/internal/platform/ops"
)

func serveOutboxRelay(ctx context.Context, l *config.Loader, common config.Common) error {
	dsn := l.SecretFile("PADDOCK_DB_RELAY_URL_FILE")
	amqpCfg := config.LoadAMQP(l)
	threshold := outbox.DefaultReaperThreshold
	if common.Development() {
		threshold = l.Duration("PADDOCK_REAPER_THRESHOLD", threshold)
	}
	if err := l.Err(); err != nil {
		return err
	}
	pool, err := db.NewRelayPool(ctx, dsn, db.Options{ApplicationName: "paddock-outbox-relay", MaxConns: 4})
	if err != nil {
		return err
	}
	defer pool.Close()
	pub := mq.NewPublisher(mq.Config{URL: amqpCfg.URL, User: amqpCfg.User, Password: amqpCfg.Password})
	defer pub.Close()

	relay := outbox.NewRelay(pool, pub)
	reaper := outbox.NewReaper(pool, threshold)
	slog.InfoContext(ctx, "outbox-relay starting", "reaper_threshold", threshold)

	return runAll(ctx,
		func(ctx context.Context) error {
			return ops.Serve(ctx, common.OpsAddr, func(ctx context.Context) error {
				return errors.Join(pool.Ping(ctx), pub.Ping())
			})
		},
		relay.Run,
		func(ctx context.Context) error { relay.RunCleanup(ctx); return nil },
		func(ctx context.Context) error { reaper.Run(ctx); return nil },
	)
}

func provisionRabbitMQ(ctx context.Context, l *config.Loader) error {
	amqpCfg := config.LoadAMQP(l)
	maxBytes := l.Int("PADDOCK_AUDIT_QUEUE_MAX_BYTES", 1<<30)
	if maxBytes < 1 {
		l.Invalid("PADDOCK_AUDIT_QUEUE_MAX_BYTES", "must be positive")
	}
	ingestMaxBytes := l.Int("PADDOCK_INGEST_QUEUE_MAX_BYTES", mq.DefaultIngestQueueMaxBytes)
	if ingestMaxBytes < 1 {
		l.Invalid("PADDOCK_INGEST_QUEUE_MAX_BYTES", "must be positive")
	}
	if err := l.Err(); err != nil {
		return err
	}
	cfg := mq.Config{URL: amqpCfg.URL, User: amqpCfg.User, Password: amqpCfg.Password}
	var err error
	for attempt := 0; attempt < 30; attempt++ {
		if err = mq.Provision(ctx, cfg, mq.ProvisionOptions{
			AuditQueueMaxBytes: int64(maxBytes), IngestQueueMaxBytes: int64(ingestMaxBytes),
		}); err == nil {
			return nil
		}
		slog.WarnContext(ctx, "provision rabbitmq failed; retrying", "error", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return err
}
