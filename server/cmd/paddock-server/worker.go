package main

import (
	"context"
	"errors"
	"log/slog"

	"github.com/paddock-mdm/paddock/server/internal/app"
	"github.com/paddock-mdm/paddock/server/internal/config"
	"github.com/paddock-mdm/paddock/server/internal/devicecache"
	"github.com/paddock-mdm/paddock/server/internal/platform/db"
	"github.com/paddock-mdm/paddock/server/internal/platform/httpx"
	"github.com/paddock-mdm/paddock/server/internal/platform/mq"
	"github.com/paddock-mdm/paddock/server/internal/platform/ops"
	"github.com/paddock-mdm/paddock/server/internal/platform/valkey"
	"github.com/paddock-mdm/paddock/server/internal/worker"
)

func serveWorker(ctx context.Context, l *config.Loader, common config.Common) error {
	dsn := l.SecretFile("PADDOCK_DB_WORKER_URL_FILE")
	amqpCfg := config.LoadAMQP(l)
	vkCfg := config.LoadValkey(l)
	if err := l.Err(); err != nil {
		return err
	}
	pool, err := db.NewOrgPool(ctx, dsn, db.Options{ApplicationName: "paddock-worker", MaxConns: 8})
	if err != nil {
		return err
	}
	defer pool.Close()
	vk, err := valkey.New(valkey.Config{Addr: vkCfg.Addr, Password: vkCfg.Password})
	if err != nil {
		return err
	}
	defer vk.Close()
	cache := devicecache.New(vk)
	// The worker acts only in organization scope; it has no platform pool.
	runner := app.NewActionRunner(pool, nil, httpx.RequestID)
	mqCfg := mq.Config{URL: amqpCfg.URL, User: amqpCfg.User, Password: amqpCfg.Password}
	enrollQueue := mq.NewConsumer(mqCfg, mq.IngestQueue(mq.IngestEnroll), worker.Prefetch)
	enroll := worker.NewEnrollment(app.NewEnrollments(runner, pool), cache)
	cacheSync := worker.NewCacheSync(pool, cache)
	slog.InfoContext(ctx, "worker starting")

	return runAll(ctx,
		func(ctx context.Context) error {
			return ops.Serve(ctx, common.OpsAddr, func(ctx context.Context) error {
				var notConnected error
				if !enrollQueue.Connected() {
					notConnected = errors.New("rabbitmq consumer not connected")
				}
				return errors.Join(pool.Ping(ctx), valkey.Ping(ctx, vk), notConnected)
			})
		},
		func(ctx context.Context) error { return enrollQueue.Run(ctx, enroll.Handle) },
		cacheSync.Run,
	)
}
