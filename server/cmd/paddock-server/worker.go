package main

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/paddock-mdm/paddock/server/internal/adapters/authentik"
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
	platformDSN := l.SecretFile("PADDOCK_DB_PLATFORM_URL_FILE")
	amqpCfg := config.LoadAMQP(l)
	vkCfg := config.LoadValkey(l)
	authentikURL := strings.TrimRight(l.Required("PADDOCK_AUTHENTIK_URL"), "/")
	authentikToken := l.SecretFile("PADDOCK_AUTHENTIK_TOKEN_FILE")
	syncEvery := l.Duration("PADDOCK_IDENTITY_SYNC_INTERVAL", worker.DefaultIdentitySyncInterval)
	reconcileEvery := l.Duration("PADDOCK_IDENTITY_RECONCILE_INTERVAL", worker.DefaultReconcileInterval)
	if err := l.Err(); err != nil {
		return err
	}
	pool, err := db.NewOrgPool(ctx, dsn, db.Options{ApplicationName: "paddock-worker", MaxConns: 8})
	if err != nil {
		return err
	}
	defer pool.Close()
	// The platform pool serves the rollout round (agent releases are platform data, plan M2b decision 19) and holds
	// the advisory locks of the rollout and the two identity rounds for their whole duration; one more connection is
	// left for the readiness check.
	platformPool, err := db.NewPlatformPool(ctx, platformDSN, db.Options{ApplicationName: "paddock-worker-platform", MaxConns: 5})
	if err != nil {
		return err
	}
	defer platformPool.Close()
	vk, err := valkey.New(valkey.Config{Addr: vkCfg.Addr, Password: vkCfg.Password})
	if err != nil {
		return err
	}
	defer vk.Close()
	cache := devicecache.New(vk)
	runner := app.NewActionRunner(pool, platformPool, httpx.RequestID)
	mqCfg := mq.Config{URL: amqpCfg.URL, User: amqpCfg.User, Password: amqpCfg.Password}
	enrollQueue := mq.NewConsumer(mqCfg, mq.IngestQueue(mq.IngestEnroll), worker.Prefetch)
	heartbeatQueue := mq.NewConsumer(mqCfg, mq.IngestQueue(mq.IngestHeartbeat), worker.Prefetch)
	eventQueue := mq.NewConsumer(mqCfg, mq.IngestQueue(mq.IngestEvent), worker.Prefetch)
	enroll := worker.NewEnrollment(app.NewEnrollments(runner, pool), cache)
	reports := worker.NewReports(app.NewDeviceReports(runner, pool), cache)
	cacheSync := worker.NewCacheSync(pool, cache)
	rollouts := worker.NewRollouts(app.NewAgentReleases(runner, platformPool, nil, nil, common.Development()), platformPool, cache)
	ak := authentik.New(authentikURL, authentikToken)
	identity := worker.NewIdentity(app.NewIdentitySync(runner, pool, ak, ak, ak), pool, platformPool, syncEvery, reconcileEvery)
	slog.InfoContext(ctx, "worker starting")

	return runAll(ctx,
		func(ctx context.Context) error {
			return ops.Serve(ctx, common.OpsAddr, func(ctx context.Context) error {
				var notConnected error
				if !enrollQueue.Connected() || !heartbeatQueue.Connected() || !eventQueue.Connected() {
					notConnected = errors.New("rabbitmq consumers not connected")
				}
				return errors.Join(pool.Ping(ctx), platformPool.Ping(ctx), valkey.Ping(ctx, vk), notConnected)
			})
		},
		func(ctx context.Context) error { return enrollQueue.Run(ctx, enroll.Handle) },
		func(ctx context.Context) error { return heartbeatQueue.Run(ctx, reports.HandleHeartbeats) },
		func(ctx context.Context) error { return eventQueue.Run(ctx, reports.HandleEvents) },
		cacheSync.Run,
		rollouts.Run,
		identity.RunSync,
		identity.RunReconcile,
	)
}
