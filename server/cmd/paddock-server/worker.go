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
	"github.com/paddock-mdm/paddock/server/internal/platform/bao"
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
	baoCfg := config.LoadOpenBao(l)
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
	// The worker's AppRole may only sign with command-signing (plan M4a decision 2).
	signer, err := bao.New(baoCfg.Addr, baoCfg.RoleID, baoCfg.SecretID)
	if err != nil {
		return err
	}
	runner := app.NewActionRunner(pool, platformPool, httpx.RequestID)
	mqCfg := mq.Config{URL: amqpCfg.URL, User: amqpCfg.User, Password: amqpCfg.Password}
	enrollQueue := mq.NewConsumer(mqCfg, mq.IngestQueue(mq.IngestEnroll), worker.Prefetch)
	heartbeatQueue := mq.NewConsumer(mqCfg, mq.IngestQueue(mq.IngestHeartbeat), worker.Prefetch)
	eventQueue := mq.NewConsumer(mqCfg, mq.IngestQueue(mq.IngestEvent), worker.Prefetch)
	issuedQueue := mq.NewConsumer(mqCfg, mq.QueueCommandIssued, worker.Prefetch)
	resultQueue := mq.NewConsumer(mqCfg, mq.IngestQueue(mq.IngestCommandResult), worker.Prefetch)
	queues := []*mq.Consumer{enrollQueue, heartbeatQueue, eventQueue, issuedQueue, resultQueue}
	enroll := worker.NewEnrollment(app.NewEnrollments(runner, pool), cache)
	deviceCommands := app.NewDeviceCommands(pool)
	reports := worker.NewReports(app.NewDeviceReports(runner, pool), deviceCommands, cache)
	commands := worker.NewCommands(deviceCommands, pool, platformPool, cache, signer)
	cacheSync := worker.NewCacheSync(pool, cache)
	rollouts := worker.NewRollouts(app.NewAgentReleases(runner, platformPool, nil, nil, common.Development()), platformPool, cache)
	ak := authentik.New(authentikURL, authentikToken)
	identity := worker.NewIdentity(app.NewIdentitySync(runner, pool, ak, ak, ak), ak, pool, platformPool, syncEvery, reconcileEvery)
	slog.InfoContext(ctx, "worker starting")

	return runAll(ctx,
		func(ctx context.Context) error {
			return ops.Serve(ctx, common.OpsAddr, func(ctx context.Context) error {
				var notConnected error
				for _, q := range queues {
					if !q.Connected() {
						notConnected = errors.New("rabbitmq consumers not connected")
					}
				}
				return errors.Join(pool.Ping(ctx), platformPool.Ping(ctx), valkey.Ping(ctx, vk), signer.Ping(ctx), notConnected)
			})
		},
		func(ctx context.Context) error { return enrollQueue.Run(ctx, enroll.Handle) },
		func(ctx context.Context) error { return heartbeatQueue.Run(ctx, reports.HandleHeartbeats) },
		func(ctx context.Context) error { return eventQueue.Run(ctx, reports.HandleEvents) },
		func(ctx context.Context) error { return issuedQueue.Run(ctx, commands.HandleIssued) },
		func(ctx context.Context) error { return resultQueue.Run(ctx, commands.HandleResults) },
		commands.Run,
		cacheSync.Run,
		rollouts.Run,
		identity.RunSync,
		identity.RunReconcile,
		identity.RunBrandFlows,
	)
}
