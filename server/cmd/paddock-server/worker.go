package main

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/phischl/paddock-mdm/server/internal/adapters/authentik"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/config"
	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/platform/mq"
	"github.com/phischl/paddock-mdm/server/internal/platform/objectstore"
	"github.com/phischl/paddock-mdm/server/internal/platform/ops"
	"github.com/phischl/paddock-mdm/server/internal/platform/valkey"
	"github.com/phischl/paddock-mdm/server/internal/worker"
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
	// Verifies uploaded LUKS headers with a read-only credential of paddock-escrow (plan M4b decision 13).
	escrowObjects := objectstore.New(l.Required("PADDOCK_ESCROW_S3_ENDPOINT"), l.SecretFile("PADDOCK_ESCROW_S3_ACCESS_KEY_FILE"),
		l.SecretFile("PADDOCK_ESCROW_S3_SECRET_KEY_FILE"), l.String("PADDOCK_ESCROW_S3_BUCKET", "paddock-escrow"))
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
	escrowQueue := mq.NewConsumer(mqCfg, mq.IngestQueue(mq.IngestEscrow), worker.Prefetch)
	queues := []*mq.Consumer{enrollQueue, heartbeatQueue, eventQueue, issuedQueue, resultQueue, escrowQueue}
	enroll := worker.NewEnrollment(app.NewEnrollments(runner, pool), cache)
	deviceCommands := app.NewDeviceCommands(pool)
	reports := worker.NewReports(app.NewDeviceReports(runner, pool), deviceCommands, cache)
	commands := worker.NewCommands(deviceCommands, app.NewRevocationReports(runner, pool), pool, platformPool, cache, signer)
	escrowStore := worker.NewEscrow(app.NewEscrow(pool, escrowObjects), cache, pool, platformPool)
	cacheSync := worker.NewCacheSync(pool, cache)
	dms := worker.NewDMS(app.NewDMS(runner, pool, cache, false, false), pool, platformPool)
	rollouts := worker.NewRollouts(app.NewAgentReleases(runner, platformPool, nil, nil, nil, common.Development()), platformPool, cache)
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
		func(ctx context.Context) error { return escrowQueue.Run(ctx, escrowStore.Handle) },
		commands.Run,
		escrowStore.Run,
		cacheSync.Run,
		dms.Run,
		rollouts.Run,
		identity.RunSync,
		identity.RunReconcile,
		identity.RunBrandFlows,
	)
}
