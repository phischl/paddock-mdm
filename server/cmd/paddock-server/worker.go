package main

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/phischl/paddock-mdm/server/internal/adapters/authentik"
	"github.com/phischl/paddock-mdm/server/internal/adapters/fleet"
	"github.com/phischl/paddock-mdm/server/internal/adapters/osvfeed"
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
	// Inventory (plan M5a decisions 2 and 6): Fleet's internal API with the API-only user's token.
	fleetURL := l.Required("PADDOCK_FLEET_URL")
	fleetToken := l.SecretFile("PADDOCK_FLEET_TOKEN_FILE")
	fleetPublicURL := l.Required("PADDOCK_FLEET_PUBLIC_URL")
	inventoryEvery := l.Duration("PADDOCK_INVENTORY_SYNC_INTERVAL", worker.DefaultInventorySyncInterval)
	// Ubuntu's vulnerability data (ADR 0020, plan M5c decision 1); development stacks download every interval from the
	// fixture server of gate O1 instead of once a day.
	osvURL := l.String("PADDOCK_OSV_UBUNTU_URL", osvfeed.DefaultURL)
	osvEvery := l.Duration("PADDOCK_OSV_SYNC_INTERVAL", 0)
	if osvEvery != 0 && (osvEvery < 0 || !common.Development()) {
		l.Invalid("PADDOCK_OSV_SYNC_INTERVAL", "only allowed with PADDOCK_ENV=development, and positive")
	}
	// Development stacks count the staleness thresholds in minutes (plan M5b decision 9, gate U4).
	stalenessUnit := config.StalenessUnit(l, common)
	if err := l.Err(); err != nil {
		return err
	}
	// Certificate expiry of the public hostnames, read from Caddy on the internal network (plan M6a decision 9).
	var tlsHosts []string
	for _, h := range strings.Split(l.String("PADDOCK_TLS_PROBE_HOSTS", ""), ",") {
		if h = strings.TrimSpace(h); h != "" {
			tlsHosts = append(tlsHosts, h)
		}
	}
	tlsAddr := l.String("PADDOCK_TLS_PROBE_ADDR", "caddy:443")
	backups, err := loadBackup(l, baoCfg.Addr)
	if err != nil {
		return err
	}
	pool, err := db.NewOrgPool(ctx, dsn, db.Options{ApplicationName: "paddock-worker", MaxConns: 8})
	if err != nil {
		return err
	}
	defer pool.Close()
	// The platform pool serves the rollout round (agent releases are platform data, plan M2b decision 19) and the host
	// mapping of the inventory round (plan M5a decision 6), and holds the advisory locks of the rollout, the two
	// identity, the dead man's switch, the inventory and the osv-sync rounds for their whole duration; two more
	// connections are left for those rounds' own queries and the readiness check.
	platformPool, err := db.NewPlatformPool(ctx, platformDSN, db.Options{ApplicationName: "paddock-worker-platform", MaxConns: 8})
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
	staleness := worker.NewStaleness(app.NewStaleness(runner, pool, stalenessUnit), pool, platformPool,
		min(worker.StalenessInterval, stalenessUnit/4))
	rollouts := worker.NewRollouts(app.NewAgentReleases(runner, platformPool, nil, nil, nil, common.Development()), platformPool, cache)
	ak := authentik.New(authentikURL, authentikToken)
	identity := worker.NewIdentity(app.NewIdentitySync(runner, pool, ak, ak, ak), ak, pool, platformPool, syncEvery, reconcileEvery)
	fleetClient := fleet.New(fleetURL, fleetToken, fleetPublicURL)
	inventory := worker.NewInventory(fleetClient, fleetClient, app.NewInventorySync(runner, pool, platformPool), pool,
		platformPool, inventoryEvery)
	osvSync := worker.NewOSV(app.NewOSV(runner, pool, platformPool), osvfeed.New(osvURL), pool, platformPool, osvEvery)
	slog.InfoContext(ctx, "worker starting")

	jobs := []func(context.Context) error{worker.NewOpsProbe(signer, worker.DialCertExpiry(tlsAddr), tlsHosts).Run}
	if backups != nil {
		jobs = append(jobs, worker.NewBackups(backups.store, backups.snap, backups.key, platformPool).Run)
	}
	return runAll(ctx, append(jobs,
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
		staleness.Run,
		rollouts.Run,
		identity.RunSync,
		identity.RunReconcile,
		identity.RunBrandFlows,
		inventory.RunSettings,
		inventory.RunSync,
		osvSync.Run,
	)...)
}
