package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/adapters/aptsign"
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
	"github.com/phischl/paddock-mdm/server/internal/sessions"
	"github.com/phischl/paddock-mdm/server/internal/worker"
)

// The values of PADDOCK_WORKER_MODE (plan M19 D1.1).
const (
	// workerModeFull runs the queue consumers and every round; one replica of it runs per control plane.
	workerModeFull = "full"
	// workerModeIngest runs only the queue consumers with a fraction of the connections, so that further replicas
	// for the ingest load (architecture N2) fit PostgreSQL's connection budget (docs/operations/capacity.md).
	workerModeIngest = "ingest"
)

// loadWorkerMode reads PADDOCK_WORKER_MODE, full by default.
func loadWorkerMode(l *config.Loader) string {
	mode := l.String("PADDOCK_WORKER_MODE", workerModeFull)
	if mode != workerModeFull && mode != workerModeIngest {
		l.Invalid("PADDOCK_WORKER_MODE", fmt.Sprintf("not full or ingest: %q", mode))
	}
	return mode
}

// workerPoolOptions returns the options of the worker's organization and platform pools in mode. A full worker holds
// at most 30 connections (organization 8, platform 8, leader locks 12, readiness 2), an ingest worker at most 11
// (organization 8, platform 2, readiness 1): it runs no round, so it needs neither lock connections nor a platform
// pool beyond the consumers' own queries (plan M19 D1.1).
func workerPoolOptions(mode string) (org, platform db.Options) {
	if mode == workerModeIngest {
		return db.Options{ApplicationName: "paddock-worker-ingest", MaxConns: 8, HealthConn: true},
			db.Options{ApplicationName: "paddock-worker-ingest-platform", MaxConns: 2}
	}
	// Readiness pings on connections of their own: long rounds may keep every query connection busy (PDK-1010).
	// The leader locks of the rounds sit in a lock pool of their own, because a round holds its lock connection for its
	// whole duration, which at many organizations is minutes; sharing the query pool, they starved it (PDK-1010).
	return db.Options{ApplicationName: "paddock-worker", MaxConns: 8, HealthConn: true},
		db.Options{ApplicationName: "paddock-worker-platform", MaxConns: 8, LockConns: worker.LeaderLockConns, HealthConn: true}
}

// openWorkerPools opens the organization and the platform pool of a worker in mode.
func openWorkerPools(ctx context.Context, mode, dsn, platformDSN string) (*db.OrgPool, *db.PlatformPool, error) {
	orgOpts, platformOpts := workerPoolOptions(mode)
	pool, err := db.NewOrgPool(ctx, dsn, orgOpts)
	if err != nil {
		return nil, nil, err
	}
	platformPool, err := db.NewPlatformPool(ctx, platformDSN, platformOpts)
	if err != nil {
		pool.Close()
		return nil, nil, err
	}
	return pool, platformPool, nil
}

// workerJobs returns the jobs of a worker in mode: the consumers, and in full mode also the rounds. rounds is called
// only in full mode, so an ingest worker never builds a round and never asks for a leader lock.
func workerJobs(mode string, consumers []func(context.Context) error, rounds func() []func(context.Context) error) []func(context.Context) error {
	if mode == workerModeIngest {
		return consumers
	}
	return append(consumers, rounds()...)
}

// workerSettings are the settings of the rounds, read in full mode only.
type workerSettings struct {
	authentikURL, authentikToken         string
	syncEvery, reconcileEvery            time.Duration
	repositoryIndex                      *objectstore.Store
	bundlesURL                           string
	fleetURL, fleetToken, fleetPublicURL string
	inventoryEvery                       time.Duration
	osvURL                               string
	osvEvery                             time.Duration
	stalenessUnit, retentionEvery        time.Duration
	indexRetention                       int
	tlsHosts                             []string
	tlsAddr                              string
	// offboarding holds the organization deletion's object-store credentials; PDK-1015's round runs its steps.
	offboarding *app.Offboarding
}

func loadWorkerSettings(l *config.Loader, common config.Common, retentionDay time.Duration) workerSettings {
	s := workerSettings{
		authentikURL:   strings.TrimRight(l.Required("PADDOCK_AUTHENTIK_URL"), "/"),
		authentikToken: l.SecretFile("PADDOCK_AUTHENTIK_TOKEN_FILE"),
		syncEvery:      l.Duration("PADDOCK_IDENTITY_SYNC_INTERVAL", worker.DefaultIdentitySyncInterval),
		reconcileEvery: l.Duration("PADDOCK_IDENTITY_RECONCILE_INTERVAL", worker.DefaultReconcileInterval),
	}
	// The organizations' Paddock repositories (plan M13c decision 13): the worker writes their signed index below
	// apt/<organization_id>/dists/ of the bundles bucket with a user that may write nothing else; the system source
	// names the repository on the public bundles host.
	s.bundlesURL = strings.TrimRight(l.Required("PADDOCK_BUNDLES_PUBLIC_URL"), "/")
	s.repositoryIndex = objectstore.New(l.Required("PADDOCK_BUNDLES_S3_ENDPOINT"), l.SecretFile("PADDOCK_BUNDLES_S3_ACCESS_KEY_FILE"),
		l.SecretFile("PADDOCK_BUNDLES_S3_SECRET_KEY_FILE"), l.String("PADDOCK_BUNDLES_S3_BUCKET", "paddock-bundles"))
	// Inventory (plan M5a decisions 2 and 6): Fleet's internal API with the API-only user's token.
	s.fleetURL = l.Required("PADDOCK_FLEET_URL")
	s.fleetToken = l.SecretFile("PADDOCK_FLEET_TOKEN_FILE")
	s.fleetPublicURL = l.Required("PADDOCK_FLEET_PUBLIC_URL")
	s.inventoryEvery = l.Duration("PADDOCK_INVENTORY_SYNC_INTERVAL", worker.DefaultInventorySyncInterval)
	// Ubuntu's vulnerability data (ADR 0020, plan M5c decision 1); development stacks download every interval from the
	// fixture server of gate O1 instead of once a day.
	s.osvURL = l.String("PADDOCK_OSV_UBUNTU_URL", osvfeed.DefaultURL)
	s.osvEvery = l.Duration("PADDOCK_OSV_SYNC_INTERVAL", 0)
	if s.osvEvery != 0 && (s.osvEvery < 0 || !common.Development()) {
		l.Invalid("PADDOCK_OSV_SYNC_INTERVAL", "only allowed with PADDOCK_ENV=development, and positive")
	}
	// Development stacks count the staleness thresholds in minutes (plan M5b decision 9, gate U4).
	s.stalenessUnit = config.StalenessUnit(l, common)
	// Development stacks run the retention round every 15 s unless PADDOCK_RETENTION_INTERVAL says otherwise (plan M10
	// amendment A3, gates TestLoginHistory and R1).
	retentionDefault := worker.RetentionInterval
	if retentionDay < time.Hour {
		retentionDefault = 15 * time.Second
	}
	s.retentionEvery = config.RetentionInterval(l, common, retentionDefault)
	s.indexRetention = workerIndexRetention(l)
	// Certificate expiry of the public hostnames, read from Caddy on the internal network (plan M6a decision 9).
	for _, h := range strings.Split(l.String("PADDOCK_TLS_PROBE_HOSTS", ""), ",") {
		if h = strings.TrimSpace(h); h != "" {
			s.tlsHosts = append(s.tlsHosts, h)
		}
	}
	s.tlsAddr = l.String("PADDOCK_TLS_PROBE_ADDR", "caddy:443")
	s.offboarding = app.NewOffboarding(loadOffboardingObjects(l))
	return s
}

// loadOffboardingObjects builds the organization deletion's two object-store clients from their own credentials,
// which list and delete but never read (plan M17 amendment k point 2). They go to app.NewOffboarding and nowhere else
// (TestOffboardingCredentialsOnlyForOffboarding). A missing credential file leaves its client nil: the step objects
// then fails closed with object_store_unavailable and the rest of the worker runs.
func loadOffboardingObjects(l *config.Loader) app.OffboardingObjects {
	var o app.OffboardingObjects
	bundlesAccess, ok1 := l.OptionalSecretFile("PADDOCK_OFFBOARD_BUNDLES_S3_ACCESS_KEY_FILE")
	bundlesSecret, ok2 := l.OptionalSecretFile("PADDOCK_OFFBOARD_BUNDLES_S3_SECRET_KEY_FILE")
	if ok1 && ok2 {
		o.Bundles = objectstore.New(l.Required("PADDOCK_BUNDLES_S3_ENDPOINT"), bundlesAccess, bundlesSecret,
			l.String("PADDOCK_BUNDLES_S3_BUCKET", "paddock-bundles"))
	}
	escrowAccess, ok1 := l.OptionalSecretFile("PADDOCK_OFFBOARD_ESCROW_S3_ACCESS_KEY_FILE")
	escrowSecret, ok2 := l.OptionalSecretFile("PADDOCK_OFFBOARD_ESCROW_S3_SECRET_KEY_FILE")
	if ok1 && ok2 {
		o.Escrow = objectstore.New(l.Required("PADDOCK_ESCROW_S3_ENDPOINT"), escrowAccess, escrowSecret,
			l.String("PADDOCK_ESCROW_S3_BUCKET", "paddock-escrow"))
	}
	if o.Bundles == nil || o.Escrow == nil {
		slog.Warn("organization deletion: its object-store credentials are missing; deleting an organization's objects fails until ./paddock secrets and ./paddock bootstrap buckets have run",
			"bundles", o.Bundles != nil, "escrow", o.Escrow != nil)
	}
	return o
}

func serveWorker(ctx context.Context, l *config.Loader, common config.Common) error {
	mode := loadWorkerMode(l)
	dsn := l.SecretFile("PADDOCK_DB_WORKER_URL_FILE")
	platformDSN := l.SecretFile("PADDOCK_DB_PLATFORM_URL_FILE")
	amqpCfg := config.LoadAMQP(l)
	vkCfg := config.LoadValkey(l)
	baoCfg := config.LoadOpenBao(l)
	// Verifies uploaded LUKS headers and diagnostics bundles with a credential of paddock-escrow that reads every object
	// and deletes diagnostics bundles only (plan M4b decision 13, plan M12 decision 7).
	escrowObjects := objectstore.New(l.Required("PADDOCK_ESCROW_S3_ENDPOINT"), l.SecretFile("PADDOCK_ESCROW_S3_ACCESS_KEY_FILE"),
		l.SecretFile("PADDOCK_ESCROW_S3_SECRET_KEY_FILE"), l.String("PADDOCK_ESCROW_S3_BUCKET", "paddock-escrow"))
	// Development stacks count the retention days in seconds (plan M8d decision 19).
	retentionDay := config.RetentionUnit(l, common)
	// An ingest worker runs no round, so it neither reads nor holds the rounds' settings and credentials.
	var s workerSettings
	if mode == workerModeFull {
		s = loadWorkerSettings(l, common, retentionDay)
	}
	if err := l.Err(); err != nil {
		return err
	}
	pool, platformPool, err := openWorkerPools(ctx, mode, dsn, platformDSN)
	if err != nil {
		return err
	}
	defer pool.Close()
	defer platformPool.Close()
	vk, err := valkey.New(valkey.Config{Addr: vkCfg.Addr, Username: vkCfg.Username, Password: vkCfg.Password})
	if err != nil {
		return err
	}
	defer vk.Close()
	cache := devicecache.New(vk)
	// The worker's AppRole may sign with command-signing (plan M4a decision 2) and encrypt and decrypt with
	// software-repo-wrap, the key of the repositories' signing keys (ADR 0050 decision 3).
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
	deviceCommands := app.NewDeviceCommands(runner, pool)
	reports := worker.NewReports(app.NewDeviceReports(runner, pool), deviceCommands, cache)
	commands := worker.NewCommands(deviceCommands, app.NewRevocationReports(runner, pool), pool, platformPool, cache, signer)
	diagnostics := worker.NewDiagnostics(app.NewDiagnostics(runner, pool, escrowObjects, retentionDay), pool, platformPool)
	escrowStore := worker.NewEscrow(app.NewEscrow(runner, pool, escrowObjects), cache, pool, platformPool).WithDiagnostics(diagnostics)
	consumers := []func(context.Context) error{
		func(ctx context.Context) error {
			return ops.ServeReporting(ctx, common.OpsAddr, "mode="+mode, func(ctx context.Context) error {
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
	}
	rounds := func() []func(context.Context) error {
		cacheSync := worker.NewCacheSync(pool, cache)
		dms := worker.NewDMS(app.NewDMS(runner, pool, cache, false, false), pool, platformPool)
		staleness := worker.NewStaleness(app.NewStaleness(runner, pool, s.stalenessUnit), pool, platformPool,
			min(worker.StalenessInterval, s.stalenessUnit/4)).Then(worker.NewFindings(app.NewFindings(runner, pool), pool, platformPool).Round)
		eventGaps := worker.NewEventGaps(app.NewEventGaps(runner, pool), pool, platformPool, min(worker.StalenessInterval, s.stalenessUnit/4))
		rollouts := worker.NewRollouts(app.NewAgentReleases(runner, platformPool, nil, nil, nil, common.Development()), platformPool, cache)
		configRollouts := worker.NewConfigRollouts(app.NewConfigRollouts(runner, pool), pool, platformPool)
		softwareRequests := worker.NewSoftwareRequests(app.NewSoftwareRequests(runner, pool), pool, platformPool, worker.SoftwareRequestInterval)
		softwareRepositories := worker.NewSoftwareRepositories(app.NewSoftwareRepositoryBuilds(runner, pool, signer,
			aptsign.Signer{}, s.repositoryIndex, s.bundlesURL), pool, platformPool)
		ak := authentik.New(s.authentikURL, s.authentikToken)
		reconcileAK := authentik.New(s.authentikURL, s.authentikToken).WithMaxConcurrent(worker.ReconcileAuthentikConcurrency)
		identity := worker.NewIdentity(app.NewIdentitySync(runner, pool, reconcileAK, ak, ak).WithEnsureRevision(authentik.EnsureRevision),
			app.NewAdminAccounts(runner, pool, platformPool, ak, sessions.NewStore(vk)), app.NewRoleMembership(runner, pool, platformPool, ak),
			app.NewMFAEnrolment(runner, platformPool, ak, ak), ak, pool, platformPool, s.syncEvery, s.reconcileEvery)
		fleetClient := fleet.New(s.fleetURL, s.fleetToken, s.fleetPublicURL)
		retention := worker.NewRetention(app.NewRetention(runner, pool, platformPool, fleetClient, retentionDay, s.indexRetention).WithDiagnosticsObjects(escrowObjects),
			app.NewLoginHistory(runner, pool, retentionDay), pool, platformPool, s.retentionEvery)
		inventory := worker.NewInventory(fleetClient, fleetClient, app.NewInventorySync(runner, pool, platformPool),
			app.NewVulnerabilitySummary(runner), pool, platformPool, s.inventoryEvery).WithSLASummary(app.NewVulnerabilitySLASummary(runner))
		osvSync := worker.NewOSV(app.NewOSV(runner, pool, platformPool), osvfeed.New(s.osvURL), pool, platformPool, s.osvEvery)
		return []func(context.Context) error{
			worker.NewOpsProbe(signer, worker.DialCertExpiry(s.tlsAddr, nil), s.tlsHosts).Run,
			worker.NewAutoUnsealObserver(platformPool, runner).Run,
			commands.Run,
			escrowStore.Run,
			diagnostics.Run,
			cacheSync.Run,
			dms.Run,
			staleness.Run,
			eventGaps.Run,
			retention.Run,
			rollouts.Run,
			configRollouts.Run,
			softwareRequests.Run,
			softwareRepositories.Run,
			identity.RunSync,
			identity.RunReconcile,
			identity.RunAdminAccounts,
			identity.RunPlatformAdmins,
			identity.RunBrandFlows,
			inventory.RunSettings,
			inventory.RunSync,
			osvSync.Run,
		}
	}
	slog.InfoContext(ctx, "worker starting", "mode", mode)
	return runAll(ctx, workerJobs(mode, consumers, rounds)...)
}
