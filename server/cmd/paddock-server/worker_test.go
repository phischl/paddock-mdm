package main

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/config"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
	"github.com/phischl/paddock-mdm/server/internal/worker"
)

// TestWorkerMode: PADDOCK_WORKER_MODE is full by default, accepts ingest and refuses anything else (plan M19 D1.1).
func TestWorkerMode(t *testing.T) {
	for _, tc := range []struct{ value, want string }{{"", workerModeFull}, {"full", workerModeFull}, {"ingest", workerModeIngest}} {
		env := map[string]string{}
		if tc.value != "" {
			env["PADDOCK_WORKER_MODE"] = tc.value
		}
		l := config.NewLoaderFrom(env)
		if got := loadWorkerMode(l); got != tc.want || l.Err() != nil {
			t.Errorf("PADDOCK_WORKER_MODE=%q: %q, %v; want %q", tc.value, got, l.Err(), tc.want)
		}
	}
	l := config.NewLoaderFrom(map[string]string{"PADDOCK_WORKER_MODE": "rounds"})
	loadWorkerMode(l)
	if err := l.Err(); err == nil || !strings.Contains(err.Error(), "PADDOCK_WORKER_MODE") {
		t.Fatalf("PADDOCK_WORKER_MODE=rounds: %v, want an invalid configuration", err)
	}
}

// TestWorkerSettingsOnlyInFullMode: an ingest worker neither requires nor reads the rounds' settings and credentials
// (Authentik, Fleet, the bundles bucket, the audit index retention); a full worker requires them.
func TestWorkerSettingsOnlyInFullMode(t *testing.T) {
	roundsOnly := []string{"PADDOCK_AUTHENTIK_URL", "PADDOCK_AUTHENTIK_TOKEN_FILE", "PADDOCK_FLEET_URL", "PADDOCK_FLEET_TOKEN_FILE",
		"PADDOCK_BUNDLES_PUBLIC_URL", "PADDOCK_BUNDLES_S3_ENDPOINT", "PADDOCK_AUDIT_INDEX_RETENTION_DAYS"}
	consumers := []string{"PADDOCK_DB_WORKER_URL_FILE", "PADDOCK_DB_PLATFORM_URL_FILE", "PADDOCK_ESCROW_S3_ENDPOINT"}
	for _, mode := range []string{workerModeFull, workerModeIngest} {
		err := serveWorker(context.Background(), config.NewLoaderFrom(map[string]string{"PADDOCK_WORKER_MODE": mode}), config.Common{})
		var missing *config.MissingError
		if !errors.As(err, &missing) {
			t.Fatalf("%s: err = %v, want a MissingError", mode, err)
		}
		for _, name := range consumers {
			if !slices.Contains(missing.Names, name) {
				t.Errorf("%s: missing %v does not name %s", mode, missing.Names, name)
			}
		}
		for _, name := range roundsOnly {
			if got, want := slices.Contains(missing.Names, name), mode == workerModeFull; got != want {
				t.Errorf("%s: missing names %s = %v, want %v", mode, name, got, want)
			}
		}
	}
}

// TestWorkerPoolOptions: the connection maxima of docs/operations/capacity.md, "PostgreSQL connection budget": a full
// worker 30 (organization 8, platform 8, leader locks 12, readiness 2), an ingest worker 11 (organization 8, platform 2,
// readiness 1) without a lock pool (plan M19 D1.1).
func TestWorkerPoolOptions(t *testing.T) {
	maxConns := func(o db.Options) int32 {
		n := o.MaxConns + o.LockConns
		if o.HealthConn {
			n++
		}
		return n
	}
	for _, tc := range []struct {
		mode                   string
		orgConns, platformConn int32
		lockConns, total       int32
	}{
		{mode: workerModeFull, orgConns: 8, platformConn: 8, lockConns: worker.LeaderLockConns, total: 30},
		{mode: workerModeIngest, orgConns: 8, platformConn: 2, lockConns: 0, total: 11},
	} {
		org, platform := workerPoolOptions(tc.mode)
		if org.MaxConns != tc.orgConns || platform.MaxConns != tc.platformConn || platform.LockConns != tc.lockConns {
			t.Errorf("%s: organization %d, platform %d, locks %d; want %d, %d, %d", tc.mode, org.MaxConns, platform.MaxConns,
				platform.LockConns, tc.orgConns, tc.platformConn, tc.lockConns)
		}
		if got := maxConns(org) + maxConns(platform); got != tc.total {
			t.Errorf("%s: at most %d connections, want %d", tc.mode, got, tc.total)
		}
	}
}

// TestWorkerJobs: an ingest worker runs only its consumers and never builds the rounds; a full worker runs both.
func TestWorkerJobs(t *testing.T) {
	consumer := func(context.Context) error { return nil }
	built := 0
	rounds := func() []func(context.Context) error {
		built++
		return []func(context.Context) error{consumer, consumer}
	}
	if got := workerJobs(workerModeIngest, []func(context.Context) error{consumer}, rounds); len(got) != 1 || built != 0 {
		t.Fatalf("ingest: %d jobs, rounds built %d times; want 1 job and no rounds", len(got), built)
	}
	if got := workerJobs(workerModeFull, []func(context.Context) error{consumer}, rounds); len(got) != 3 || built != 1 {
		t.Fatalf("full: %d jobs, rounds built %d times; want 3 jobs and the rounds once", len(got), built)
	}
}

// TestWorkerPoolsOnTheServer reads the pools of each mode from pg_stat_activity: a full worker takes a leader lock on a
// connection of its lock pool; an ingest worker has no lock pool and no platform readiness connection, so even a lock
// it were asked for would sit on one of its two platform query connections (plan M19 D1.1).
func TestWorkerPoolsOnTheServer(t *testing.T) {
	env := pgtest.SharedPaddock(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = super.Close(ctx) }()
	sys := principal.With(ctx, principal.Principal{Kind: principal.KindSystem})

	for i, tc := range []struct{ mode, prefix, lockHolder string }{
		{mode: workerModeFull, prefix: "paddock-worker-platform", lockHolder: "paddock-worker-platform-locks"},
		{mode: workerModeIngest, prefix: "paddock-worker-ingest", lockHolder: "paddock-worker-ingest-platform"},
	} {
		pool, platformPool, err := openWorkerPools(ctx, tc.mode, env.Worker, env.Platform)
		if err != nil {
			t.Fatalf("%s: %v", tc.mode, err)
		}
		if err := errors.Join(pool.Ping(ctx), platformPool.Ping(ctx)); err != nil {
			t.Fatalf("%s: ping: %v", tc.mode, err)
		}
		key := int64(0x696e676573) + int64(i)
		var holder string
		var names []string
		ok, err := platformPool.WithLeaderLock(sys, key, func(ctx context.Context) error {
			if err := super.QueryRow(ctx, `SELECT a.application_name FROM pg_locks l JOIN pg_stat_activity a USING (pid)
				WHERE l.locktype = 'advisory' AND l.granted AND l.objid = $1::bigint::oid`, key&0xffffffff).Scan(&holder); err != nil {
				return err
			}
			rows, err := super.Query(ctx, `SELECT application_name FROM pg_stat_activity WHERE application_name LIKE $1 || '%'`, tc.prefix)
			if err != nil {
				return err
			}
			names, err = pgx.CollectRows(rows, pgx.RowTo[string])
			return err
		})
		platformPool.Close()
		pool.Close()
		if !ok || err != nil {
			t.Fatalf("%s: leader lock %v, %v", tc.mode, ok, err)
		}
		if holder != tc.lockHolder {
			t.Errorf("%s: the lock sits on %q, want %q", tc.mode, holder, tc.lockHolder)
		}
		if tc.mode == workerModeIngest {
			for _, n := range names {
				if strings.HasSuffix(n, "-locks") || n == "paddock-worker-ingest-platform-health" {
					t.Errorf("ingest: connection %q, want neither a lock pool nor a platform readiness connection (all: %v)", n, names)
				}
			}
		}
	}
}
