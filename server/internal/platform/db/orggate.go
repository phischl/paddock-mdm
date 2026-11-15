package db

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	// gateRefreshInterval is how often a process re-reads its set of inactive organizations (plan M17 amendment
	// 2026-11-15 j point 1).
	gateRefreshInterval = time.Second
	// gateMaxAge is the age of the set after which the gate reads the status in the transaction instead (amendment j
	// point 2). paddock_offboard_finalize's quiescence cutoff of 6 s depends on it: changing it changes that cutoff.
	gateMaxAge = 5 * time.Second
	// gateRefreshTimeout bounds one refresh, so a hung read ages the set into the fallback instead of blocking the
	// poller.
	gateRefreshTimeout = 2 * time.Second
)

// metricGateRefreshFailures counts failed refreshes of the status cache. A refresh that keeps failing is safe (the gate
// falls back to a status read per transaction) but costs that read in every transaction, so it must be visible.
var metricGateRefreshFailures = promauto.NewCounter(prometheus.CounterOpts{
	Name: "paddock_org_gate_refresh_failures_total",
	Help: "Failed refreshes of the organization gate's status cache; while they fail, every organization transaction reads the status itself.",
})

// orgGate is the offboarding gate's per-process status cache: the organizations that are deleting or deleted, polled
// on the pool it belongs to. No LISTEN/NOTIFY: that would hold a connection per process (amendment j point 1).
type orgGate struct {
	p *pgxpool.Pool
	// since is process-local monotonic time; the set's age is never measured on the database's or the wall clock,
	// which can jump.
	since func() time.Duration
	snap  atomic.Pointer[gateSnapshot]
	stop  context.CancelFunc
	done  chan struct{}
	log   *slog.Logger
	// failing is true from the first failed refresh to the next successful one: one warning per failure streak.
	failing atomic.Bool
}

// gateSnapshot is one successful read of the inactive organizations, taken at monotonic time at (before the read
// was sent, so its age is never underestimated).
type gateSnapshot struct {
	inactive map[uuid.UUID]string
	at       time.Duration
}

// monotonicSince returns process-local monotonic time elapsed since the call.
func monotonicSince() func() time.Duration {
	start := time.Now()
	return func() time.Duration { return time.Since(start) }
}

// newOrgGate reads the set once and starts the poller, which runs until close. A failed first read leaves the set
// empty and stale, so every transaction reads the status itself until a refresh succeeds.
func newOrgGate(ctx context.Context, p *pgxpool.Pool, since func() time.Duration, log *slog.Logger) *orgGate {
	g := &orgGate{p: p, since: since, done: make(chan struct{}), log: log}
	_ = g.refresh(ctx)
	pctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	g.stop = cancel
	go g.poll(pctx)
	return g
}

func (g *orgGate) poll(ctx context.Context) {
	defer close(g.done)
	t := time.NewTicker(gateRefreshInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = g.refresh(ctx)
		}
	}
}

// refresh re-reads the set; on an error the previous set stays and keeps ageing. Failures are counted and logged once
// per streak; one caused by the caller's own context ending (shutdown) is neither.
func (g *orgGate) refresh(ctx context.Context) error {
	err := g.read(ctx)
	switch {
	case err != nil && ctx.Err() == nil:
		metricGateRefreshFailures.Inc()
		if !g.failing.Swap(true) {
			g.log.Warn("organization gate: status cache refresh failed; organization transactions read the status "+
				"themselves until it succeeds", "error", err)
		}
	case err == nil && g.failing.Swap(false):
		g.log.Info("organization gate: status cache refresh recovered")
	}
	return err
}

func (g *orgGate) read(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, gateRefreshTimeout)
	defer cancel()
	at := g.since()
	rows, err := g.p.Query(ctx, "SELECT id, status FROM paddock_inactive_organizations()")
	if err != nil {
		return err
	}
	inactive := map[uuid.UUID]string{}
	var id uuid.UUID
	var status string
	if _, err := pgx.ForEachRow(rows, []any{&id, &status}, func() error {
		inactive[id] = status
		return nil
	}); err != nil {
		return err
	}
	g.snap.Store(&gateSnapshot{inactive: inactive, at: at})
	return nil
}

// lookup returns org's status from the set ("" when it is not inactive) and whether the set is fresh enough to
// decide. A nil gate is never fresh.
func (g *orgGate) lookup(org uuid.UUID) (status string, fresh bool) {
	if g == nil {
		return "", false
	}
	s := g.snap.Load()
	if s == nil || g.since()-s.at > gateMaxAge {
		return "", false
	}
	return s.inactive[org], true
}

// close stops the poller and waits for it.
func (g *orgGate) close() {
	if g == nil {
		return
	}
	g.stop()
	<-g.done
}
