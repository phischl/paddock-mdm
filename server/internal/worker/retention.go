package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// RetentionInterval is the period of the retention round (plan M10 decision 12).
const RetentionInterval = 6 * time.Hour

// retentionLockKey is the advisory lock of the round ("padd ret").
const retentionLockKey = 0x7061646420726574

// legacyLoginHistoryLockKey is the lock of the login history round the retention round replaced ("padd log"). The
// round holds it too, so that during a rolling upgrade a worker of an earlier version never purges the login history
// at the same time (plan M10 amendment 2026-10-30).
const legacyLoginHistoryLockKey = 0x70616464206c6f67

var (
	metricRetentionLastSuccess = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "paddock_retention_last_success_timestamp_seconds",
		Help: "When the retention round last purged a store in every organization without an error.",
	}, []string{"store"})
	metricRetentionDeleted = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "paddock_retention_deleted_total",
		Help: "Rows the retention round deleted, per store; devices whose inventory it purged for store retired_inventory.",
	}, []string{"store"})
	// metricRetentionStores lets an alert notice stores whose last success is never exported, e.g. because a pass
	// fails from the start (PaddockRetentionPurgeMissing).
	metricRetentionStores = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "paddock_retention_stores",
		Help: "Number of stores the retention round purges.",
	})
)

// retentionPass purges one store of the context's organization and returns what it deleted: rows, or devices for
// app.StoreRetiredInventory (plan M10 §6.6).
type retentionPass struct {
	store string
	purge func(ctx context.Context, now time.Time) (int64, error)
}

// Retention is the one retention round (plan M10 amendment A3): per organization it runs every store's pass in a
// fixed order, each with its own evidence: a retention.purged event per store, a device.inventory_purged event per
// retired device whose inventory it deleted.
type Retention struct {
	passes   []retentionPass
	pool     *db.OrgPool
	platform *db.PlatformPool
	interval time.Duration
	now      func() time.Time
}

// NewRetention creates the round; interval is RetentionInterval, shorter in development installations that count the
// retention days in seconds.
func NewRetention(a *app.Retention, history *app.LoginHistory, pool *db.OrgPool, platform *db.PlatformPool, interval time.Duration) *Retention {
	return &Retention{
		passes: []retentionPass{
			{store: app.StoreDeviceLoginEvent, purge: history.Purge},
			{store: app.StoreDeviceUserSeen, purge: a.PurgeUserSeen},
			{store: app.StoreRetiredInventory, purge: func(ctx context.Context, now time.Time) (int64, error) {
				n, err := a.PurgeRetiredInventory(ctx, now)
				return int64(n), err
			}},
		},
		pool: pool, platform: platform, interval: interval, now: time.Now,
	}
}

// Run runs the round at start and then every interval until ctx ends; only the replica holding the lock acts.
func (r *Retention) Run(ctx context.Context) error {
	metricRetentionStores.Set(float64(len(r.passes)))
	tick := time.NewTicker(r.interval)
	defer tick.Stop()
	for {
		if err := r.Round(ctx); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "retention round failed; retrying next round", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// Round runs every pass for every organization; a failing pass or organization does not stop the others. A store's
// last success is set only when its pass succeeded in every organization.
func (r *Retention) Round(ctx context.Context) error {
	sys := principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker"})
	_, err := r.platform.WithLeaderLocks(sys, []int64{retentionLockKey, legacyLoginHistoryLockKey}, r.purge)
	return err
}

// purge runs every pass for every organization while the round holds its locks.
func (r *Retention) purge(ctx context.Context) error {
	orgs, err := r.pool.OrganizationIDs(ctx)
	if err != nil {
		return err
	}
	now := r.now()
	failed := make([]bool, len(r.passes))
	var errs []error
	for _, org := range orgs {
		for i, pass := range r.passes {
			n, err := pass.purge(systemContext(ctx, org, "retention-round"), now)
			// A failed pass still reports the rows of the batches, or the devices, it committed before the failure.
			metricRetentionDeleted.WithLabelValues(pass.store).Add(float64(n))
			if err != nil {
				failed[i] = true
				errs = append(errs, fmt.Errorf("organization %s, store %s: %w", org, pass.store, err))
			}
		}
	}
	done := float64(r.now().Unix())
	for i, pass := range r.passes {
		if !failed[i] {
			metricRetentionLastSuccess.WithLabelValues(pass.store).Set(done)
		}
	}
	return errors.Join(errs...)
}
