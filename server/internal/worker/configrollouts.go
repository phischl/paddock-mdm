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
	"github.com/phischl/paddock-mdm/server/internal/domain/configrollout"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// ConfigRolloutInterval is the period of the configuration rollout round (plan M11 decision 33).
const ConfigRolloutInterval = 60 * time.Second

// configRolloutLockKey is the advisory lock of the round ("padd cfr").
const configRolloutLockKey = 0x7061646420636672

// metricConfigRollouts counts the configuration rollouts by status across organizations; no organization label
// (plan M11 decision 33, amendment R2.15).
var metricConfigRollouts = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "paddock_config_rollouts",
	Help: "Staged configuration rollouts by status across all organizations, as of the last rollout round.",
}, []string{"status"})

// configRolloutStatuses are the label values of metricConfigRollouts, exported also when no rollout has them.
var configRolloutStatuses = []string{
	configrollout.StatusRunning, configrollout.StatusHalted, configrollout.StatusCompleted, configrollout.StatusReverted,
}

// ConfigRollouts evaluates the staged configuration rollouts of every organization.
type ConfigRollouts struct {
	rollouts *app.ConfigRollouts
	pool     *db.OrgPool
	platform *db.PlatformPool
	interval time.Duration
	now      func() time.Time
}

// NewConfigRollouts creates the round.
func NewConfigRollouts(rollouts *app.ConfigRollouts, pool *db.OrgPool, platform *db.PlatformPool) *ConfigRollouts {
	return &ConfigRollouts{rollouts: rollouts, pool: pool, platform: platform, interval: ConfigRolloutInterval, now: time.Now}
}

// Run evaluates at start and then every interval until ctx ends; only the replica holding the lock acts.
func (c *ConfigRollouts) Run(ctx context.Context) error {
	tick := time.NewTicker(c.interval)
	defer tick.Stop()
	for {
		if err := c.Round(ctx); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "config rollout round failed; retrying next round", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// Round evaluates the rollouts of every organization, then exports the gauge; a failing organization does not stop
// the others.
func (c *ConfigRollouts) Round(ctx context.Context) error {
	sys := principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker"})
	_, err := c.platform.WithLeaderLock(sys, configRolloutLockKey, func(ctx context.Context) error {
		orgs, err := c.pool.OrganizationIDs(ctx)
		if err != nil {
			return err
		}
		totals := map[string]int64{}
		var errs []error
		for _, org := range orgs {
			octx := systemContext(ctx, org, "config-rollout-round")
			if err := c.rollouts.Evaluate(octx, c.now()); err != nil {
				errs = append(errs, fmt.Errorf("organization %s: %w", org, err))
			}
			counts, err := c.rollouts.StatusCounts(octx)
			if err != nil {
				errs = append(errs, fmt.Errorf("organization %s: %w", org, err))
				continue
			}
			for status, n := range counts {
				totals[status] += n
			}
		}
		for _, s := range configRolloutStatuses {
			metricConfigRollouts.WithLabelValues(s).Set(float64(totals[s]))
		}
		return errors.Join(errs...)
	})
	return err
}
