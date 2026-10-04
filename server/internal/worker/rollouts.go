package worker

import (
	"context"
	"log/slog"
	"time"

	"github.com/paddock-mdm/paddock/server/internal/app"
	"github.com/paddock-mdm/paddock/server/internal/devicecache"
	"github.com/paddock-mdm/paddock/server/internal/platform/db"
	"github.com/paddock-mdm/paddock/server/internal/platform/httpx"
	"github.com/paddock-mdm/paddock/server/internal/principal"
)

// RolloutInterval is the period of the rollout round (plan M2b decision 22).
const RolloutInterval = 60 * time.Second

// rolloutLockKey is the advisory lock of the rollout round ("paddock rollouts").
const rolloutLockKey = 0x7061646420726f6c

// Rollouts evaluates agent rollouts and publishes the current offer to Valkey (ar:current).
type Rollouts struct {
	releases *app.AgentReleases
	platform *db.PlatformPool
	cache    *devicecache.Cache
	interval time.Duration
	now      func() time.Time
}

// NewRollouts creates the rollout loop.
func NewRollouts(releases *app.AgentReleases, platform *db.PlatformPool, cache *devicecache.Cache) *Rollouts {
	return &Rollouts{releases: releases, platform: platform, cache: cache, interval: RolloutInterval, now: time.Now}
}

// Run evaluates at start and then every interval until ctx ends; only the replica holding the lock acts.
func (r *Rollouts) Run(ctx context.Context) error {
	tick := time.NewTicker(r.interval)
	defer tick.Stop()
	for {
		if err := r.Round(ctx); err != nil {
			slog.WarnContext(ctx, "rollout round failed; retrying next round", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// Round is one rollout round.
func (r *Rollouts) Round(ctx context.Context) error {
	ctx = principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker"})
	ctx = httpx.WithRequestID(ctx, "rollout-"+r.now().UTC().Format(time.RFC3339))
	_, err := r.platform.WithLeaderLock(ctx, rolloutLockKey, func(ctx context.Context) error {
		offer, err := r.releases.EvaluateRollouts(ctx, r.now())
		if err != nil {
			return err
		}
		return r.cache.PutOffer(ctx, offer)
	})
	return err
}
