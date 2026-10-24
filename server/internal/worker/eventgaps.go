package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// eventGapLockKey is the advisory lock of the round ("padd gap").
const eventGapLockKey = 0x7061646420676170

// EventGaps finds, reports and closes the event gaps of every organization's devices (plan M8b decision 21).
type EventGaps struct {
	gaps     *app.EventGaps
	pool     *db.OrgPool
	platform *db.PlatformPool
	interval time.Duration
	now      func() time.Time
}

// NewEventGaps creates the round; interval is the one of the staleness round.
func NewEventGaps(gaps *app.EventGaps, pool *db.OrgPool, platform *db.PlatformPool, interval time.Duration) *EventGaps {
	return &EventGaps{gaps: gaps, pool: pool, platform: platform, interval: interval, now: time.Now}
}

// Run runs the round at start and then every interval until ctx ends; only the replica holding the lock acts.
func (e *EventGaps) Run(ctx context.Context) error {
	tick := time.NewTicker(e.interval)
	defer tick.Stop()
	for {
		if err := e.Round(ctx); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "event gap round failed; retrying next round", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// Round evaluates the devices of every organization; a failing organization does not stop the others.
func (e *EventGaps) Round(ctx context.Context) error {
	sys := principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker"})
	_, err := e.platform.WithLeaderLock(sys, eventGapLockKey, func(ctx context.Context) error {
		orgs, err := e.pool.OrganizationIDs(ctx)
		if err != nil {
			return err
		}
		var errs []error
		for _, org := range orgs {
			if err := e.gaps.Evaluate(systemContext(ctx, org, "event-gap-round"), e.now()); err != nil {
				errs = append(errs, fmt.Errorf("organization %s: %w", org, err))
			}
		}
		return errors.Join(errs...)
	})
	return err
}
