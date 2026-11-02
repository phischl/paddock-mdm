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

// StalenessInterval is the period of the staleness round (plan M5b decision 10).
const StalenessInterval = 5 * time.Minute

// stalenessLockKey is the advisory lock of the round ("padd sta").
const stalenessLockKey = 0x7061646420737461

// Staleness raises and clears the staleness alerts of every organization's devices.
type Staleness struct {
	staleness *app.Staleness
	pool      *db.OrgPool
	platform  *db.PlatformPool
	interval  time.Duration
	now       func() time.Time
	// next runs after every round, whether or not it acted (Then).
	next func(ctx context.Context) error
}

// NewStaleness creates the round; interval is StalenessInterval, shorter in development installations that count
// the thresholds in minutes (gate U4).
func NewStaleness(staleness *app.Staleness, pool *db.OrgPool, platform *db.PlatformPool, interval time.Duration) *Staleness {
	return &Staleness{staleness: staleness, pool: pool, platform: platform, interval: interval, now: time.Now}
}

// Then makes next run right after every round, e.g. the findings round, which materializes the conditions the
// staleness round has just raised or cleared (plan M9 decision 32). It returns s.
func (s *Staleness) Then(next func(ctx context.Context) error) *Staleness {
	s.next = next
	return s
}

// Run runs the round at start and then every interval until ctx ends; only the replica holding the lock acts.
func (s *Staleness) Run(ctx context.Context) error {
	tick := time.NewTicker(s.interval)
	defer tick.Stop()
	for {
		if err := s.Round(ctx); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "staleness round failed; retrying next round", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// Round evaluates the devices of every organization; a failing organization does not stop the others. The round of
// Then follows, also when this one failed.
func (s *Staleness) Round(ctx context.Context) error {
	sys := principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker"})
	_, err := s.platform.WithLeaderLock(sys, stalenessLockKey, func(ctx context.Context) error {
		orgs, err := s.pool.OrganizationIDs(ctx)
		if err != nil {
			return err
		}
		var errs []error
		for _, org := range orgs {
			if err := s.staleness.Evaluate(systemContext(ctx, org, "staleness-round"), s.now()); err != nil {
				errs = append(errs, fmt.Errorf("organization %s: %w", org, err))
			}
		}
		return errors.Join(errs...)
	})
	if s.next != nil {
		err = errors.Join(err, s.next(ctx))
	}
	return err
}
