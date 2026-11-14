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

// SoftwareRequestInterval is the period of the software request round: an entry switched to approval none frees its
// users within it (plan M13c §3.8 L4).
const SoftwareRequestInterval = 10 * time.Minute

// softwareRequestLockKey is the advisory lock of the round ("padd swr").
const softwareRequestLockKey = 0x7061646420737772

// SoftwareRequests expires the software requests of every organization that stayed open past their validity or whose
// entry no longer requires approval (plan M13c §3.7 and §3.8 L4). The plan names the retention round for it; the
// retention round only purges stores with retention.purged evidence (ADR 0032), and an expiry is a state transition
// with an event of its own, so it is a round of its own.
type SoftwareRequests struct {
	requests *app.SoftwareRequests
	pool     *db.OrgPool
	platform *db.PlatformPool
	interval time.Duration
	now      func() time.Time
}

// NewSoftwareRequests creates the round.
func NewSoftwareRequests(requests *app.SoftwareRequests, pool *db.OrgPool, platform *db.PlatformPool, interval time.Duration) *SoftwareRequests {
	return &SoftwareRequests{requests: requests, pool: pool, platform: platform, interval: interval, now: time.Now}
}

// Run runs the round at start and then every interval until ctx ends; only the replica holding the lock acts.
func (s *SoftwareRequests) Run(ctx context.Context) error {
	tick := time.NewTicker(s.interval)
	defer tick.Stop()
	for {
		if err := s.Round(ctx); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "software request round failed; retrying next round", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// Round expires the due requests of every organization; a failing organization does not stop the others.
func (s *SoftwareRequests) Round(ctx context.Context) error {
	sys := principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker"})
	_, err := s.platform.WithLeaderLock(sys, softwareRequestLockKey, func(ctx context.Context) error {
		orgs, err := s.pool.OrganizationIDs(ctx)
		if err != nil {
			return err
		}
		var errs []error
		for _, org := range orgs {
			if _, err := s.requests.Expire(systemContext(ctx, org, "software-request-round"), s.now()); err != nil {
				errs = append(errs, fmt.Errorf("organization %s: %w", org, err))
			}
		}
		return errors.Join(errs...)
	})
	return err
}
