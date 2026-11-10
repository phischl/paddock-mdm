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

// SoftwareRepositoryInterval is the period of the repository build round (plan M13c decision 13): an upload is
// published, and a failed build retried, within it.
const SoftwareRepositoryInterval = 60 * time.Second

// softwareRepositoryLockKey is the advisory lock of the round ("padd apt").
const softwareRepositoryLockKey = 0x7061646420617074

// SoftwareRepositories builds the Paddock repository of every organization whose build is due (plan M13c decision 13,
// ADR 0050 decision 3). Signing happens in this process only.
type SoftwareRepositories struct {
	builds   *app.SoftwareRepositoryBuilds
	pool     *db.OrgPool
	platform *db.PlatformPool
	interval time.Duration
}

// NewSoftwareRepositories creates the round.
func NewSoftwareRepositories(builds *app.SoftwareRepositoryBuilds, pool *db.OrgPool, platform *db.PlatformPool) *SoftwareRepositories {
	return &SoftwareRepositories{builds: builds, pool: pool, platform: platform, interval: SoftwareRepositoryInterval}
}

// Run builds at start and then every interval until ctx ends; only the replica holding the lock acts.
func (s *SoftwareRepositories) Run(ctx context.Context) error {
	tick := time.NewTicker(s.interval)
	defer tick.Stop()
	for {
		if err := s.Round(ctx); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "software repository round failed; retrying next round", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// Round builds the due repositories; a failing organization does not stop the others.
func (s *SoftwareRepositories) Round(ctx context.Context) error {
	sys := principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker"})
	_, err := s.platform.WithLeaderLock(sys, softwareRepositoryLockKey, func(ctx context.Context) error {
		orgs, err := s.pool.OrganizationIDs(ctx)
		if err != nil {
			return err
		}
		var errs []error
		for _, org := range orgs {
			if err := s.builds.Build(systemContext(ctx, org, "software-repository-round")); err != nil {
				errs = append(errs, fmt.Errorf("organization %s: %w", org, err))
			}
		}
		return errors.Join(errs...)
	})
	return err
}
