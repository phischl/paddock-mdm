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

// findingsLockKey is the advisory lock of the round ("padd fnd").
const findingsLockKey = 0x7061646420666e64

// Findings materializes the attention conditions of every organization as findings and clears those whose
// condition is gone (plan M9 decision 32).
type Findings struct {
	findings *app.Findings
	pool     *db.OrgPool
	platform *db.PlatformPool
	interval time.Duration
	now      func() time.Time
}

// NewFindings creates the round; interval is the one of the staleness round.
func NewFindings(findings *app.Findings, pool *db.OrgPool, platform *db.PlatformPool, interval time.Duration) *Findings {
	return &Findings{findings: findings, pool: pool, platform: platform, interval: interval, now: time.Now}
}

// Run runs the round at start and then every interval until ctx ends; only the replica holding the lock acts.
func (f *Findings) Run(ctx context.Context) error {
	tick := time.NewTicker(f.interval)
	defer tick.Stop()
	for {
		if err := f.Round(ctx); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "findings round failed; retrying next round", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// Round materializes the findings of every organization; a failing organization does not stop the others.
func (f *Findings) Round(ctx context.Context) error {
	sys := principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker"})
	_, err := f.platform.WithLeaderLock(sys, findingsLockKey, func(ctx context.Context) error {
		orgs, err := f.pool.OrganizationIDs(ctx)
		if err != nil {
			return err
		}
		var errs []error
		for _, org := range orgs {
			if err := f.findings.Materialize(systemContext(ctx, org, "findings-round"), f.now()); err != nil {
				errs = append(errs, fmt.Errorf("organization %s: %w", org, err))
			}
		}
		return errors.Join(errs...)
	})
	return err
}
