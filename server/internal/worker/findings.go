package worker

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// findingsLockKey is the advisory lock of the round ("padd fnd").
const findingsLockKey = 0x7061646420666e64

// Findings materializes the attention conditions of every organization as findings and clears those whose
// condition is gone (plan M9 decision 32). It runs right after the staleness round (Staleness.Then).
type Findings struct {
	findings *app.Findings
	pool     *db.OrgPool
	platform *db.PlatformPool
	now      func() time.Time
}

// NewFindings creates the round.
func NewFindings(findings *app.Findings, pool *db.OrgPool, platform *db.PlatformPool) *Findings {
	return &Findings{findings: findings, pool: pool, platform: platform, now: time.Now}
}

// Round materializes the findings of every organization; a failing organization does not stop the others. Only the
// replica holding the lock acts.
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
