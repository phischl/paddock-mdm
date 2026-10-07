package worker

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// DMSInterval is the period of the dead man's switch round (plan M4c decision 17).
const DMSInterval = 5 * time.Minute

// dmsLockKey is the advisory lock of the round ("padd dms").
const dmsLockKey = 0x7061646420646d73

// DMS marks devices silent past their organization's dead man's switch period as presumed self-locked.
type DMS struct {
	dms      *app.DMS
	pool     *db.OrgPool
	platform *db.PlatformPool
	now      func() time.Time
}

// NewDMS creates the round.
func NewDMS(dms *app.DMS, pool *db.OrgPool, platform *db.PlatformPool) *DMS {
	return &DMS{dms: dms, pool: pool, platform: platform, now: time.Now}
}

// Run runs the round at start and then every DMSInterval until ctx ends; only the replica holding the lock acts.
func (d *DMS) Run(ctx context.Context) error {
	tick := time.NewTicker(DMSInterval)
	defer tick.Stop()
	for {
		if err := d.Round(ctx); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "dead man's switch round failed; retrying next round", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// Round marks and clears presumed self-locked devices of every organization.
func (d *DMS) Round(ctx context.Context) error {
	sys := principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker"})
	_, err := d.platform.WithLeaderLock(sys, dmsLockKey, func(ctx context.Context) error {
		orgs, err := d.pool.OrganizationIDs(ctx)
		if err != nil {
			return err
		}
		for _, org := range orgs {
			if err := d.dms.MarkSilent(systemContext(ctx, org, "dms-round"), d.now()); err != nil {
				return fmt.Errorf("organization %s: %w", org, err)
			}
		}
		return nil
	})
	return err
}
