package worker

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/paddock-mdm/paddock/server/internal/app"
	"github.com/paddock-mdm/paddock/server/internal/platform/db"
	"github.com/paddock-mdm/paddock/server/internal/principal"
)

// Default periods of the identity rounds (plan M3a decisions 2, 3 and 5).
const (
	DefaultIdentitySyncInterval = 5 * time.Minute
	DefaultReconcileInterval    = 10 * time.Minute
	// conflictPause is how long a synced user whose username belongs to another organization is skipped, so its
	// audited failure is not repeated every round.
	conflictPause = 24 * time.Hour
)

// Advisory locks of the identity rounds ("paddock idsync", "paddock idrecn").
const (
	identitySyncLockKey      = 0x7061646420696473
	identityReconcileLockKey = 0x706164642069647e
)

// Identity runs the identity rounds: synced users and group mirrors every sync interval, the organizations'
// Authentik objects and per-device login groups every reconcile interval. Only the replica holding a round's lock
// acts.
type Identity struct {
	sync      *app.IdentitySync
	org       *db.OrgPool
	platform  *db.PlatformPool
	syncEvery time.Duration
	reconcile time.Duration
	now       func() time.Time

	mu        sync.Mutex
	conflicts map[string]time.Time // username → skipped until
}

// NewIdentity creates the identity rounds.
func NewIdentity(s *app.IdentitySync, org *db.OrgPool, platform *db.PlatformPool, syncEvery, reconcile time.Duration) *Identity {
	return &Identity{sync: s, org: org, platform: platform, syncEvery: syncEvery, reconcile: reconcile, now: time.Now,
		conflicts: map[string]time.Time{}}
}

// RunSync runs the sync round at start and then every sync interval until ctx ends.
func (i *Identity) RunSync(ctx context.Context) error {
	return i.every(ctx, i.syncEvery, identitySyncLockKey, "identity-sync", i.syncOrg)
}

// RunReconcile runs the reconcile round at start and then every reconcile interval until ctx ends.
func (i *Identity) RunReconcile(ctx context.Context) error {
	return i.every(ctx, i.reconcile, identityReconcileLockKey, "identity-reconcile", i.sync.Reconcile)
}

func (i *Identity) every(ctx context.Context, interval time.Duration, lock int64, name string, fn func(ctx context.Context) error) error {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		if err := i.Round(ctx, lock, name, fn); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "identity round failed; retrying next round", "round", name, "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// Round runs fn for every organization under the advisory lock; a failing organization does not stop the others.
func (i *Identity) Round(ctx context.Context, lock int64, name string, fn func(ctx context.Context) error) error {
	sys := principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker"})
	_, err := i.platform.WithLeaderLock(sys, lock, func(ctx context.Context) error {
		orgs, err := i.org.OrganizationIDs(ctx)
		if err != nil {
			return err
		}
		round := name + "-" + i.now().UTC().Format(time.RFC3339)
		for _, org := range orgs {
			if err := fn(systemContext(ctx, org, round)); err != nil && ctx.Err() == nil {
				slog.WarnContext(ctx, "identity round of an organization failed", "round", name, "organization_id", org, "error", err)
			}
		}
		return nil
	})
	return err
}

func (i *Identity) syncOrg(ctx context.Context) error {
	conflicts, err := i.sync.SyncUsers(ctx, i.skipped)
	i.mu.Lock()
	for _, u := range conflicts {
		i.conflicts[u] = i.now().Add(conflictPause)
	}
	i.mu.Unlock()
	if err != nil {
		return err
	}
	return i.sync.SyncGroupMirrors(ctx)
}

func (i *Identity) skipped(username string) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	until, ok := i.conflicts[username]
	return ok && i.now().Before(until)
}
