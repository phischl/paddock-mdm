package worker

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// Default periods of the identity rounds (plan M3a decisions 2, 3 and 5).
const (
	DefaultIdentitySyncInterval = 5 * time.Minute
	DefaultReconcileInterval    = 10 * time.Minute
	// conflictPause is how long a synced user whose username belongs to another organization is skipped, so its
	// audited failure is not repeated every round.
	conflictPause = 24 * time.Hour
	// brandRetryInterval is how soon a failed brand round is repeated: at the first start Authentik may not have applied
	// the blueprints with the flows yet, and local users cannot be created until the brand has its recovery flow.
	brandRetryInterval = 15 * time.Second
)

// ReconcileAuthentikConcurrency bounds the Authentik requests of the reconcile round's EnsureOrganization, which fans
// out about a dozen requests per organization. A loaded Authentik serves only one or two at a time, so an organization
// create in the portal waited 2–6 s per request behind the round (PDK-392). No one waits for the round, so it sends
// one request at a time and leaves Authentik's capacity to the interactive calls of the API.
const ReconcileAuthentikConcurrency = 1

// refusedRepeatedly is the number of consecutive refused admin-accounts rounds of an organization from which each
// further refusal is logged as a repeated one (PDK-424).
const refusedRepeatedly = 3

var metricDirectoryRefusals = promauto.NewCounter(prometheus.CounterOpts{
	Name: "paddock_identity_directory_refusals_total",
	Help: "Organization rounds of admin-accounts refused because every role group listing was empty and the directory " +
		"probe did not show that the service token sees the directory (app.ErrDirectoryEmpty, PDK-424).",
})

// BrandFlows keeps the platform-wide flows of the identity provider's default brand (authentik.Client).
type BrandFlows interface {
	EnsureBrandFlows(ctx context.Context) error
}

// Advisory locks of the identity rounds ("paddock idsync", "paddock idrecn", "paddock idacct").
const (
	identitySyncLockKey           = 0x7061646420696473
	identityReconcileLockKey      = 0x706164642069647e
	identityAdminAccountsLockKey  = 0x7061646420696461
	identityPlatformAdminsLockKey = 0x7061646420696470
)

// Identity runs the identity rounds: synced users and group mirrors every sync interval, the organizations'
// Authentik objects and per-device login groups every reconcile interval. Only the replica holding a round's lock
// acts. The default brand's flows are ensured by every replica (idempotent) at start and every reconcile interval.
type Identity struct {
	sync       *app.IdentitySync
	accounts   *app.AdminAccounts
	roles      *app.RoleMembership
	brand      BrandFlows
	brandRetry time.Duration
	org        *db.OrgPool
	platform   *db.PlatformPool
	syncEvery  time.Duration
	reconcile  time.Duration
	now        func() time.Time

	mu        sync.Mutex
	conflicts map[string]time.Time // username → skipped until
	// refused counts the consecutive refused admin-accounts rounds per organization. It lives in this process only; the
	// metric, not this count, is what survives a change of the replica holding the round's lock.
	refused map[uuid.UUID]int
}

// NewIdentity creates the identity rounds.
func NewIdentity(s *app.IdentitySync, accounts *app.AdminAccounts, roles *app.RoleMembership, brand BrandFlows, org *db.OrgPool,
	platform *db.PlatformPool, syncEvery, reconcile time.Duration) *Identity {
	return &Identity{sync: s, accounts: accounts, roles: roles, brand: brand, brandRetry: brandRetryInterval, org: org, platform: platform,
		syncEvery: syncEvery, reconcile: reconcile, now: time.Now, conflicts: map[string]time.Time{}, refused: map[uuid.UUID]int{}}
}

// RunBrandFlows ensures the default brand's recovery and device-code flows at start and then every reconcile interval
// until ctx ends (plan M3.1 decision 5); a failure is retried after brandRetryInterval.
func (i *Identity) RunBrandFlows(ctx context.Context) error {
	for {
		wait := i.reconcile
		if err := i.brand.EnsureBrandFlows(ctx); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "ensuring the default brand's flows failed", "retry_in", i.brandRetry, "error", err)
			wait = i.brandRetry
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

// RunSync runs the sync round at start and then every sync interval until ctx ends.
func (i *Identity) RunSync(ctx context.Context) error {
	return i.every(ctx, i.syncEvery, identitySyncLockKey, "identity-sync", i.syncOrg)
}

// RunAdminAccounts runs the round admin-accounts (plan M8s decision 22) at start and then every sync interval until
// ctx ends: administrator accounts follow their role groups in the identity provider, and every change of a role
// group's members is recorded (plan M8b decision 36, PDK-111).
func (i *Identity) RunAdminAccounts(ctx context.Context) error {
	return i.every(ctx, i.syncEvery, identityAdminAccountsLockKey, "admin-accounts", i.adminAccounts)
}

// adminAccounts lists an organization's role groups once for both consumers of the round. A round refused because the
// directory looks empty to the service token (app.ErrDirectoryEmpty) is counted once, whichever consumer refused it.
func (i *Identity) adminAccounts(ctx context.Context) error {
	groups, err := i.roles.OrganizationRoleGroups(ctx)
	if err != nil || groups == nil {
		return err
	}
	err = errors.Join(i.accounts.Reconcile(ctx, groups), i.roles.SyncOrganization(ctx, groups))
	i.noteRefusal(ctx, err)
	return err
}

// noteRefusal counts a refused round of the caller's organization and warns from refusedRepeatedly consecutive
// refusals on: role changes of the organization are not recorded and its administrator accounts are not followed
// until an operator restores the service token's view (docs/operations/monitoring.md). A successful round ends the
// streak; a round failing otherwise (Authentik unreachable) neither counts nor ends it.
func (i *Identity) noteRefusal(ctx context.Context, err error) {
	p, _ := principal.From(ctx)
	i.mu.Lock()
	defer i.mu.Unlock()
	switch {
	case err == nil:
		delete(i.refused, p.OrganizationID)
		return
	case !errors.Is(err, app.ErrDirectoryEmpty):
		return
	}
	metricDirectoryRefusals.Inc()
	i.refused[p.OrganizationID]++
	if n := i.refused[p.OrganizationID]; n >= refusedRepeatedly {
		slog.WarnContext(ctx, "the identity provider's directory looked empty to the service token in consecutive rounds; "+
			"the organization's role changes are not recorded and its administrator accounts are not followed",
			"organization_id", p.OrganizationID, "rounds", n)
	}
}

// RunPlatformAdmins ends the sessions of platform administrators the directory no longer lists (PDK-185) and records
// the changes of the platform administrators and the identity provider's superusers (PDK-111), at start and then every
// sync interval until ctx ends, under its own lock.
func (i *Identity) RunPlatformAdmins(ctx context.Context) error {
	return i.loop(ctx, i.syncEvery, "platform-admins", func(ctx context.Context) error {
		sys := principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker"})
		_, err := i.platform.WithLeaderLock(sys, identityPlatformAdminsLockKey, func(ctx context.Context) error {
			ctx = httpx.WithRequestID(ctx, "platform-admins-"+i.now().UTC().Format(time.RFC3339))
			groups := i.roles.PlatformRoleGroups(ctx)
			return errors.Join(i.accounts.ReconcilePlatform(ctx, groups), i.roles.SyncPlatform(ctx, groups))
		})
		return err
	})
}

// RunReconcile runs the reconcile round at start and then every reconcile interval until ctx ends.
func (i *Identity) RunReconcile(ctx context.Context) error {
	return i.every(ctx, i.reconcile, identityReconcileLockKey, "identity-reconcile", i.sync.Reconcile)
}

func (i *Identity) every(ctx context.Context, interval time.Duration, lock int64, name string, fn func(ctx context.Context) error) error {
	return i.loop(ctx, interval, name, func(ctx context.Context) error { return i.Round(ctx, lock, name, fn) })
}

// loop runs round at start and then every interval until ctx ends; a failed round is logged and retried next time.
func (i *Identity) loop(ctx context.Context, interval time.Duration, name string, round func(ctx context.Context) error) error {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		if err := round(ctx); err != nil && ctx.Err() == nil {
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
