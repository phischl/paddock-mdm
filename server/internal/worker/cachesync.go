package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// ReconcileInterval is how often the cache sync rewrites every entry from PostgreSQL (plan M2a risk R2).
const ReconcileInterval = 60 * time.Second

// OffboardedRestoreInterval is how often the reconcile restores the devices of deleted organizations, besides the
// first reconcile after start (plan M17 amendment s point 4.2): such a device only fetches its uninstall, valid for 365
// days, so after a Valkey data loss it waits at most this much longer.
const OffboardedRestoreInterval = 15 * time.Minute

var metricReconcileWrites = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "paddock_device_cache_reconcile_writes_total",
	Help: "Valkey keys the periodic device cache reconcile wrote because they differed from PostgreSQL, by kind; flat in the steady state.",
}, []string{"kind"})

// Kinds of paddock_device_cache_reconcile_writes_total.
const (
	reconcileWritesDeviceKey  = "device_key"
	reconcileWritesOffboarded = "offboarded_device"
)

// notifyChannel is the PostgreSQL channel of the device_cache_notify trigger (migration 00003).
const notifyChannel = "device_cache"

// CacheSync keeps et: and dk: in Valkey equal to PostgreSQL: immediately on change notifications and completely
// every ReconcileInterval, which also repairs lost notifications and an emptied Valkey (and then restores seq:
// from device_status.last_seq).
type CacheSync struct {
	pool       *db.OrgPool
	cache      *devicecache.Cache
	syncer     *devicecache.Syncer
	offboarded offboardedRestorer
	interval   time.Duration
	now        func() time.Time
	// restoredAt is when Restore last succeeded; zero until then, so the first reconcile restores.
	restoredAt time.Time
	// skippedMu guards skipped, the organizations whose refused change notifications were already logged.
	skippedMu sync.Mutex
	skipped   map[uuid.UUID]bool
	// pageSize overrides ReconcilePageSize in tests; zero keeps it.
	pageSize int
	// beforeListen, if set, runs before each LISTEN attempt; tests use it to hold the listener back.
	beforeListen func(ctx context.Context)
}

// offboardedRestorer rewrites the cached keys and uninstalls of the devices of deleted organizations
// (app.OffboardedDevices).
type offboardedRestorer interface {
	Restore(ctx context.Context) (app.OffboardedRestore, error)
}

// WithOffboardedDevices makes the reconcile also restore the devices of deleted organizations (plan M17 decision
// 15): their rows left with the organization, so only their platform records can rebuild them.
func (s *CacheSync) WithOffboardedDevices(o offboardedRestorer) *CacheSync {
	s.offboarded = o
	return s
}

// NewCacheSync creates the sync.
func NewCacheSync(pool *db.OrgPool, cache *devicecache.Cache) *CacheSync {
	return &CacheSync{pool: pool, cache: cache, syncer: devicecache.NewSyncer(cache), interval: ReconcileInterval, now: time.Now,
		skipped: map[uuid.UUID]bool{}}
}

// Run listens for changes and reconciles periodically until ctx ends. It also reconciles whenever LISTEN is
// (re-)established (PDK-1060): a change committed before that raised a notification nobody received, and a revocation
// must not wait for the next interval.
func (s *CacheSync) Run(ctx context.Context) error {
	listening := make(chan struct{}, 1)
	go s.listen(ctx, listening)
	for {
		if err := s.ReconcileAll(ctx); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "device cache reconcile failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-listening:
		case <-time.After(s.interval):
		}
	}
}

func (s *CacheSync) listen(ctx context.Context, listening chan<- struct{}) {
	for ctx.Err() == nil {
		if s.beforeListen != nil {
			s.beforeListen(ctx)
		}
		err := s.pool.Listen(ctx, notifyChannel, func() {
			// A pending signal already guarantees a reconcile that starts after this LISTEN.
			select {
			case listening <- struct{}{}:
			default:
			}
		}, func(payload string) { s.applyChange(ctx, payload) })
		if ctx.Err() == nil {
			slog.WarnContext(ctx, "device cache LISTEN failed; reconciling continues", "error", err)
			select {
			case <-ctx.Done():
			case <-time.After(5 * time.Second):
			}
		}
	}
}

// applyChange applies one change notification and logs a failure. A refusal because the organization is deleting is
// logged once per organization at Info, not per notification (plan M17 amendment s point 6.2): a deletion refuses
// every change of its devices, and its valkey step removes their keys.
func (s *CacheSync) applyChange(ctx context.Context, payload string) {
	err := s.Changed(ctx, payload)
	if err == nil {
		return
	}
	var u *db.OrganizationUnavailableError
	if !errors.As(err, &u) {
		slog.WarnContext(ctx, "device cache update failed; the reconcile loop repairs it", "change", payload, "error", err)
		return
	}
	s.skippedMu.Lock()
	logged := s.skipped[u.Organization]
	s.skipped[u.Organization] = true
	s.skippedMu.Unlock()
	if !logged {
		slog.InfoContext(ctx, "device cache changes of a deleting organization are skipped; the deletion removes its keys",
			"organization", u.Organization, "status", u.Status)
	}
}

// Changed applies one change notification "<table>:<organization_id>:<id>". The rows are read in one short
// transaction and written to Valkey after it committed (plan M17 amendment r point 6).
func (s *CacheSync) Changed(ctx context.Context, payload string) error {
	parts := strings.Split(payload, ":")
	if len(parts) != 3 {
		return fmt.Errorf("malformed notification %q", payload)
	}
	org, err1 := uuid.Parse(parts[1])
	id, err2 := uuid.Parse(parts[2])
	if err1 != nil || err2 != nil {
		return fmt.Errorf("malformed notification %q", payload)
	}
	ctx = systemContext(ctx, org, "cache-sync")
	switch parts[0] {
	case "enrollment_token":
		var tok pgstore.EnrollmentToken
		if err := s.pool.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
			var err error
			tok, err = q.GetEnrollmentToken(ctx, id)
			return err
		}); err != nil {
			return err
		}
		return s.putToken(ctx, tok)
	case "device", "device_identity_key":
		var keys []cachedKey
		var dev pgstore.Device
		if err := s.pool.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
			rows, err := q.ListCachedDeviceKeysOfDevice(ctx, id)
			if err != nil {
				return err
			}
			for _, r := range rows {
				keys = append(keys, cachedKey(r))
			}
			if parts[0] == "device" {
				dev, err = q.GetDevice(ctx, id)
			}
			return err
		}); err != nil {
			return err
		}
		if err := s.putKeys(ctx, org, keys); err != nil {
			return err
		}
		if parts[0] == "device" {
			return s.putUpdateRequest(ctx, id, dev.AgentUpdateRequestedVersion, dev.AgentUpdateRequestedAt)
		}
		return nil
	}
	return fmt.Errorf("unexpected table in notification %q", payload)
}

// ReconcileAll rewrites the cache entries of every organization. A failing organization is logged and skipped, and
// the joined error of all failures is returned: since PDK-475 a device whose counter is missing gets 503 until a
// reconcile restores it, so one broken organization must not keep the devices of all later ones waiting.
func (s *CacheSync) ReconcileAll(ctx context.Context) error {
	var errs []error
	orgs, err := s.pool.OrganizationIDs(principal.With(ctx, principal.Principal{Kind: principal.KindSystem}))
	if err != nil {
		errs = append(errs, err)
	}
	for _, org := range orgs {
		err := s.Reconcile(ctx, org)
		if db.IsOrganizationUnavailable(err) {
			// The organization started deleting after the listing; its deletion removes its keys (amendment s point 6.2).
			continue
		}
		if err != nil {
			slog.WarnContext(ctx, "device cache reconcile of an organization failed", "organization", org, "error", err)
			errs = append(errs, fmt.Errorf("organization %s: %w", org, err))
		}
	}
	// The offboarded devices are platform records, independent of the organization list: they are restored also when
	// that list failed. Only a successful restore counts for the interval, so a failed one is retried by the next
	// reconcile.
	if s.offboarded != nil && (s.restoredAt.IsZero() || !s.now().Before(s.restoredAt.Add(OffboardedRestoreInterval))) {
		started := s.now()
		res, err := s.offboarded.Restore(ctx)
		metricReconcileWrites.WithLabelValues(reconcileWritesOffboarded).Add(float64(res.Written))
		if err != nil {
			slog.WarnContext(ctx, "device cache reconcile of the offboarded devices failed", "error", err)
			errs = append(errs, fmt.Errorf("offboarded devices: %w", err))
		} else {
			s.restoredAt = started
		}
	}
	return errors.Join(errs...)
}

// ReconcilePageSize is the number of identity keys one reconcile transaction reads (plan M17 amendment r point 6).
const ReconcilePageSize = 2000

// cachedKey is one identity key with the state of its device, as ListCachedDeviceKeysPage and
// ListCachedDeviceKeysOfDevice return it.
type cachedKey pgstore.ListCachedDeviceKeysPageRow

// Reconcile rewrites the live tokens and the identity keys of one organization; writing a key restores its device's
// missing sequence number. Every read is a short transaction of its own, the keys in pages of ReconcilePageSize
// keyset-paged by device ID, and Valkey is written only after each transaction committed: a reconcile must not hold
// an organization transaction for as long as Valkey takes, because an organization deletion waits for every open
// one (plan M17 amendment r). A device that changes between two pages is caught by its change notification or the
// next reconcile.
func (s *CacheSync) Reconcile(ctx context.Context, org uuid.UUID) error {
	ctx = systemContext(ctx, org, "cache-sync")
	var tokens []pgstore.EnrollmentToken
	if err := s.pool.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		tokens, err = q.ListLiveEnrollmentTokens(ctx)
		return err
	}); err != nil {
		return err
	}
	for _, tok := range tokens {
		if err := s.putToken(ctx, tok); err != nil {
			return err
		}
	}
	pageSize := s.pageSize
	if pageSize <= 0 {
		pageSize = ReconcilePageSize
	}
	after := pgstore.ListCachedDeviceKeysPageParams{PageSize: int32(pageSize)} //nolint:gosec // a small positive constant
	for {
		var keys []cachedKey
		if err := s.pool.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
			rows, err := q.ListCachedDeviceKeysPage(ctx, after)
			for _, r := range rows {
				keys = append(keys, cachedKey(r))
			}
			return err
		}); err != nil {
			return err
		}
		if err := s.syncKeys(ctx, org, keys); err != nil {
			return err
		}
		if len(keys) < pageSize {
			break
		}
		last := keys[len(keys)-1]
		after.AfterDevice, after.AfterKey = last.DeviceID, last.KeyID
	}
	var requests []pgstore.ListAgentUpdateRequestsRow
	if err := s.pool.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		requests, err = q.ListAgentUpdateRequests(ctx)
		return err
	}); err != nil {
		return err
	}
	for _, r := range requests {
		if err := s.putUpdateRequest(ctx, r.ID, r.AgentUpdateRequestedVersion, r.AgentUpdateRequestedAt); err != nil {
			return err
		}
	}
	return nil
}

// putUpdateRequest writes au:<device> for an open update-now request younger than 24 hours and deletes it otherwise
// (plan M8d decision 26).
func (s *CacheSync) putUpdateRequest(ctx context.Context, device uuid.UUID, version *string, at *time.Time) error {
	if version == nil || at == nil {
		return s.cache.DeleteUpdateRequest(ctx, device)
	}
	return s.cache.PutUpdateRequest(ctx, device, *version, *at, s.now())
}

func (s *CacheSync) putToken(ctx context.Context, tok pgstore.EnrollmentToken) error {
	return s.cache.PutToken(ctx, tok.SecretSha256, devicecache.Token{
		OrganizationID: tok.OrganizationID, Revoked: tok.RevokedAt != nil, ExpiresAt: tok.ExpiresAt,
	}, s.now())
}

// syncKeys caches the identity keys of one reconcile page, writing only those that differ from what Valkey holds (plan
// M17 amendment s point 4.1); keys of pending devices are not cached (plan M2a decision 10).
func (s *CacheSync) syncKeys(ctx context.Context, org uuid.UUID, keys []cachedKey) error {
	entries := make([]devicecache.DeviceKeyEntry, 0, len(keys))
	for _, k := range keys {
		if k.State == "pending" {
			continue
		}
		entries = append(entries, devicecache.DeviceKeyEntry{KeyID: k.KeyID, LastSeq: k.LastSeq, Key: devicecache.DeviceKey{
			DeviceID: k.DeviceID, OrganizationID: org, Status: devicecache.KeyStatus(k.KeyStatus, k.State), PublicKey: k.PublicKey}})
	}
	written, err := s.syncer.SyncDeviceKeys(ctx, entries)
	metricReconcileWrites.WithLabelValues(reconcileWritesDeviceKey).Add(float64(written))
	return err
}

// putKeys caches the identity keys read by Changed unconditionally, since a notification names one changed device;
// keys of pending devices are not cached (plan M2a decision 10).
func (s *CacheSync) putKeys(ctx context.Context, org uuid.UUID, keys []cachedKey) error {
	for _, k := range keys {
		if k.State == "pending" {
			continue
		}
		if err := s.cache.PutDeviceKey(ctx, k.KeyID, devicecache.DeviceKey{
			DeviceID: k.DeviceID, OrganizationID: org, Status: devicecache.KeyStatus(k.KeyStatus, k.State), PublicKey: k.PublicKey,
		}, k.LastSeq); err != nil {
			return err
		}
	}
	return nil
}
