package worker

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/server/internal/adapters/postgres/pgstore"
	"github.com/paddock-mdm/paddock/server/internal/devicecache"
	"github.com/paddock-mdm/paddock/server/internal/platform/db"
	"github.com/paddock-mdm/paddock/server/internal/principal"
)

// ReconcileInterval is how often the cache sync rewrites every entry from PostgreSQL (plan M2a risk R2).
const ReconcileInterval = 60 * time.Second

// notifyChannel is the PostgreSQL channel of the device_cache_notify trigger (migration 00003).
const notifyChannel = "device_cache"

// CacheSync keeps et: and dk: in Valkey equal to PostgreSQL: immediately on change notifications and completely
// every ReconcileInterval, which also repairs lost notifications and an emptied Valkey.
type CacheSync struct {
	pool     *db.OrgPool
	cache    *devicecache.Cache
	interval time.Duration
	now      func() time.Time
}

// NewCacheSync creates the sync.
func NewCacheSync(pool *db.OrgPool, cache *devicecache.Cache) *CacheSync {
	return &CacheSync{pool: pool, cache: cache, interval: ReconcileInterval, now: time.Now}
}

// Run listens for changes and reconciles periodically until ctx ends.
func (s *CacheSync) Run(ctx context.Context) error {
	go s.listen(ctx)
	for {
		if err := s.ReconcileAll(ctx); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "device cache reconcile failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(s.interval):
		}
	}
}

func (s *CacheSync) listen(ctx context.Context) {
	for ctx.Err() == nil {
		err := s.pool.Listen(ctx, notifyChannel, func(payload string) {
			if err := s.Changed(ctx, payload); err != nil {
				slog.WarnContext(ctx, "device cache update failed; the reconcile loop repairs it", "change", payload, "error", err)
			}
		})
		if ctx.Err() == nil {
			slog.WarnContext(ctx, "device cache LISTEN failed; reconciling continues", "error", err)
			select {
			case <-ctx.Done():
			case <-time.After(5 * time.Second):
			}
		}
	}
}

// Changed applies one change notification "<table>:<organization_id>:<id>".
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
	return s.pool.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		switch parts[0] {
		case "enrollment_token":
			tok, err := q.GetEnrollmentToken(ctx, id)
			if err != nil {
				return err
			}
			return s.putToken(ctx, tok)
		case "device", "device_identity_key":
			return s.putKeys(ctx, q, org, uuid.NullUUID{UUID: id, Valid: true})
		}
		return fmt.Errorf("unexpected table in notification %q", payload)
	})
}

// ReconcileAll rewrites the cache entries of every organization.
func (s *CacheSync) ReconcileAll(ctx context.Context) error {
	orgs, err := s.pool.OrganizationIDs(principal.With(ctx, principal.Principal{Kind: principal.KindSystem}))
	if err != nil {
		return err
	}
	for _, org := range orgs {
		if err := s.Reconcile(ctx, org); err != nil {
			return fmt.Errorf("organization %s: %w", org, err)
		}
	}
	return nil
}

// Reconcile rewrites the live tokens and the identity keys of one organization.
func (s *CacheSync) Reconcile(ctx context.Context, org uuid.UUID) error {
	ctx = systemContext(ctx, org, "cache-sync")
	return s.pool.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		tokens, err := q.ListLiveEnrollmentTokens(ctx)
		if err != nil {
			return err
		}
		for _, tok := range tokens {
			if err := s.putToken(ctx, tok); err != nil {
				return err
			}
		}
		return s.putKeys(ctx, q, org, uuid.NullUUID{})
	})
}

func (s *CacheSync) putToken(ctx context.Context, tok pgstore.EnrollmentToken) error {
	return s.cache.PutToken(ctx, tok.SecretSha256, devicecache.Token{
		OrganizationID: tok.OrganizationID, Revoked: tok.RevokedAt != nil, ExpiresAt: tok.ExpiresAt,
	}, s.now())
}

// putKeys caches the identity keys of one device or, with a null device, of the whole organization.
func (s *CacheSync) putKeys(ctx context.Context, q *pgstore.Queries, org uuid.UUID, deviceID uuid.NullUUID) error {
	keys, err := q.ListCachedDeviceKeys(ctx, deviceID)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if err := s.cache.PutDeviceKey(ctx, k.KeyID, devicecache.DeviceKey{
			DeviceID: k.DeviceID, OrganizationID: org, Status: devicecache.KeyStatus(k.KeyStatus, k.State), PublicKey: k.PublicKey,
		}); err != nil {
			return err
		}
	}
	return nil
}
