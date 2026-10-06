package compiler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	"github.com/phischl/paddock-mdm/server/internal/domain/statechange"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// ReconcileInterval is how often the bundle pointers are rewritten from PostgreSQL (plan M2a decision 13, risk R2).
const ReconcileInterval = 60 * time.Second

// RunReconcile rewrites bp: for the newest bundle of every device every ReconcileInterval, so a Valkey failure
// after a commit or an emptied Valkey heals itself, and recompiles devices whose agent reports another bundle schema
// than their latest bundle has (an agent update to schema 2, plan M3a decision 14a). When the keys object of v2
// bundles changed (a key rotation, or the first round after start), it recompiles every organization once, so
// devices receive the new keys (plan M4a decision 5); unchanged devices keep their bundle version.
func (c *Compiler) RunReconcile(ctx context.Context) {
	for {
		if err := c.Reconcile(ctx); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "bundle pointer reconcile failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(ReconcileInterval):
		}
	}
}

// Reconcile rewrites the bundle pointers of every organization.
func (c *Compiler) Reconcile(ctx context.Context) error {
	orgs, err := c.pool.OrganizationIDs(principal.With(ctx, principal.Principal{Kind: principal.KindSystem}))
	if err != nil {
		return err
	}
	keys, err := c.keys(ctx)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(keys)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(raw)
	keysChanged := digest != c.keysDigest
	for _, org := range orgs {
		if err := c.reconcileOrg(systemContext(ctx, org), keysChanged); err != nil {
			return fmt.Errorf("organization %s: %w", org, err)
		}
	}
	c.keysDigest = digest
	return nil
}

func (c *Compiler) reconcileOrg(ctx context.Context, keysChanged bool) error {
	var latest []pgstore.Bundle
	var outdated []uuid.UUID
	if err := c.pool.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		if latest, err = q.ListLatestBundles(ctx); err != nil {
			return err
		}
		outdated, err = q.ListDevicesWithOutdatedSchema(ctx)
		return err
	}); err != nil {
		return err
	}
	for _, b := range latest {
		if err := c.cache.PutBundlePointer(ctx, b.DeviceID, pointer(b)); err != nil {
			return err
		}
	}
	org, _ := principal.From(ctx)
	if keysChanged {
		return c.compileOrg(ctx, org.OrganizationID, []statechange.Event{
			{OrganizationID: org.OrganizationID, Scope: statechange.ScopeOrg, ID: org.OrganizationID},
		})
	}
	if len(outdated) == 0 {
		return nil
	}
	events := make([]statechange.Event, len(outdated))
	for i, d := range outdated {
		events[i] = statechange.Event{OrganizationID: org.OrganizationID, Scope: statechange.ScopeDevice, ID: d}
	}
	slog.InfoContext(ctx, "recompiling devices whose agent changed its bundle schema", "devices", len(outdated))
	return c.compileOrg(ctx, org.OrganizationID, events)
}

func pointer(b pgstore.Bundle) devicecache.BundlePointer {
	return devicecache.BundlePointer{Version: b.Version, SHA256: hex.EncodeToString(b.EnvelopeSha256), ObjectKey: b.ObjectKey}
}
