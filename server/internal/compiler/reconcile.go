package compiler

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/paddock-mdm/paddock/server/internal/adapters/postgres/pgstore"
	"github.com/paddock-mdm/paddock/server/internal/devicecache"
	"github.com/paddock-mdm/paddock/server/internal/principal"
)

// ReconcileInterval is how often the bundle pointers are rewritten from PostgreSQL (plan M2a decision 13, risk R2).
const ReconcileInterval = 60 * time.Second

// RunReconcile rewrites bp: for the newest bundle of every device every ReconcileInterval, so a Valkey failure
// after a commit or an emptied Valkey heals itself.
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
	for _, org := range orgs {
		if err := c.reconcileOrg(systemContext(ctx, org)); err != nil {
			return fmt.Errorf("organization %s: %w", org, err)
		}
	}
	return nil
}

func (c *Compiler) reconcileOrg(ctx context.Context) error {
	var latest []pgstore.Bundle
	if err := c.pool.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		latest, err = q.ListLatestBundles(ctx)
		return err
	}); err != nil {
		return err
	}
	for _, b := range latest {
		if err := c.cache.PutBundlePointer(ctx, b.DeviceID, pointer(b)); err != nil {
			return err
		}
	}
	return nil
}

func pointer(b pgstore.Bundle) devicecache.BundlePointer {
	return devicecache.BundlePointer{Version: b.Version, SHA256: hex.EncodeToString(b.EnvelopeSha256), ObjectKey: b.ObjectKey}
}
