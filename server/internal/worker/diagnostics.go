package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// DiagnosticsInterval is the period of the diagnostics round: uploaded bundles are verified against their objects
// (plan M12 decision 5).
const DiagnosticsInterval = 30 * time.Second

// diagnosticsLockKey is the advisory lock of the diagnostics round ("padddiag").
const diagnosticsLockKey = 0x7061646464696167

// Diagnostics records the devices' announcements of diagnostics bundles, which arrive on the escrow ingest queue
// (Escrow.WithDiagnostics), and runs the round that verifies uploaded bundles (ADR 0048 decision 3). Nothing of a
// bundle but its hash is logged.
type Diagnostics struct {
	diagnostics *app.Diagnostics
	pool        *db.OrgPool
	platform    *db.PlatformPool
	interval    time.Duration
}

// NewDiagnostics creates the announcement handler and the round.
func NewDiagnostics(diagnostics *app.Diagnostics, pool *db.OrgPool, platform *db.PlatformPool) *Diagnostics {
	return &Diagnostics{diagnostics: diagnostics, pool: pool, platform: platform, interval: DiagnosticsInterval}
}

func (d *Diagnostics) announce(ctx context.Context, messageID string, body []byte) outcome {
	var m ingest.DiagnosticsAnnounced
	if err := decode(body, &m); err != nil {
		return poison
	}
	ctx = systemContext(ctx, m.OrganizationID, messageID)
	counted, err := d.diagnostics.Announce(ctx, m)
	if err != nil {
		slog.WarnContext(ctx, "recording diagnostics announcement failed; retrying", "diagnostics_id", m.DiagnosticsID, "error", err)
		return retry
	}
	slog.InfoContext(ctx, "diagnostics announcement processed", "device_id", m.DeviceID, "diagnostics_id", m.DiagnosticsID,
		"sha256", m.SHA256, "size", m.Size, "counted", counted)
	return ack
}

// Run runs the round at start and then every interval until ctx ends; only the replica holding the lock acts.
func (d *Diagnostics) Run(ctx context.Context) error {
	tick := time.NewTicker(d.interval)
	defer tick.Stop()
	for {
		if err := d.Round(ctx); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "diagnostics round failed; retrying next round", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// Round verifies the uploaded bundles of every organization; one organization's failure never holds up the others.
func (d *Diagnostics) Round(ctx context.Context) error {
	sys := principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker"})
	_, err := d.platform.WithLeaderLock(sys, diagnosticsLockKey, func(ctx context.Context) error {
		orgs, err := d.pool.OrganizationIDs(ctx)
		if err != nil {
			return err
		}
		var errs []error
		for _, org := range orgs {
			if err := d.diagnostics.Verify(systemContext(ctx, org, "diagnostics-round")); err != nil {
				errs = append(errs, fmt.Errorf("organization %s: %w", org, err))
			}
		}
		if len(errs) > 0 {
			return fmt.Errorf("%d of %d organizations failed: %w", len(errs), len(orgs), errors.Join(errs...))
		}
		return nil
	})
	return err
}
