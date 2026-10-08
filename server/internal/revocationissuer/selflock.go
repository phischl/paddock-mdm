package revocationissuer

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/revocation"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	domain "github.com/phischl/paddock-mdm/server/internal/domain/revocation"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/revocationsign"
)

// reconcileSelfLocks keeps one self-lock token per active device while the organization's dead man's switch is on
// (plan M4c decision 15): no approvals and no limits, period_days in the token, valid a year and replaced 60 days
// before it expires or when the period changes. Tokens of a switch that is off, of a period that changed or of a
// device that is no longer active, and those whose volumes no longer match the device's volumes with a confirmed
// header escrow (PDK-009 decision 6), are cancelled and removed from cmd:<device_id>; the same round issues the
// replacement.
func (i *Issuer) reconcileSelfLocks(ctx context.Context) error {
	now := i.now().UTC().Truncate(time.Second)
	var enabled bool
	var period int32
	var cancelled []pgstore.CancelSelfLocksRow
	var devices []pgstore.ListDevicesWithoutSelfLockRow
	err := i.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		s, err := q.GetDMSSettings(ctx)
		if err != nil && !db.IsNoRows(err) {
			return err
		}
		// While revocation is disabled the issuer signs nothing, self-locks neither (plan M4c decision 1).
		enabled, period = err == nil && s.Enabled && i.enabled, s.PeriodDays
		if cancelled, err = q.CancelSelfLocks(ctx, pgstore.CancelSelfLocksParams{
			Now: now, Enabled: enabled, PeriodDays: period, RenewBefore: now.Add(domain.SelfLockRenewal),
		}); err != nil || !enabled {
			return err
		}
		devices, err = q.ListDevicesWithoutSelfLock(ctx)
		return err
	})
	if err != nil {
		return err
	}
	for _, c := range cancelled {
		if err := i.commands.DeleteCommand(ctx, c.DeviceID, c.ID); err != nil {
			return err
		}
	}
	for _, dev := range devices {
		if err := i.issueSelfLock(ctx, dev, period, now); err != nil {
			slog.WarnContext(ctx, "issuing a self-lock token failed; retrying next round", "device_id", dev.ID, "error", err)
		}
	}
	return nil
}

// issueSelfLock signs and records the self-lock token of a device (audited: revocation.issued, action self_lock)
// and puts it into cmd:<device_id>; the agent stores it, it does not execute it.
func (i *Issuer) issueSelfLock(ctx context.Context, dev pgstore.ListDevicesWithoutSelfLockRow, period int32, now time.Time) error {
	id := uuid.Must(uuid.NewV7())
	p := app.ActionSpec{
		Code:   audit.CodeRevocationIssued,
		Target: &audit.Target{Type: "device", ID: dev.ID.String(), Display: dev.Hostname},
		Params: map[string]any{"action": revocation.ActionSelfLock, "hostname": dev.Hostname, "request_id": id.String(),
			"expires_at": now.Add(domain.SelfLockLifetime).Format(time.RFC3339)},
	}
	var issued pgstore.RevocationRequest
	org := dev.OrganizationID
	err := i.runner.RunTx(ctx, app.ScopeOrg, p, func(ctx context.Context, q *pgstore.Queries, rec app.Recorder) error {
		expires := now.Add(domain.SelfLockLifetime)
		volumes, err := lockVolumes(ctx, q, dev.ID)
		if err != nil {
			return err
		}
		rec.SetParam("volumes", len(volumes))
		env, err := revocationsign.Sign(ctx, i.signer, revocation.Token{
			CommandID: id.String(), DeviceID: dev.ID.String(), OrganizationID: org.String(), Action: revocation.ActionSelfLock,
			IssuedAt: now, ExpiresAt: expires, RequestID: id.String(), PeriodDays: int(period), Volumes: volumeStrings(volumes),
		})
		if err != nil {
			return err
		}
		issued, err = q.InsertSelfLock(ctx, pgstore.InsertSelfLockParams{
			ID: id, OrganizationID: org, DeviceID: dev.ID, IssuedAt: now, ExpiresAt: &expires, Envelope: env, PeriodDays: &period,
			Volumes: volumes,
		})
		return err
	})
	if err != nil {
		return err
	}
	return i.commands.PutCommand(ctx, issued.DeviceID, issued.ID, devicecache.Command{ExpiresAt: *issued.ExpiresAt, Envelope: issued.Envelope})
}
