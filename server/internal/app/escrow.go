package app

import (
	"context"
	"fmt"

	"github.com/paddock-mdm/paddock/pkg/escrow"
	"github.com/paddock-mdm/paddock/server/internal/adapters/postgres/pgstore"
	"github.com/paddock-mdm/paddock/server/internal/ingest"
	"github.com/paddock-mdm/paddock/server/internal/platform/db"
)

// Escrow stores the secrets devices escrow (worker, plan M4a decisions 11 and 12). The caller's context carries a
// system principal of the device's organization.
type Escrow struct {
	org *db.OrgPool
}

// NewEscrow creates the use case.
func NewEscrow(org *db.OrgPool) *Escrow { return &Escrow{org: org} }

// Store records an upload as generation stored and returns the status the device polls: stored, or failed for a
// generation that is not above the active one or exists already. A repeated message reports the recorded status.
func (e *Escrow) Store(ctx context.Context, m ingest.Escrow) (string, error) {
	status := escrow.StatusFailed
	err := e.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		if cur, err := q.GetEscrowSecret(ctx, m.EscrowID); err == nil {
			if cur.DeviceID == m.DeviceID && cur.Status != escrow.StatusFailed {
				status = escrow.StatusStored
			}
			return nil
		} else if !db.IsNoRows(err) {
			return err
		}
		active, err := q.ActiveEscrowGeneration(ctx, pgstore.ActiveEscrowGenerationParams{DeviceID: m.DeviceID, Kind: m.Kind})
		if err != nil {
			return fmt.Errorf("active generation: %w", err)
		}
		if m.Generation <= int64(active) || m.Generation > 1<<31-1 {
			return nil
		}
		org, err := orgOf(ctx)
		if err != nil {
			return err
		}
		n, err := q.InsertEscrowSecret(ctx, pgstore.InsertEscrowSecretParams{
			ID: m.EscrowID, OrganizationID: org, DeviceID: m.DeviceID, Kind: m.Kind,
			Generation: int32(m.Generation), Ciphertext: m.Ciphertext, KeyVersion: int32(m.KeyVersion), //nolint:gosec // bounded above and by the gateway
			CreatedAt: m.ReceivedAt,
		})
		if err != nil {
			return fmt.Errorf("insert escrow secret: %w", err)
		}
		if n == 1 {
			status = escrow.StatusStored
		}
		return nil
	})
	return status, err
}
