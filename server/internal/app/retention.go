package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// StoreDeviceUserSeen is the store name of the users seen on devices in retention.purged (plan M10 decision 13).
const StoreDeviceUserSeen = "device_user_seen"

// StoreRetiredInventory is the store name of the retired devices' inventory in the round's metrics (plan M10 decision
// 15); its evidence is device.inventory_purged per device.
const StoreRetiredInventory = "retired_inventory"

// retiredInventoryDevices bounds the devices of one organization whose inventory one pass purges (plan M10 decision
// 16); the rest follow in the next round.
const retiredInventoryDevices = 100

// fleetDeleteTimeout bounds the deletion of one Fleet host including the adapter's retries, so a device's action
// finishes well before the outbox reaper's threshold (outbox.DefaultReaperThreshold, 10 minutes) would record it as
// unknown.
const fleetDeleteTimeout = 3 * time.Minute

// retentionBatch is the row limit of one deletion statement; every batch commits on its own, so it bounds how long the
// rows stay locked (plan M10 amendment 2026-10-30).
const retentionBatch = 1000

// retentionPassBudget bounds one pass over one store of an organization. It stays well below the outbox reaper's
// threshold (outbox.DefaultReaperThreshold, 10 minutes): a pass still running then would be finalized as unknown
// without its deleted count. The rows left over follow in the next round (plan M10 amendment 2026-10-30).
const retentionPassBudget = 5 * time.Minute

// retentionLockTimeout bounds the row-lock wait of one batch; a timeout ends the pass like an elapsed budget.
const retentionLockTimeout = 30 * time.Second

// SpecRetentionPurged records one retention pass over one store of an organization; system principal only.
var SpecRetentionPurged = ActionSpec{Code: audit.CodeRetentionPurged}

// SpecDeviceInventoryPurged records the inventory purge of one retired device; system principal only.
var SpecDeviceInventoryPurged = ActionSpec{Code: audit.CodeDeviceInventoryPurged}

// hostUsers answers whether a device of any organization other than the retired one still uses a Fleet host or its
// hardware (db.PlatformPool.FleetHostInUse).
type hostUsers interface {
	FleetHostInUse(ctx context.Context, retiredDevice uuid.UUID, host string) (bool, error)
}

// Retention deletes the expired rows of an organization's stores with deletion evidence (ADR 0032, plan M10 §3.3).
type Retention struct {
	runner    *ActionRunner
	org       *db.OrgPool
	hosts     hostUsers
	inventory ports.InventoryAdmin
	// unit is the length of a retention day: 24 hours, a second in development (PADDOCK_RETENTION_UNIT).
	unit time.Duration
	// budget bounds one pass (retentionPassBudget).
	budget time.Duration
	// lockTimeout bounds the row-lock wait of one batch (retentionLockTimeout).
	lockTimeout time.Duration
}

// NewRetention creates the use cases.
func NewRetention(runner *ActionRunner, org *db.OrgPool, hosts hostUsers, inventory ports.InventoryAdmin, unit time.Duration) *Retention {
	return &Retention{runner: runner, org: org, hosts: hosts, inventory: inventory, unit: unit, budget: retentionPassBudget,
		lockTimeout: retentionLockTimeout}
}

// PurgeUserSeen deletes the users seen on the context's organization's devices whose last login is older than
// SeenWindow at now (system principal). Without expired rows it records nothing. It returns the number of deleted rows
// (purgeBatches).
func (r *Retention) PurgeUserSeen(ctx context.Context, now time.Time) (int64, error) {
	if p, ok := principal.From(ctx); !ok || p.Kind != principal.KindSystem {
		return 0, problem.Unauthenticated
	}
	cutoff := now.Add(-time.Duration(SeenWindow/(24*time.Hour)) * r.unit)
	var expired bool
	err := r.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		expired, err = q.HasExpiredDeviceUserSeen(ctx, cutoff)
		return err
	})
	if err != nil || !expired {
		return 0, err
	}
	return purgeBatches(ctx, r.runner, r.org, StoreDeviceUserSeen, cutoff, r.budget, r.lockTimeout, func(ctx context.Context, q *pgstore.Queries) (int64, error) {
		return q.DeleteExpiredDeviceUserSeen(ctx, cutoff)
	})
}

// PurgeRetiredInventory deletes the inventory of the context's organization's devices retired longer than the
// organization's retired_inventory_days at now, in Paddock and in Fleet (system principal, plan M10 decision 16): one
// device.inventory_purged action per device, at most retiredInventoryDevices per pass, longest retired first. It
// returns the number of devices whose inventory it purged (plan M10 §6.6). A failing device is recorded as its own
// failure event and the pass goes on with the next one, so one device Fleet keeps refusing does not block the
// organization (plan M10 amendment 2026-10-30, PDK-138); the pass then ends partial with an error that counts the
// failed devices. The pass starts no further device once the budget has elapsed.
func (r *Retention) PurgeRetiredInventory(ctx context.Context, now time.Time) (int, error) {
	if p, ok := principal.From(ctx); !ok || p.Kind != principal.KindSystem {
		return 0, problem.Unauthenticated
	}
	var devices []pgstore.ListRetiredDevicesWithInventoryRow
	var cutoff time.Time
	err := r.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		settings, err := LoadPrivacySettings(ctx, q)
		if err != nil {
			return err
		}
		cutoff = now.Add(-time.Duration(settings.RetiredInventoryDays) * r.unit)
		devices, err = q.ListRetiredDevicesWithInventory(ctx, pgstore.ListRetiredDevicesWithInventoryParams{
			Cutoff: cutoff, MaxDevices: retiredInventoryDevices,
		})
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("list retired devices: %w", err)
	}
	start := time.Now()
	var purged, attempted int
	var errs []error
	for _, d := range devices {
		attempted++
		if err := r.purgeDeviceInventory(ctx, d, cutoff); err != nil {
			errs = append(errs, fmt.Errorf("device %s: %w", d.ID, err))
		} else {
			purged++
		}
		if ctx.Err() != nil || time.Since(start) >= r.budget {
			break
		}
	}
	if len(errs) > 0 {
		return purged, fmt.Errorf("purge retired inventory: %d of %d devices failed: %w", len(errs), attempted, errors.Join(errs...))
	}
	return purged, nil
}

// purgeDeviceInventory deletes one retired device's Fleet host and then its Paddock inventory rows as one
// device.inventory_purged action. When the Fleet deletion fails, the Paddock rows stay, so the next round finds the
// device again and retries the host; a host Fleet no longer knows counts as deleted. The host is kept when a device of
// any organization still uses it or the same hardware enrolled again (plan M10 §13, amendment 2026-10-30); the
// retired device's Paddock rows go all the same. When that check fails, nothing is deleted. cutoff is the one the
// device was listed with; a device no longer retired before it is refused under the row lock.
func (r *Retention) purgeDeviceInventory(ctx context.Context, d pgstore.ListRetiredDevicesWithInventoryRow, cutoff time.Time) error {
	spec := SpecDeviceInventoryPurged
	spec.Target = &audit.Target{Type: "device", ID: d.ID.String(), Display: d.Hostname}
	spec.Params = map[string]any{
		"hostname": d.Hostname, "retired_at": audit.Timestamp(d.StateChangedAt).Format(time.RFC3339Nano),
		"software": int64(0), "findings": int64(0), "policy_results": int64(0), "fleet_host_deleted": false,
	}
	var held pgstore.CountDeviceInventoryRow
	var hostDeleted bool
	return r.runner.RunExternal(ctx, ScopeOrg, spec,
		func(ctx context.Context, q *pgstore.Queries, _ Recorder) error {
			if err := r.lockDevice(ctx, q, d.ID, cutoff); err != nil {
				return err
			}
			var err error
			held, err = q.CountDeviceInventory(ctx, d.ID)
			return err
		},
		func(ctx context.Context) error {
			if held.ExternalID == "" {
				return nil
			}
			inUse, err := r.hosts.FleetHostInUse(ctx, d.ID, held.ExternalID)
			if err != nil {
				return err
			}
			if inUse {
				return nil
			}
			ctx, cancel := context.WithTimeout(ctx, fleetDeleteTimeout)
			defer cancel()
			if err := r.inventory.DeleteHost(ctx, ports.HostRef(held.ExternalID)); err != nil {
				return fmt.Errorf("%w: delete the Fleet host: %w", problem.UpstreamUnavailable, err)
			}
			hostDeleted = true
			return nil
		},
		func(ctx context.Context, q *pgstore.Queries, rec Recorder, externalErr error) error {
			// A failed action records the rows it kept; the runner records these params when this transaction fails.
			rec.SetParam("software", held.Software)
			rec.SetParam("findings", held.Findings)
			rec.SetParam("policy_results", held.PolicyResults)
			rec.SetParam("fleet_host_deleted", hostDeleted)
			if externalErr != nil {
				return nil
			}
			if err := r.setLockTimeout(ctx, q); err != nil {
				return err
			}
			n, err := q.DeleteDeviceInventory(ctx, d.ID)
			if err != nil {
				return err
			}
			rec.SetParam("software", n.Software)
			rec.SetParam("findings", n.Findings)
			rec.SetParam("policy_results", n.PolicyResults)
			return nil
		})
}

// lockDevice locks the retired device's row for the action's first transaction, waiting at most the lock timeout, and
// refuses a device that is no longer retired before cutoff.
func (r *Retention) lockDevice(ctx context.Context, q *pgstore.Queries, id uuid.UUID, cutoff time.Time) error {
	if err := r.setLockTimeout(ctx, q); err != nil {
		return err
	}
	dev, err := q.LockDevice(ctx, id)
	if err != nil {
		return err
	}
	if dev.State != "retired" {
		return errors.New("the device is no longer retired")
	}
	// Reactivated and retired again between the list and the lock: its new retirement has not run the period yet.
	if !dev.StateChangedAt.Before(cutoff) {
		return errors.New("the device was retired again inside the retention period")
	}
	return nil
}

func (r *Retention) setLockTimeout(ctx context.Context, q *pgstore.Queries) error {
	return q.SetRetentionLockTimeout(ctx, fmt.Sprintf("%dms", r.lockTimeout.Milliseconds()))
}

// purgeBatches deletes a store's rows older than cutoff in batches of retentionBatch rows, each batch in its own
// transaction, and records them as one retention.purged event (plan M10 amendment 2026-10-30): a long backlog then
// never holds the locks of all its rows in one transaction, so the agents' logins do not wait for the purge. The event
// carries the rows of the committed batches; when a batch fails, the batches before it stay deleted and the event is
// recorded with outcome failure and their number. Once budget has elapsed after a committed batch, the pass ends with
// outcome success and the rows deleted so far; the rest follows in the next round. A batch that waits longer than
// lockTimeout for a row lock rolls back alone and ends the pass the same way.
func purgeBatches(ctx context.Context, runner *ActionRunner, org *db.OrgPool, store string, cutoff time.Time, budget, lockTimeout time.Duration,
	batch func(ctx context.Context, q *pgstore.Queries) (int64, error)) (int64, error) {
	spec := SpecRetentionPurged
	spec.Params = map[string]any{"store": store, "cutoff": audit.Timestamp(cutoff).Format(time.RFC3339Nano)}
	var deleted int64
	err := runner.RunExternal(ctx, ScopeOrg, spec,
		func(context.Context, *pgstore.Queries, Recorder) error { return nil },
		func(ctx context.Context) error {
			start := time.Now()
			for {
				var n int64
				if err := org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
					if err := q.SetRetentionLockTimeout(ctx, fmt.Sprintf("%dms", lockTimeout.Milliseconds())); err != nil {
						return err
					}
					var err error
					n, err = batch(ctx, q)
					return err
				}); db.IsLockTimeout(err) {
					return nil
				} else if err != nil {
					return fmt.Errorf("purge %s: %w", store, err)
				}
				deleted += n
				if n < retentionBatch || time.Since(start) >= budget {
					return nil
				}
			}
		},
		func(_ context.Context, _ *pgstore.Queries, rec Recorder, _ error) error {
			rec.SetParam("deleted", deleted)
			return nil
		})
	return deleted, err
}
