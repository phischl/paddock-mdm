package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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

// retiredInventoryDevices is the page of devices one listing of a pass reads (plan M10 decision 16); the pass pages on
// after the last listed device until its budget elapses, so devices behind ones that keep failing are reached in the
// same pass (amendment 2026-10-30, PDK-138).
const retiredInventoryDevices = 100

// fleetBreakerFailures is the number of consecutive upstream_unavailable failures of the Fleet step after which a
// retention round skips the Fleet step for all its remaining devices and organizations, so an unreachable Fleet does
// not cost every device its own retries and failure event (amendment 2026-10-30, PDK-138).
const fleetBreakerFailures = 3

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

// hostUsers answers whether a device of any organization other than the retired one still uses a Fleet host or may
// use it through the retired device's hardware: db.FleetHostUsedByRef, db.FleetHostUsedByHardware or
// db.FleetHostUnused (db.PlatformPool.FleetHostInUse).
type hostUsers interface {
	FleetHostInUse(ctx context.Context, retiredDevice uuid.UUID, host string) (string, error)
}

// RetentionRound is the state one retention round shares across its organizations' passes: the Fleet step's
// consecutive upstream_unavailable failures. It is not safe for concurrent use; the round runs its passes one after
// another.
type RetentionRound struct {
	fleetFailures int
}

// NewRetentionRound creates the state of one round.
func NewRetentionRound() *RetentionRound { return &RetentionRound{} }

func (r *RetentionRound) fleetSkipped() bool { return r.fleetFailures >= fleetBreakerFailures }

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
	// page is the devices one listing of the retired inventory pass reads (retiredInventoryDevices).
	page int32
}

// NewRetention creates the use cases.
func NewRetention(runner *ActionRunner, org *db.OrgPool, hosts hostUsers, inventory ports.InventoryAdmin, unit time.Duration) *Retention {
	return &Retention{runner: runner, org: org, hosts: hosts, inventory: inventory, unit: unit, budget: retentionPassBudget,
		lockTimeout: retentionLockTimeout, page: retiredInventoryDevices}
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
// device.inventory_purged action per device, longest retired first, in pages of retiredInventoryDevices. It returns
// the number of devices whose inventory it purged (plan M10 §6.6). A failing device is recorded as its own failure
// event and the pass goes on with the next one, also on the next page, so devices Fleet keeps refusing do not block
// the organization (plan M10 amendment 2026-10-30, PDK-138); the pass then ends partial with an error that counts the
// failed devices. The pass starts no further device once the budget has elapsed. Once round has seen
// fleetBreakerFailures consecutive Fleet failures, the pass starts no device at all and records one retention.purged
// failure (upstream_unavailable, store retired_inventory) for the organization instead; the devices keep their rows.
func (r *Retention) PurgeRetiredInventory(ctx context.Context, now time.Time, round *RetentionRound) (int, error) {
	if p, ok := principal.From(ctx); !ok || p.Kind != principal.KindSystem {
		return 0, problem.Unauthenticated
	}
	var cutoff time.Time
	err := r.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		settings, err := LoadPrivacySettings(ctx, q)
		if err != nil {
			return err
		}
		cutoff = now.Add(-time.Duration(settings.RetiredInventoryDays) * r.unit)
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("load the privacy settings: %w", err)
	}
	start := time.Now()
	var purged, attempted int
	var failed, errs []error
	var after pgstore.ListRetiredDevicesWithInventoryRow
pages:
	for {
		devices, err := r.listRetired(ctx, cutoff, after)
		if err != nil {
			errs = append(errs, fmt.Errorf("list retired devices: %w", err))
			break
		}
		for _, d := range devices {
			if round.fleetSkipped() {
				errs = append(errs, r.recordFleetSkipped(ctx, cutoff))
				break pages
			}
			if r.heldForHardware(ctx, d) {
				slog.InfoContext(ctx, "retired device keeps its Fleet host for a device of the same hardware; nothing left to purge",
					"device", d.ID)
			} else {
				attempted++
				if err := r.purgeDeviceInventory(ctx, d, cutoff, round); err != nil {
					failed = append(failed, fmt.Errorf("device %s: %w", d.ID, err))
				} else {
					purged++
				}
			}
			if ctx.Err() != nil || time.Since(start) >= r.budget {
				break pages
			}
		}
		if len(devices) < int(r.page) {
			break
		}
		after = devices[len(devices)-1]
	}
	if len(failed) > 0 {
		errs = append(errs, fmt.Errorf("%d of %d devices failed: %w", len(failed), attempted, errors.Join(failed...)))
	}
	if len(errs) > 0 {
		return purged, fmt.Errorf("purge retired inventory: %w", errors.Join(errs...))
	}
	return purged, nil
}

// listRetired lists the next page of retired devices with inventory after the device after (the zero row for the
// first page).
func (r *Retention) listRetired(ctx context.Context, cutoff time.Time, after pgstore.ListRetiredDevicesWithInventoryRow) (
	[]pgstore.ListRetiredDevicesWithInventoryRow, error) {
	var devices []pgstore.ListRetiredDevicesWithInventoryRow
	err := r.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		devices, err = q.ListRetiredDevicesWithInventory(ctx, pgstore.ListRetiredDevicesWithInventoryParams{
			Cutoff: cutoff, AfterChanged: after.StateChangedAt, AfterID: after.ID, MaxDevices: r.page,
		})
		return err
	})
	return devices, err
}

// heldForHardware reports whether a listed device has nothing left but the host reference that a device of the same
// hardware may still use (db.FleetHostUsedByHardware). The pass then starts no action for it: the answer has not
// changed since the round that purged its other rows, and an event with nothing deleted every round would be noise
// (plan M10 amendment 2026-10-30, PDK-583). Any error reports false, so the action re-checks under the row lock and
// records the failure.
func (r *Retention) heldForHardware(ctx context.Context, d pgstore.ListRetiredDevicesWithInventoryRow) bool {
	var held pgstore.CountDeviceInventoryRow
	err := r.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		held, err = q.CountDeviceInventory(ctx, d.ID)
		return err
	})
	if err != nil || held.ExternalID == "" || held.Software+held.Findings+held.PolicyResults != 0 {
		return false
	}
	use, err := r.hosts.FleetHostInUse(ctx, d.ID, held.ExternalID)
	return err == nil && use == db.FleetHostUsedByHardware
}

// recordFleetSkipped records the one retention.purged failure of an organization whose retired devices the round no
// longer offers to Fleet, and returns its error.
func (r *Retention) recordFleetSkipped(ctx context.Context, cutoff time.Time) error {
	spec := SpecRetentionPurged
	spec.Params = map[string]any{"store": StoreRetiredInventory, "cutoff": audit.Timestamp(cutoff).Format(time.RFC3339Nano),
		"deleted": int64(0)}
	skipped := fmt.Errorf("%w: the Fleet step failed %d times in a row this round; retired devices are retried next round",
		problem.UpstreamUnavailable, fleetBreakerFailures)
	return r.runner.RunTx(ctx, ScopeOrg, spec, func(context.Context, *pgstore.Queries, Recorder) error { return skipped })
}

// purgeDeviceInventory deletes one retired device's Fleet host and then its Paddock inventory rows as one
// device.inventory_purged action. When the Fleet deletion fails, the Paddock rows stay, so the next round finds the
// device again and retries the host; a host Fleet no longer knows counts as deleted. The host is kept when a device of
// any organization still references it; the retired device's Paddock rows go all the same. When a device of the same
// hardware has no reference yet, the host is kept and so is the retired device's reference, so later rounds list the
// device again and decide once that device has synced or is gone (plan M10 amendments 2026-10-30); fleet_host_in_use
// records the answer. When that check fails, nothing is deleted. cutoff is the one the device was listed with; a
// device no longer retired before it is refused under the row lock. round counts the Fleet step's consecutive
// upstream_unavailable failures; Fleet's refusal of this one host (invalid_state) fails the device without counting
// (plan M10 amendment 2026-10-30, PDK-583).
func (r *Retention) purgeDeviceInventory(ctx context.Context, d pgstore.ListRetiredDevicesWithInventoryRow, cutoff time.Time,
	round *RetentionRound) error {
	spec := SpecDeviceInventoryPurged
	spec.Target = &audit.Target{Type: "device", ID: d.ID.String(), Display: d.Hostname}
	spec.Params = map[string]any{
		"hostname": d.Hostname, "retired_at": audit.Timestamp(d.StateChangedAt).Format(time.RFC3339Nano),
		"software": int64(0), "findings": int64(0), "policy_results": int64(0), "fleet_host_deleted": false,
	}
	var held pgstore.CountDeviceInventoryRow
	var use string
	var hostDeleted bool
	var fleetErr error
	err := r.runner.RunExternal(ctx, ScopeOrg, spec,
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
			var err error
			use, err = r.hosts.FleetHostInUse(ctx, d.ID, held.ExternalID)
			if err != nil {
				return err
			}
			switch use {
			case db.FleetHostUsedByRef, db.FleetHostUsedByHardware:
				return nil
			case db.FleetHostUnused:
			default:
				return fmt.Errorf("check the Fleet host's other devices: unexpected answer %q", use)
			}
			ctx, cancel := context.WithTimeout(ctx, fleetDeleteTimeout)
			defer cancel()
			if fleetErr = r.inventory.DeleteHost(ctx, ports.HostRef(held.ExternalID)); fleetErr != nil {
				return fmt.Errorf("delete the Fleet host: %w", fleetErr)
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
			if use != "" {
				rec.SetParam("fleet_host_in_use", use)
			}
			if externalErr != nil {
				return nil
			}
			if err := r.setLockTimeout(ctx, q); err != nil {
				return err
			}
			n, err := q.DeleteDeviceInventory(ctx, pgstore.DeleteDeviceInventoryParams{
				DeviceID: d.ID, KeepRef: use == db.FleetHostUsedByHardware,
			})
			if err != nil {
				return err
			}
			rec.SetParam("software", n.Software)
			rec.SetParam("findings", n.Findings)
			rec.SetParam("policy_results", n.PolicyResults)
			return nil
		})
	switch {
	case hostDeleted:
		round.fleetFailures = 0
	case errors.Is(fleetErr, problem.UpstreamUnavailable):
		round.fleetFailures++
	}
	return err
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
