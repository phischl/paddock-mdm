package app

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/dsse"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// StoreOffboardedDevice is the store name of the records of devices of deleted organizations in retention.purged (plan
// M17 decision 15).
const StoreOffboardedDevice = "offboarded_device"

// offboardedBatch bounds the records one purge transaction deletes.
const offboardedBatch = 500

// offboardedKey is one element of offboarded_device.keys: [{"key_id": "...", "public_key": "<base64 SPKI DER>"}].
type offboardedKey struct {
	KeyID     string `json:"key_id"`
	PublicKey []byte `json:"public_key"`
}

// OffboardedDeviceCache is what a device of a deleted organization keeps in Valkey (devicecache.Cache).
type OffboardedDeviceCache interface {
	PutOffboardedDevice(ctx context.Context, d devicecache.OffboardedDevice, lastSeq int64) error
	DeleteOffboardedDevice(ctx context.Context, device uuid.UUID, keyIDs []string) error
}

// OffboardedDevices are the devices of deleted organizations that had not reported their removal (plan M17 decision
// 15, ADR 0052 decision 2). Their records live in the platform table offboarded_device; a device's report of its
// removal, or the 365-day retention, deletes the record and the keys it kept in Valkey (amendment l point 3).
type OffboardedDevices struct {
	runner   *ActionRunner
	platform *db.PlatformPool
	cache    OffboardedDeviceCache
}

// NewOffboardedDevices creates the use cases; platform is the worker's platform pool.
func NewOffboardedDevices(runner *ActionRunner, platform *db.PlatformPool, cache OffboardedDeviceCache) *OffboardedDevices {
	return &OffboardedDevices{runner: runner, platform: platform, cache: cache}
}

func offboardedSystem(ctx context.Context) context.Context {
	return principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "offboarded-devices"})
}

// keyIDs reads the key IDs of a record.
func keyIDs(raw json.RawMessage) ([]string, error) {
	var keys []offboardedKey
	if err := json.Unmarshal(raw, &keys); err != nil {
		return nil, fmt.Errorf("offboarded device keys: %w", err)
	}
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = k.KeyID
	}
	return out, nil
}

// Uninstalled handles agent.uninstalled of a device whose organization is being deleted or was deleted: it deletes
// the device's record and cached keys and records platform.offboarded_device_uninstalled, exactly once. It reports
// false when the device has no record (a redelivery, or a device that reported before the step devices, amendment f
// point 2). The keys are deleted before and after the record: before, so a failed deletion keeps the record for the
// retry; after, so keys a concurrent cache sync rewrote in between go too (Restore deletes what it rewrote for a
// record that is gone).
func (o *OffboardedDevices) Uninstalled(ctx context.Context, device uuid.UUID) (bool, error) {
	ctx = offboardedSystem(ctx)
	var row pgstore.OffboardedDevice
	err := o.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		row, err = q.GetOffboardedDevice(ctx, device)
		return err
	})
	if db.IsNoRows(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read offboarded device %s: %w", device, err)
	}
	keys, err := keyIDs(row.Keys)
	if err != nil {
		return false, err
	}
	if err := o.cache.DeleteOffboardedDevice(ctx, device, keys); err != nil {
		return false, err
	}
	spec := ActionSpec{Code: audit.CodePlatformOffboardedDeviceUninstalled,
		Target: &audit.Target{Type: "device", ID: device.String()},
		Params: map[string]any{"device_id": device.String(), "organization_id": row.OrganizationID.String()}}
	recorded, err := o.runner.RecordOnceInScope(ctx, ScopePlatform, spec,
		func(ctx context.Context, q *pgstore.Queries, _ Recorder) (bool, error) {
			_, err := q.DeleteOffboardedDevice(ctx, device)
			if db.IsNoRows(err) {
				return false, nil
			}
			return err == nil, err
		})
	if err != nil {
		return false, fmt.Errorf("delete offboarded device %s: %w", device, err)
	}
	if err := o.cache.DeleteOffboardedDevice(ctx, device, keys); err != nil {
		slog.WarnContext(ctx, "deleting the keys of an uninstalled offboarded device again failed", "device_id", device, "error", err)
	}
	return recorded, nil
}

// Restore rewrites the cached keys and the uninstall of every offboarded device (the cache sync, after Valkey lost its
// data). A missing counter restarts at 0: the device's check-in counter left with its organization's rows, and the
// gateway records no heartbeat for such a device. Keys of a record deleted while they were rewritten are deleted
// again, so a device that reported its removal meanwhile keeps nothing.
func (o *OffboardedDevices) Restore(ctx context.Context) (int, error) {
	ctx = offboardedSystem(ctx)
	var rows []pgstore.OffboardedDevice
	err := o.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		rows, err = q.ListOffboardedDevices(ctx)
		return err
	})
	if err != nil || len(rows) == 0 {
		return 0, err
	}
	ids := make([]uuid.UUID, 0, len(rows))
	keysOf := map[uuid.UUID][]string{}
	for _, r := range rows {
		d, err := cachedOffboardedDevice(r)
		if err != nil {
			slog.WarnContext(ctx, "an offboarded device's record is unusable; not cached", "device_id", r.DeviceID, "error", err)
			continue
		}
		if err := o.cache.PutOffboardedDevice(ctx, d, 0); err != nil {
			return 0, err
		}
		ids = append(ids, r.DeviceID)
		for _, k := range d.Keys {
			keysOf[r.DeviceID] = append(keysOf[r.DeviceID], k.KeyID)
		}
	}
	var present []uuid.UUID
	err = o.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		present, err = q.ListPresentOffboardedDevices(ctx, ids)
		return err
	})
	if err != nil {
		return 0, err
	}
	still := make(map[uuid.UUID]bool, len(present))
	for _, id := range present {
		still[id] = true
	}
	for _, id := range ids {
		if !still[id] {
			if err := o.cache.DeleteOffboardedDevice(ctx, id, keysOf[id]); err != nil {
				return 0, err
			}
		}
	}
	return len(present), nil
}

// cachedOffboardedDevice is the cache entry of a record; the command's expiry is read from its signed payload.
func cachedOffboardedDevice(r pgstore.OffboardedDevice) (devicecache.OffboardedDevice, error) {
	var keys []offboardedKey
	if err := json.Unmarshal(r.Keys, &keys); err != nil {
		return devicecache.OffboardedDevice{}, fmt.Errorf("keys: %w", err)
	}
	_, payload, err := dsse.Decode(r.CommandEnvelope)
	if err != nil {
		return devicecache.OffboardedDevice{}, fmt.Errorf("envelope: %w", err)
	}
	var c command.Command
	if err := json.Unmarshal(payload, &c); err != nil {
		return devicecache.OffboardedDevice{}, fmt.Errorf("command: %w", err)
	}
	d := devicecache.OffboardedDevice{ID: r.DeviceID, OrganizationID: r.OrganizationID, CommandID: r.CommandID,
		Command: devicecache.Command{ExpiresAt: c.ExpiresAt, Envelope: r.CommandEnvelope}}
	for _, k := range keys {
		d.Keys = append(d.Keys, devicecache.OffboardedKey{KeyID: k.KeyID, PublicKey: k.PublicKey})
	}
	return d, nil
}

// Purge deletes the records older than OffboardedDeviceRetention at now and their cached keys, with one
// retention.purged (store offboarded_device) in the platform pseudo-organization; without expired records it records
// nothing (system principal). The retention is counted in real days, never in the development retention unit: the
// command the device fetches is valid as long. Each batch deletes the keys before and after its records, as
// Uninstalled does. It returns the number of deleted records.
func (o *OffboardedDevices) Purge(ctx context.Context, now time.Time) (int64, error) {
	if p, ok := principal.From(ctx); !ok || p.Kind != principal.KindSystem {
		return 0, problem.Unauthenticated
	}
	cutoff := now.Add(-organization.OffboardedDeviceRetention)
	list := func(ctx context.Context) ([]pgstore.OffboardedDevice, error) {
		var rows []pgstore.OffboardedDevice
		err := o.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
			var err error
			rows, err = q.ListExpiredOffboardedDevices(ctx, pgstore.ListExpiredOffboardedDevicesParams{Before: cutoff, MaxRows: offboardedBatch})
			return err
		})
		return rows, err
	}
	rows, err := list(ctx)
	if err != nil || len(rows) == 0 {
		return 0, err
	}
	spec := SpecRetentionPurged
	spec.Params = map[string]any{"store": StoreOffboardedDevice, "cutoff": audit.Timestamp(cutoff).Format(time.RFC3339Nano)}
	var deleted int64
	err = o.runner.RunExternal(ctx, ScopePlatform, spec,
		func(context.Context, *pgstore.Queries, Recorder) error { return nil },
		func(ctx context.Context) error {
			for len(rows) > 0 {
				ids := make([]uuid.UUID, len(rows))
				keys := make([][]string, len(rows))
				for i, r := range rows {
					ids[i] = r.DeviceID
					if keys[i], err = keyIDs(r.Keys); err != nil {
						slog.WarnContext(ctx, "an expired offboarded device's keys are unreadable; its seq, sd and cmd keys go",
							"device_id", r.DeviceID, "error", err)
					}
				}
				drop := func() error {
					for i, id := range ids {
						if err := o.cache.DeleteOffboardedDevice(ctx, id, keys[i]); err != nil {
							return err
						}
					}
					return nil
				}
				if err := drop(); err != nil {
					return err
				}
				var n int64
				if err := o.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
					var err error
					n, err = q.DeleteOffboardedDevices(ctx, ids)
					return err
				}); err != nil {
					return fmt.Errorf("purge %s: %w", StoreOffboardedDevice, err)
				}
				deleted += n
				if err := drop(); err != nil {
					return err
				}
				if len(rows) < offboardedBatch {
					return nil
				}
				if rows, err = list(ctx); err != nil {
					return err
				}
			}
			return nil
		},
		func(_ context.Context, _ *pgstore.Queries, rec Recorder, _ error) error {
			rec.SetParam("deleted", deleted)
			return nil
		})
	return deleted, err
}
