package devicecache

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/valkey-io/valkey-go"
)

// syncBatch bounds the entries of one pipelined read and write round of the Syncer.
const syncBatch = 500

// DeviceKeyEntry is one identity key the periodic reconcile wants cached, with its device's last sequence number
// (PutDeviceKey).
type DeviceKeyEntry struct {
	KeyID   string
	Key     DeviceKey
	LastSeq int64
}

// Syncer is the periodic reconcile's writer (plan M17 amendment s point 4.1): it reads what Valkey holds and writes
// only what differs, so a reconcile of unchanged entries appends nothing to the AOF. It compares with Valkey rather
// than with a process-local fingerprint because other paths (enrolment, the deletion's devices step, change
// notifications) write dk: too, and a skipped write of a stale active key would be a security defect. The worker's
// Valkey user may run HGETALL on dk: and cmd: only, through its read-only selector (ADR 0051 amendment 2026-11-16).
type Syncer struct{ c *Cache }

// NewSyncer creates the Syncer of c.
func NewSyncer(c *Cache) *Syncer { return &Syncer{c: c} }

// SyncDeviceKeys caches the identity keys as PutDeviceKey does: a missing seq:<device> is restored from LastSeq and a
// live one is left unchanged, then every dk: whose fields differ from the wanted ones is replaced. It returns the
// number of keys written (restored counters and replaced identity keys).
func (s *Syncer) SyncDeviceKeys(ctx context.Context, entries []DeviceKeyEntry) (written int, err error) {
	for start := 0; start < len(entries); start += syncBatch {
		batch := entries[start:min(start+syncBatch, len(entries))]
		seqs := make(map[uuid.UUID]int64, len(batch))
		keys := make([]string, len(batch))
		for i, e := range batch {
			if _, ok := seqs[e.Key.DeviceID]; !ok {
				seqs[e.Key.DeviceID] = e.LastSeq
			}
			keys[i] = deviceKeyKey(e.KeyID)
		}
		n, err := s.restoreSeqs(ctx, seqs)
		written += n
		if err != nil {
			return written, err
		}
		have, err := s.hashes(ctx, keys)
		if err != nil {
			return written, err
		}
		for i, e := range batch {
			want := deviceKeyFields(e.Key)
			if maps.Equal(have[i], want) {
				continue
			}
			if err := s.c.putHash(ctx, keys[i], time.Time{}, want); err != nil {
				return written, err
			}
			written++
		}
	}
	return written, nil
}

// SyncOffboardedDevices caches the devices as PutOffboardedDevice does with lastSeq 0: a missing seq:<device> is
// restored, the fields of cmd:<device> that are missing or differ are set (a field is never removed, amendment n point
// 2), then every dk: of the device whose fields differ is replaced with status offboarded. It returns the number of
// keys written.
func (s *Syncer) SyncOffboardedDevices(ctx context.Context, devices []OffboardedDevice) (written int, err error) {
	for start := 0; start < len(devices); start += syncBatch {
		batch := devices[start:min(start+syncBatch, len(devices))]
		seqs := make(map[uuid.UUID]int64, len(batch))
		var keys []string
		for _, d := range batch {
			seqs[d.ID] = 0
			keys = append(keys, commandsKey(d.ID))
			for _, k := range d.Keys {
				keys = append(keys, deviceKeyKey(k.KeyID))
			}
		}
		n, err := s.restoreSeqs(ctx, seqs)
		written += n
		if err != nil {
			return written, err
		}
		have, err := s.hashes(ctx, keys)
		if err != nil {
			return written, err
		}
		next := 0
		for _, d := range batch {
			cmds := have[next]
			next++
			hset := s.c.c.B().Hset().Key(commandsKey(d.ID)).FieldValue()
			missing := 0
			for _, oc := range d.Commands {
				value, err := json.Marshal(oc.Command)
				if err != nil {
					return written, err
				}
				if v, ok := cmds[oc.ID.String()]; ok && v == string(value) {
					continue
				}
				hset = hset.FieldValue(oc.ID.String(), string(value))
				missing++
			}
			// The commands go before the keys, as in PutOffboardedDevice: a check-in that already sees the offboarded
			// key finds them.
			if missing > 0 {
				if err := s.c.c.Do(ctx, hset.Build()).Error(); err != nil {
					return written, fmt.Errorf("devicecache: put the commands of offboarded device %s: %w", d.ID, err)
				}
				written++
			}
			for _, k := range d.Keys {
				current := have[next]
				next++
				want := deviceKeyFields(DeviceKey{DeviceID: d.ID, OrganizationID: d.OrganizationID, Status: KeyOffboarded,
					PublicKey: k.PublicKey})
				if maps.Equal(current, want) {
					continue
				}
				if err := s.c.putHash(ctx, deviceKeyKey(k.KeyID), time.Time{}, want); err != nil {
					return written, err
				}
				written++
			}
		}
	}
	return written, nil
}

// restoreSeqs sets every missing seq:<device> in one pipeline (RestoreSeq); a counter that exists fails its NX and
// appends nothing to the AOF. It returns the number of counters set.
func (s *Syncer) restoreSeqs(ctx context.Context, seqs map[uuid.UUID]int64) (int, error) {
	if len(seqs) == 0 {
		return 0, nil
	}
	cmds := make(valkey.Commands, 0, len(seqs))
	for device, last := range seqs {
		cmds = append(cmds, s.c.c.B().Set().Key(seqKey(device)).Value(strconv.FormatInt(last, 10)).Nx().Build())
	}
	set := 0
	for _, r := range s.c.c.DoMulti(ctx, cmds...) {
		err := r.Error()
		if valkey.IsValkeyNil(err) {
			continue
		}
		if err != nil {
			return set, fmt.Errorf("devicecache: restore seq: %w", err)
		}
		set++
	}
	return set, nil
}

// hashes reads the hashes of keys in one pipeline; a missing key reads as an empty map.
func (s *Syncer) hashes(ctx context.Context, keys []string) ([]map[string]string, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	cmds := make(valkey.Commands, len(keys))
	for i, k := range keys {
		cmds[i] = s.c.c.B().Hgetall().Key(k).Build()
	}
	out := make([]map[string]string, len(keys))
	for i, r := range s.c.c.DoMulti(ctx, cmds...) {
		m, err := r.AsStrMap()
		if err != nil {
			return nil, fmt.Errorf("devicecache: read hash: %w", err) // key left out, see putHash
		}
		out[i] = m
	}
	return out, nil
}
