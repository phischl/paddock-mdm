package devicecache

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/valkey-io/valkey-go"
)

// NonceTTL is how long a nonce is remembered; it covers the ±300 s timestamp window twice.
const NonceTTL = 600 * time.Second

// UseNonce records nonce:<device>:<nonce> with SET NX EX 600 and reports whether it was unused.
func (c *Cache) UseNonce(ctx context.Context, device, nonce string) (bool, error) {
	err := c.c.Do(ctx, c.c.B().Set().Key("nonce:"+device+":"+nonce).Value("1").Nx().Ex(NonceTTL).Build()).Error()
	if valkey.IsValkeyNil(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("devicecache: nonce: %w", err)
	}
	return true, nil
}

func seqKey(device uuid.UUID) string { return "seq:" + device.String() }

// ErrSeqMissing reports that seq:<device> does not exist, so no sequence number can be issued until the worker has
// restored it from device_status.last_seq.
var ErrSeqMissing = errors.New("devicecache: sequence number not restored yet")

// nextSeqScript increments seq:<device> only if it exists: a plain INCR on an emptied Valkey would restart the counter
// at 1, far below device_status.last_seq, and hand out numbers the device already received. Restored values are never
// negative, so 0 is free to mean "missing".
var nextSeqScript = valkey.NewLuaScript(`
if redis.call('EXISTS', KEYS[1]) == 1 then
  return redis.call('INCR', KEYS[1])
end
return 0
`)

// NextSeq increments seq:<device> and returns the new value (architecture §6.4). It returns ErrSeqMissing while the
// counter has not been restored (PutDeviceKey restores it before the identity key becomes usable).
func (c *Cache) NextSeq(ctx context.Context, device uuid.UUID) (int64, error) {
	n, err := nextSeqScript.Exec(ctx, c.c, []string{seqKey(device)}, nil).AsInt64()
	if err != nil {
		return 0, fmt.Errorf("devicecache: seq: %w", err)
	}
	if n == 0 {
		return 0, ErrSeqMissing
	}
	return n, nil
}

// releaseSeqScript decrements seq:<device> only while it still holds the value given: a check-in of another holder of
// the identity (a clone) that drew a number meanwhile is never rewound.
var releaseSeqScript = valkey.NewLuaScript(`
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DECR', KEYS[1])
end
return -1
`)

// ReleaseSeq takes back seq, drawn by NextSeq for a check-in that failed before its response, so a number the
// device never received does not count as issued (architecture §6.4: the tolerance of one is for a lost response,
// not for failed check-ins). It reports whether seq was still the current value.
func (c *Cache) ReleaseSeq(ctx context.Context, device uuid.UUID, seq int64) (bool, error) {
	n, err := releaseSeqScript.Exec(ctx, c.c, []string{seqKey(device)}, []string{strconv.FormatInt(seq, 10)}).AsInt64()
	if err != nil {
		return false, fmt.Errorf("devicecache: release seq: %w", err)
	}
	return n >= 0, nil
}

// RestoreSeq sets seq:<device> to last (device_status.last_seq) only if it is missing (the worker rebuilds an emptied
// Valkey from PostgreSQL, so clone detection survives a cache loss). A live counter is never changed: last_seq is
// persisted asynchronously and can include a number the gateway released after an ambiguous heartbeat publish, or lag
// behind numbers the device already holds after a restore from a stale value, so raising a live counter from it can
// put the counter more than one ahead of the device and quarantine a healthy device as a clone (PDK-475). A counter
// restored from a stale last_seq therefore reissues numbers until it catches up, which weakens clone detection (RR-97).
func (c *Cache) RestoreSeq(ctx context.Context, device uuid.UUID, last int64) error {
	err := c.c.Do(ctx, c.c.B().Set().Key(seqKey(device)).Value(strconv.FormatInt(last, 10)).Nx().Build()).Error()
	if err != nil && !valkey.IsValkeyNil(err) {
		return fmt.Errorf("devicecache: restore seq: %w", err)
	}
	return nil
}

func deliveredKey(device uuid.UUID) string { return "sd:" + device.String() }

// LastDelivered reads sd:<device>, the highest sequence number a check-in response carried. It reports false when
// the key is missing; the caller then flags nothing (plan M2a amendment PDK-590, option a).
func (c *Cache) LastDelivered(ctx context.Context, device uuid.UUID) (int64, bool, error) {
	n, err := c.c.Do(ctx, c.c.B().Get().Key(deliveredKey(device)).Build()).AsInt64()
	if valkey.IsValkeyNil(err) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("devicecache: delivered seq: %w", err)
	}
	return n, true, nil
}

// markDeliveredScript raises sd:<device> and never lowers it: a slower request that delivered an older number must
// not undo a newer delivery.
var markDeliveredScript = valkey.NewLuaScript(`
local cur = redis.call('GET', KEYS[1])
if not cur or tonumber(cur) < tonumber(ARGV[1]) then
  redis.call('SET', KEYS[1], ARGV[1])
end
return 1
`)

// MarkDelivered raises sd:<device> to seq once a check-in response carries it. Clone detection compares against
// delivered numbers only, because a number drawn for a check-in that stalled and failed after the device's retry
// cannot be released and would otherwise count as issued (PDK-590). The key is never lowered and not restored after a
// cache loss: while the key is missing the gateway flags nothing, and the next delivery seeds it.
func (c *Cache) MarkDelivered(ctx context.Context, device uuid.UUID, seq int64) error {
	err := markDeliveredScript.Exec(ctx, c.c, []string{deliveredKey(device)}, []string{strconv.FormatInt(seq, 10)}).Error()
	if err != nil {
		return fmt.Errorf("devicecache: mark delivered seq: %w", err)
	}
	return nil
}

// BundlePointer is bp:<device>: the newest uploaded bundle of a device.
type BundlePointer struct {
	Version   int64
	SHA256    string // hex SHA-256 of the envelope object
	ObjectKey string
}

func bundleKey(device uuid.UUID) string { return "bp:" + device.String() }

// PutBundlePointer replaces bp:<device> unless the cached version is newer (out-of-order writers never move the
// pointer back).
func (c *Cache) PutBundlePointer(ctx context.Context, device uuid.UUID, p BundlePointer) error {
	cur, ok, err := c.BundlePointer(ctx, device)
	if err != nil {
		return err
	}
	if ok && cur.Version > p.Version {
		return nil
	}
	return c.putHash(ctx, bundleKey(device), time.Time{}, map[string]string{
		"version": strconv.FormatInt(p.Version, 10), "sha256": p.SHA256, "object_key": p.ObjectKey,
	})
}

// BundlePointer reads bp:<device>.
func (c *Cache) BundlePointer(ctx context.Context, device uuid.UUID) (BundlePointer, bool, error) {
	m, ok, err := c.getHash(ctx, bundleKey(device))
	if !ok || err != nil {
		return BundlePointer{}, ok, err
	}
	v, err := strconv.ParseInt(m["version"], 10, 64)
	if err != nil {
		return BundlePointer{}, false, fmt.Errorf("devicecache: corrupt bundle pointer: %w", err)
	}
	return BundlePointer{Version: v, SHA256: m["sha256"], ObjectKey: m["object_key"]}, true, nil
}

// Allow is a rate limiter over core commands only: a sliding window of one minute, estimated from the counters of
// the current and the previous minute, which behaves like a token bucket of limit tokens refilled per minute. It
// returns whether the request may proceed and, if not, how long to wait.
func (c *Cache) Allow(ctx context.Context, scope string, limit int, now time.Time) (bool, time.Duration, error) {
	minute := now.Unix() / 60
	cur := "rl:" + scope + ":" + strconv.FormatInt(minute, 10)
	prev := "rl:" + scope + ":" + strconv.FormatInt(minute-1, 10)
	res := c.c.DoMulti(ctx,
		c.c.B().Incr().Key(cur).Build(),
		c.c.B().Expire().Key(cur).Seconds(120).Build(),
		c.c.B().Get().Key(prev).Build())
	count, err := res[0].AsInt64()
	if err != nil {
		return false, 0, fmt.Errorf("devicecache: rate limit: %w", err)
	}
	previous, err := res[2].AsInt64()
	if err != nil && !valkey.IsValkeyNil(err) {
		return false, 0, fmt.Errorf("devicecache: rate limit: %w", err)
	}
	elapsed := float64(now.Unix()%60) / 60
	if float64(previous)*(1-elapsed)+float64(count) <= float64(limit) {
		return true, 0, nil
	}
	return false, time.Duration(60-now.Unix()%60) * time.Second, nil
}

// HeartbeatInterval coalesces device_status writes to one per device and interval (plan M2a decision 12).
const HeartbeatInterval = 60 * time.Second

func heartbeatKey(device uuid.UUID) string { return "hb:" + device.String() }

// ClaimHeartbeat sets hb:<device> with SET NX EX 60 and reports whether this heartbeat should be materialized.
func (c *Cache) ClaimHeartbeat(ctx context.Context, device uuid.UUID) (bool, error) {
	err := c.c.Do(ctx, c.c.B().Set().Key(heartbeatKey(device)).Value("1").Nx().Ex(HeartbeatInterval).Build()).Error()
	if valkey.IsValkeyNil(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("devicecache: heartbeat: %w", err)
	}
	return true, nil
}

// ReleaseHeartbeat deletes hb:<device> after a failed write, so the retried heartbeat is materialized.
func (c *Cache) ReleaseHeartbeat(ctx context.Context, device uuid.UUID) error {
	return c.c.Do(ctx, c.c.B().Del().Key(heartbeatKey(device)).Build()).Error()
}
