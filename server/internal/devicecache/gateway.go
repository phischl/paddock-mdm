package devicecache

import (
	"context"
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

// NextSeq increments seq:<device> and returns the new value (architecture §6.4).
func (c *Cache) NextSeq(ctx context.Context, device uuid.UUID) (int64, error) {
	n, err := c.c.Do(ctx, c.c.B().Incr().Key(seqKey(device)).Build()).AsInt64()
	if err != nil {
		return 0, fmt.Errorf("devicecache: seq: %w", err)
	}
	return n, nil
}

// RestoreSeq sets seq:<device> to last unless it exists (the worker rebuilds an emptied Valkey from
// device_status.last_seq, so clone detection survives a cache loss).
func (c *Cache) RestoreSeq(ctx context.Context, device uuid.UUID, last int64) error {
	err := c.c.Do(ctx, c.c.B().Set().Key(seqKey(device)).Value(strconv.FormatInt(last, 10)).Nx().Build()).Error()
	if err != nil && !valkey.IsValkeyNil(err) {
		return fmt.Errorf("devicecache: restore seq: %w", err)
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
