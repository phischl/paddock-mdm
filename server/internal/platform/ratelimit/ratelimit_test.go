package ratelimit_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/phischl/paddock-mdm/server/internal/platform/ratelimit"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/valkeytest"
)

// memStore counts in memory and records the keys it saw.
type memStore struct {
	counts map[string]int64
	keys   []string
	err    error
}

func (m *memStore) Hit(_ context.Context, cur, prev string, _ time.Duration) (int64, int64, error) {
	if m.err != nil {
		return 0, 0, m.err
	}
	if m.counts == nil {
		m.counts = map[string]int64{}
	}
	m.keys = append(m.keys, cur)
	m.counts[cur]++
	return m.counts[cur], m.counts[prev], nil
}

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

// windowStart is the start of a counting window.
var windowStart = time.Unix(1_800_000_000-1_800_000_000%60, 0)

func allowN(t *testing.T, l *ratelimit.Limiter, class ratelimit.Class, key string, n int) {
	t.Helper()
	for i := range n {
		if ok, _, err := l.Allow(context.Background(), class, key); !ok || err != nil {
			t.Fatalf("request %d of %d refused (err %v)", i+1, n, err)
		}
	}
}

func TestWindowEdges(t *testing.T) {
	c := &clock{now: windowStart.Add(10 * time.Second)}
	l := ratelimit.New(&memStore{}, c.Now, map[ratelimit.Class]int{ratelimit.Auth: 20})

	allowN(t, l, ratelimit.Auth, "198.51.100.1", 20)
	ok, retry, err := l.Allow(context.Background(), ratelimit.Auth, "198.51.100.1")
	if ok || err != nil || retry != 50*time.Second {
		t.Fatalf("21st request: ok %v retry %v err %v, want refused with Retry-After 50s", ok, retry, err)
	}
	allowN(t, l, ratelimit.Auth, "198.51.100.2", 1)

	// At the start of the next window the full previous window still weighs: a burst at the edge is refused.
	c.now = windowStart.Add(60 * time.Second)
	if ok, retry, _ := l.Allow(context.Background(), ratelimit.Auth, "198.51.100.1"); ok || retry != 60*time.Second {
		t.Fatalf("first request after the edge: ok %v retry %v, want refused with 60s", ok, retry)
	}
	// Three quarters in, the previous window weighs a quarter (21 × 0.25 = 5.25) and the refused request above counts
	// in the current one: 13 more fit, the 14th does not.
	c.now = windowStart.Add(105 * time.Second)
	allowN(t, l, ratelimit.Auth, "198.51.100.1", 13)
	if ok, _, _ := l.Allow(context.Background(), ratelimit.Auth, "198.51.100.1"); ok {
		t.Fatal("request above the weighted limit allowed")
	}
	// Once neither the current nor the previous window holds requests, the full limit is available again.
	c.now = windowStart.Add(240 * time.Second)
	allowN(t, l, ratelimit.Auth, "198.51.100.1", 20)
}

func TestOffClassAndKeyLayout(t *testing.T) {
	s := &memStore{}
	l := ratelimit.New(s, func() time.Time { return windowStart }, map[ratelimit.Class]int{ratelimit.AdminRead: 600, ratelimit.AdminWrite: 0})
	allowN(t, l, ratelimit.AdminWrite, "session:x", 1000)
	allowN(t, l, ratelimit.Auth, "198.51.100.1", 1000)
	if len(s.keys) != 0 {
		t.Fatalf("an unlimited class reached the store: %v", s.keys)
	}
	allowN(t, l, ratelimit.AdminRead, "token:abc", 1)
	if got := s.keys[0]; got != "rl:admin_read:token:abc:30000000" {
		t.Fatalf("key %q", got)
	}
}

func TestStoreErrorFailsOpen(t *testing.T) {
	l := ratelimit.New(&memStore{err: errors.New("connection refused")}, nil, map[ratelimit.Class]int{ratelimit.Auth: 1})
	before := testutil.ToFloat64(ratelimit.MetricErrors())
	for range 3 {
		ok, _, err := l.Allow(context.Background(), ratelimit.Auth, "198.51.100.1")
		if !ok || err == nil {
			t.Fatalf("ok %v err %v, want allowed with the error reported", ok, err)
		}
	}
	if got := testutil.ToFloat64(ratelimit.MetricErrors()) - before; got != 3 {
		t.Fatalf("paddock_ratelimit_errors_total grew by %v, want 3", got)
	}
}

func TestRejectedMetric(t *testing.T) {
	l := ratelimit.New(&memStore{}, func() time.Time { return windowStart }, map[ratelimit.Class]int{ratelimit.PlatformUpload: 1})
	before := testutil.ToFloat64(ratelimit.MetricRejected(ratelimit.PlatformUpload))
	allowN(t, l, ratelimit.PlatformUpload, "token:x", 1)
	if ok, _, _ := l.Allow(context.Background(), ratelimit.PlatformUpload, "token:x"); ok {
		t.Fatal("second upload allowed")
	}
	if got := testutil.ToFloat64(ratelimit.MetricRejected(ratelimit.PlatformUpload)) - before; got != 1 {
		t.Fatalf("paddock_ratelimit_rejected_total{class=platform_upload} grew by %v, want 1", got)
	}
}

func TestIPKey(t *testing.T) {
	for _, c := range []struct {
		addr   string
		prefix int
		want   string
	}{
		{"198.51.100.7", 64, "198.51.100.7"},
		{"::ffff:198.51.100.7", 64, "198.51.100.7"},
		{"2001:db8:1:2:aaaa::1", 64, "2001:db8:1:2::/64"},
		{"2001:db8:1:2:bbbb::9", 64, "2001:db8:1:2::/64"},
		{"2001:db8:1:2:bbbb::9", 128, "2001:db8:1:2:bbbb::9/128"},
		{"2001:db8:1:2:bbbb::9", 48, "2001:db8:1::/48"},
		{"fe80::1%eth0", 64, "fe80::/64"},
		{"not-an-address", 64, "not-an-address"},
	} {
		if got := ratelimit.IPKey(c.addr, c.prefix); got != c.want {
			t.Errorf("IPKey(%q, %d) = %q, want %q", c.addr, c.prefix, got, c.want)
		}
	}
	// Two addresses of one /64 share a budget.
	l := ratelimit.New(&memStore{}, func() time.Time { return windowStart }, map[ratelimit.Class]int{ratelimit.Device: 1})
	allowN(t, l, ratelimit.Device, ratelimit.IPKey("2001:db8:1:2::1", 64), 1)
	if ok, _, _ := l.Allow(context.Background(), ratelimit.Device, ratelimit.IPKey("2001:db8:1:2::2", 64)); ok {
		t.Fatal("second address of the same /64 has its own budget")
	}
}

func TestValkeyStore(t *testing.T) {
	vc := valkeytest.Start(t).Client(t)
	c := &clock{now: windowStart.Add(30 * time.Second)}
	l := ratelimit.New(ratelimit.NewValkeyStore(vc), c.Now, map[ratelimit.Class]int{ratelimit.DeviceKey: 3})
	allowN(t, l, ratelimit.DeviceKey, "k1", 3)
	if ok, retry, err := l.Allow(context.Background(), ratelimit.DeviceKey, "k1"); ok || err != nil || retry != 30*time.Second {
		t.Fatalf("4th: ok %v retry %v err %v", ok, retry, err)
	}
	allowN(t, l, ratelimit.DeviceKey, "k2", 1)
	key := "rl:device_key:k1:" + "30000000"
	ttl, err := vc.Do(context.Background(), vc.B().Ttl().Key(key).Build()).AsInt64()
	if err != nil || ttl <= 60 || ttl > 120 {
		t.Fatalf("TTL of %s: %d %v, want within (60, 120]", key, ttl, err)
	}
	c.now = windowStart.Add(135 * time.Second)
	allowN(t, l, ratelimit.DeviceKey, "k1", 3)
}
