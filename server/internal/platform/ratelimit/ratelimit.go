// Package ratelimit is the application rate limiter of the api and the gateway (ADR 0051 decision 3, plan M12h
// §3.3): per-minute windows in Valkey under rl:<class>:<key>:<window>, counted with INCR and EXPIRE only, so the
// roles need no scripting and the Valkey ACL can grant the rl:* prefix with core commands.
package ratelimit

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/valkey-io/valkey-go"
)

// Class is a route class with its own limit and key space.
type Class string

// The classes of plan M12h decision 7.
const (
	Auth           Class = "auth"            // /api/auth/* per client address
	AdminRead      Class = "admin_read"      // admin API reads per principal
	AdminWrite     Class = "admin_write"     // admin API writes per principal
	PlatformUpload Class = "platform_upload" // agent artifact and package uploads per principal
	BundlesAPT     Class = "bundles_apt"     // the bundles host's /apt/* per client address (M13c)
	Device         Class = "device"          // device API per client address
	DeviceKey      Class = "device_key"      // device API per device key
)

// Default limits per minute (plan M12h §6.1); the device limits are the gateway's existing ones (plan M2a §6.2).
const (
	DefaultAuth           = 20
	DefaultAdminRead      = 600
	DefaultAdminWrite     = 120
	DefaultPlatformUpload = 10
	DefaultBundlesAPT     = 60
	DefaultDevice         = 300
	DefaultDeviceKey      = 30
	// DefaultV6Prefix is the prefix length an IPv6 client address is keyed by: one /64 is one subscriber, and every
	// address inside it is the same client to a limiter.
	DefaultV6Prefix = 64
)

// Window is the length of one counting window.
const Window = 60 * time.Second

// keyTTL keeps a window readable while the following window weighs it.
const keyTTL = 2 * Window

// Prefix is the Valkey key prefix of every window; the Valkey ACL grants the roles that limit exactly this prefix.
const Prefix = "rl:"

var (
	metricRejected = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "paddock_ratelimit_rejected_total",
		Help: "Requests refused with 429 by the application rate limiter, by class.",
	}, []string{"class"})
	metricErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "paddock_ratelimit_errors_total",
		Help: "Rate limit decisions the store could not answer; the api let the request through, the gateway answered 503.",
	})
)

// Store counts hits of a window. Hit increments cur, keeps it for ttl and returns its new count together with the
// count of prev (0 when prev does not exist).
type Store interface {
	Hit(ctx context.Context, cur, prev string, ttl time.Duration) (count, previous int64, err error)
}

// Limiter decides whether a request of a class and key is within the class's limit.
type Limiter struct {
	store  Store
	clock  func() time.Time
	limits map[Class]int
}

// New returns a limiter over store with the limits per minute of each class; a class without a limit, or with 0, is
// not limited.
func New(store Store, clock func() time.Time, limits map[Class]int) *Limiter {
	if clock == nil {
		clock = time.Now
	}
	l := make(map[Class]int, len(limits))
	for c, n := range limits {
		l[c] = n
	}
	return &Limiter{store: store, clock: clock, limits: l}
}

// Limit is the limit per minute of class; 0 means off.
func (l *Limiter) Limit(class Class) int { return l.limits[class] }

// Allow counts one request of key in class. The admission is the gateway's existing estimate over two fixed windows:
// the current window's count plus the previous window's count weighted by the part of it that still lies within the
// last minute, which removes the double burst at a window edge that a plain fixed window allows. A refusal returns
// the time until the current window ends. A store error fails open: ok is true, err is set and
// paddock_ratelimit_errors_total counts it, so that a Valkey outage never locks administrators out.
func (l *Limiter) Allow(ctx context.Context, class Class, key string) (ok bool, retryAfter time.Duration, err error) {
	limit := l.limits[class]
	if limit <= 0 {
		return true, 0, nil
	}
	now := l.clock()
	window := now.Unix() / int64(Window/time.Second)
	base := Prefix + string(class) + ":" + key + ":"
	count, previous, err := l.store.Hit(ctx, base+strconv.FormatInt(window, 10), base+strconv.FormatInt(window-1, 10), keyTTL)
	if err != nil {
		metricErrors.Inc()
		return true, 0, fmt.Errorf("ratelimit: %s: %w", class, err)
	}
	seconds := int64(Window / time.Second)
	elapsed := float64(now.Unix()%seconds) / float64(seconds)
	if float64(previous)*(1-elapsed)+float64(count) <= float64(limit) {
		return true, 0, nil
	}
	metricRejected.WithLabelValues(string(class)).Inc()
	return false, time.Duration(seconds-now.Unix()%seconds) * time.Second, nil
}

// IPKey is the key of a client address: an IPv4 address (or an IPv4-mapped IPv6 address) as is, an IPv6 address as
// its prefix of v6Prefix bits. A value that is not an address is used unchanged.
func IPKey(addr string, v6Prefix int) string {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return addr
	}
	a = a.Unmap().WithZone("")
	if a.Is4() {
		return a.String()
	}
	p, err := a.Prefix(v6Prefix)
	if err != nil {
		return a.String()
	}
	return p.String()
}

// ValkeyStore is the Store over Valkey: INCR and EXPIRE of the current window and GET of the previous one, in one
// round trip.
type ValkeyStore struct{ c valkey.Client }

// NewValkeyStore wraps a Valkey client.
func NewValkeyStore(c valkey.Client) *ValkeyStore { return &ValkeyStore{c: c} }

// Hit implements Store.
func (s *ValkeyStore) Hit(ctx context.Context, cur, prev string, ttl time.Duration) (int64, int64, error) {
	res := s.c.DoMulti(ctx,
		s.c.B().Incr().Key(cur).Build(),
		s.c.B().Expire().Key(cur).Seconds(int64(ttl/time.Second)).Build(),
		s.c.B().Get().Key(prev).Build())
	count, err := res[0].AsInt64()
	if err != nil {
		return 0, 0, err
	}
	if err := res[1].Error(); err != nil {
		return 0, 0, err
	}
	previous, err := res[2].AsInt64()
	if err != nil && !valkey.IsValkeyNil(err) {
		return 0, 0, err
	}
	return count, previous, nil
}
