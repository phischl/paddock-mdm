package admin

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/ipallowlist"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Metrics of the IP allow list (plan M7a decision 23).
var (
	metricIPAllowlistEntries = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "paddock_ip_allowlist_entries", Help: "Entries of the IP allow list of the administrative surfaces.",
	})
	metricIPAllowlistEnabled = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "paddock_ip_allowlist_enabled", Help: "1 while the IP allow list has at least one entry.",
	})
	metricIPAllowlistBypass = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "paddock_ip_allowlist_bypass", Help: "1 while PADDOCK_IP_ALLOWLIST_BYPASS disables the IP allow list on this api (break-glass).",
	})
	metricIPAllowlistDenied = promauto.NewCounter(prometheus.CounterOpts{
		Name: "paddock_ip_allowlist_denied_total", Help: "Requests to the admin surface refused by the IP allow list.",
	})
	metricIPAllowlistReloadErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "paddock_ip_allowlist_reload_errors_total", Help: "Failed reloads of the IP allow list from PostgreSQL.",
	})
	metricIPAllowlistLastReload = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "paddock_ip_allowlist_last_reload_timestamp_seconds", Help: "Unix time of the last successful reload of the IP allow list.",
	})
)

// Reload timing of the guard (plan M7a decision 18).
const (
	ipGuardRetry   = 5 * time.Second  // until the first load succeeds
	ipGuardPoll    = 2 * time.Second  // version checks
	ipGuardFull    = 60 * time.Second // unconditional reloads
	ipGuardBypassL = 10 * time.Minute // bypass reminders in the log
)

// IPGuard enforces the application allow list on every request of the admin surface (plan M7a decision 17). Every
// api replica keeps the set in memory and reloads it when the shared version changes, and periodically.
type IPGuard struct {
	load    func(context.Context) ([]netip.Prefix, error)
	version app.Version    // nil: periodic reloads only
	denials *app.IPDenials // nil: denials are not audited
	bypass  bool
	set     atomic.Pointer[ipallowlist.Set]
	ready   atomic.Bool
}

// NewIPGuard creates a guard that allows everything until the first load; Ready reports the first load (or the
// bypass). bypass is PADDOCK_IP_ALLOWLIST_BYPASS (decision 22).
func NewIPGuard(load func(context.Context) ([]netip.Prefix, error), version app.Version, denials *app.IPDenials, bypass bool) *IPGuard {
	g := &IPGuard{load: load, version: version, denials: denials, bypass: bypass}
	empty := ipallowlist.NewSet(nil)
	g.set.Store(&empty)
	if bypass {
		metricIPAllowlistBypass.Set(1)
		g.ready.Store(true)
	}
	return g
}

// Ready is true after the first successful load, or with the bypass.
func (g *IPGuard) Ready() bool { return g.ready.Load() }

// Reload reads the list synchronously (used after a write in this process); a failure keeps the last set.
func (g *IPGuard) Reload(ctx context.Context) error {
	prefixes, err := g.load(ctx)
	if err != nil {
		metricIPAllowlistReloadErrors.Inc()
		return fmt.Errorf("load ip allow list: %w", err)
	}
	s := ipallowlist.NewSet(prefixes)
	g.set.Store(&s)
	g.ready.Store(true)
	metricIPAllowlistEntries.Set(float64(s.Len()))
	metricIPAllowlistEnabled.Set(boolGauge(s.Enabled()))
	metricIPAllowlistLastReload.Set(float64(time.Now().Unix()))
	return nil
}

func boolGauge(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// Run loads the list until the first success, then follows the version every 2 s and reloads every 60 s anyway;
// it returns when ctx ends.
func (g *IPGuard) Run(ctx context.Context) error {
	if g.bypass {
		slog.WarnContext(ctx, "ip allow list bypassed by PADDOCK_IP_ALLOWLIST_BYPASS")
	}
	for {
		err := g.Reload(ctx)
		if err == nil {
			break
		}
		slog.WarnContext(ctx, "ip allow list not loaded; retrying", "error", err, "retry", ipGuardRetry)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(ipGuardRetry):
		}
	}
	var last int64
	if g.version != nil {
		if v, err := g.version.Get(ctx); err == nil {
			last = v
		}
	}
	poll := time.NewTicker(ipGuardPoll)
	full := time.NewTicker(ipGuardFull)
	remind := time.NewTicker(ipGuardBypassL)
	defer poll.Stop()
	defer full.Stop()
	defer remind.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-poll.C:
			if g.version == nil {
				continue
			}
			v, err := g.version.Get(ctx)
			if err != nil || v == last {
				continue
			}
			if err := g.Reload(ctx); err != nil {
				slog.WarnContext(ctx, "ip allow list reload failed; keeping the last set", "error", err)
				continue
			}
			last = v
		case <-full.C:
			if err := g.Reload(ctx); err != nil {
				slog.WarnContext(ctx, "ip allow list reload failed; keeping the last set", "error", err)
			}
		case <-remind.C:
			if g.bypass {
				slog.WarnContext(ctx, "ip allow list bypassed by PADDOCK_IP_ALLOWLIST_BYPASS")
			}
		}
	}
}

// Middleware refuses every request from an address outside the list: 403 ip_not_allowed as problem details under
// /api/, a plain 403 elsewhere. The response reveals nothing about the list.
func (g *IPGuard) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, ok := httpx.ClientAddr(r)
		if g.allows(ip, ok) {
			next.ServeHTTP(w, r)
			return
		}
		metricIPAllowlistDenied.Inc()
		if g.denials != nil && ok {
			g.denials.Note(ip, time.Now())
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			httpx.WriteProblem(w, r, problem.IPNotAllowed)
			return
		}
		h := w.Header()
		h.Set("Content-Type", "text/plain; charset=utf-8")
		h.Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "403 Forbidden\n")
	})
}

func (g *IPGuard) allows(ip netip.Addr, ok bool) bool {
	if g.bypass {
		return true
	}
	set := g.set.Load()
	return !set.Enabled() || (ok && set.Allows(ip))
}
