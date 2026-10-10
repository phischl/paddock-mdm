package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// MaxImmediateDenials is how many distinct addresses per window get an event at their first denial (plan M7a
// decision 20); further addresses are counted and summarized at the window's end.
const MaxImmediateDenials = 20

// IPDenials aggregates the denials of the IP allow list per address and window so that a scan never floods the
// audit log: at most MaxImmediateDenials immediate events, one summary per address with further denials and one for
// the addresses beyond the cap — 2 × MaxImmediateDenials + 1 events per window and replica.
type IPDenials struct {
	runner *ActionRunner
	window time.Duration
	now    func() time.Time
	record func(ctx context.Context, spec ActionSpec) error

	mu       sync.Mutex
	start    time.Time // first denial of the current window; zero while none happened
	seen     map[netip.Addr]*denialCount
	others   int // denials of the addresses beyond the cap
	otherIPs map[netip.Addr]struct{}
	pending  []ActionSpec
	wake     chan struct{}
}

type denialCount struct {
	count       int
	first, last time.Time
}

// NewIPDenials creates the aggregator; now is the clock (time.Now in production).
func NewIPDenials(runner *ActionRunner, window time.Duration, now func() time.Time) *IPDenials {
	d := &IPDenials{runner: runner, window: window, now: now, seen: map[netip.Addr]*denialCount{},
		otherIPs: map[netip.Addr]struct{}{}, wake: make(chan struct{}, 1)}
	d.record = d.recordEvent
	return d
}

// Note counts one denial of ip at at; no I/O, never blocks on the recorder.
func (d *IPDenials) Note(ip netip.Addr, at time.Time) {
	d.mu.Lock()
	d.roll(at)
	if d.start.IsZero() {
		d.start = at
	}
	switch c, ok := d.seen[ip]; {
	case ok:
		c.count++
		c.last = at
	case len(d.seen) < MaxImmediateDenials:
		d.seen[ip] = &denialCount{count: 1, first: at, last: at}
		d.pending = append(d.pending, d.spec(ip, map[string]any{"ip": ip.String(), "count": 1, "aggregated": false}))
	default:
		d.others++
		d.otherIPs[ip] = struct{}{}
	}
	d.mu.Unlock()
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// roll closes the window when at is past its end: the summaries of the ended window are queued and the counters
// reset. Callers hold d.mu.
func (d *IPDenials) roll(at time.Time) {
	if d.start.IsZero() || at.Before(d.start.Add(d.window)) {
		return
	}
	for ip, c := range d.seen {
		if c.count > 1 {
			d.pending = append(d.pending, d.spec(ip, map[string]any{
				"ip": ip.String(), "count": c.count, "aggregated": true,
				"first_at": c.first.UTC().Format(time.RFC3339), "last_at": c.last.UTC().Format(time.RFC3339),
			}))
		}
	}
	if d.others > 0 {
		d.pending = append(d.pending, d.spec(netip.Addr{}, map[string]any{
			"ip": "", "count": d.others, "distinct_ips": len(d.otherIPs), "aggregated": true,
		}))
	}
	d.seen = map[netip.Addr]*denialCount{}
	d.otherIPs = map[netip.Addr]struct{}{}
	d.others = 0
	d.start = time.Time{}
}

// spec is the denied event of ip (an invalid ip: the summary of the addresses beyond the cap) in the current window;
// the immediate and the summary event of one address and window share the correlation ID.
func (d *IPDenials) spec(ip netip.Addr, params map[string]any) ActionSpec {
	params["window_seconds"] = int(d.window.Seconds())
	suffix := "others"
	actor := &audit.Actor{Type: audit.ActorAnonymous}
	if ip.IsValid() {
		suffix, actor.IP = ip.String(), ip.String()
	}
	return ActionSpec{
		Code: audit.CodePlatformIPAllowlistDenied, Actor: actor, Params: params,
		CorrelationID: fmt.Sprintf("ipal-%d-%s", d.start.Unix(), suffix),
	}
}

// Run records the queued events until ctx ends; the window is closed by the clock even without further denials.
// At the end the open window is summarized so that nothing counted is lost.
func (d *IPDenials) Run(ctx context.Context) error {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			d.mu.Lock()
			d.roll(d.start.Add(d.window))
			d.mu.Unlock()
			d.flush(context.WithoutCancel(ctx))
			return nil
		case <-d.wake:
		case <-t.C:
		}
		d.flush(ctx)
	}
}

// flush closes an ended window and records every queued event.
func (d *IPDenials) flush(ctx context.Context) {
	d.mu.Lock()
	d.roll(d.now())
	specs := d.pending
	d.pending = nil
	d.mu.Unlock()
	for _, s := range specs {
		if err := d.record(ctx, s); err != nil {
			slog.ErrorContext(ctx, "recording an ip allow list denial failed", "error", err, "ip", s.Actor.IP)
		}
	}
}

// recordEvent records one denied event in the platform pseudo-organization under a system principal.
func (d *IPDenials) recordEvent(ctx context.Context, spec ActionSpec) error {
	ctx = principal.With(ctx, principal.Principal{Kind: principal.KindSystem, OrganizationID: uuid.Nil})
	err := d.runner.RunTxRefusal(ctx, ScopePlatform, spec, problem.IPNotAllowed,
		func(context.Context, *pgstore.Queries, Recorder) error { return nil })
	if errors.Is(err, problem.IPNotAllowed) {
		return nil
	}
	return err
}
