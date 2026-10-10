package app

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// denialHarness captures the events an IPDenials records with a controllable clock.
type denialHarness struct {
	d      *IPDenials
	now    time.Time
	events []ActionSpec
}

func newDenialHarness(window time.Duration) *denialHarness {
	h := &denialHarness{now: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)}
	h.d = NewIPDenials(nil, window, func() time.Time { return h.now })
	h.d.record = func(_ context.Context, spec ActionSpec) error {
		h.events = append(h.events, spec)
		return nil
	}
	return h
}

func (h *denialHarness) note(ip string) { h.d.Note(netip.MustParseAddr(ip), h.now) }

func (h *denialHarness) flush() []ActionSpec {
	h.events = nil
	h.d.flush(context.Background())
	return h.events
}

// TestIPDenialsAggregation: the first denial of an address is recorded at once, further ones are summarized at the
// window's end with the same correlation ID, and single denials get no summary (plan M7a decision 20).
func TestIPDenialsAggregation(t *testing.T) {
	h := newDenialHarness(10 * time.Minute)
	h.note("192.0.2.9")
	first := h.flush()
	if len(first) != 1 || first[0].Params["ip"] != "192.0.2.9" || first[0].Params["count"] != 1 ||
		first[0].Params["aggregated"] != false || first[0].Params["window_seconds"] != 600 || first[0].Actor.IP != "192.0.2.9" {
		t.Fatalf("first denial: %+v", first)
	}
	corr := first[0].CorrelationID
	if corr != fmt.Sprintf("ipal-%d-192.0.2.9", h.now.Unix()) {
		t.Fatalf("correlation %s", corr)
	}
	for range 20 {
		h.now = h.now.Add(time.Second)
		h.note("192.0.2.9")
	}
	h.note("192.0.2.10")
	if got := h.flush(); len(got) != 1 || got[0].Params["ip"] != "192.0.2.10" {
		t.Fatalf("within the window only the new address is recorded: %+v", got)
	}
	h.now = h.now.Add(5 * time.Minute)
	if got := h.flush(); len(got) != 0 {
		t.Fatalf("no summary before the window ends: %+v", got)
	}
	h.now = h.now.Add(6 * time.Minute)
	got := h.flush()
	if len(got) != 1 {
		t.Fatalf("summaries: %+v", got)
	}
	s := got[0]
	if s.Params["ip"] != "192.0.2.9" || s.Params["count"] != 21 || s.Params["aggregated"] != true || s.CorrelationID != corr ||
		s.Params["first_at"] != "2026-10-10T12:00:00Z" || s.Params["last_at"] != "2026-10-10T12:00:20Z" {
		t.Fatalf("summary: %+v", s)
	}
	h.note("192.0.2.9")
	if got := h.flush(); len(got) != 1 || got[0].CorrelationID == corr || got[0].Params["count"] != 1 {
		t.Fatalf("a new window records the address again with a new correlation: %+v", got)
	}
}

// TestIPDenialsCap: at most 20 addresses get an immediate event; the rest are counted into one summary.
func TestIPDenialsCap(t *testing.T) {
	h := newDenialHarness(time.Minute)
	for i := range 25 {
		h.note(fmt.Sprintf("198.51.100.%d", i+1))
	}
	h.note("198.51.100.25")
	h.note("198.51.100.21")
	if got := h.flush(); len(got) != MaxImmediateDenials {
		t.Fatalf("%d immediate events, want %d", len(got), MaxImmediateDenials)
	}
	h.now = h.now.Add(2 * time.Minute)
	got := h.flush()
	if len(got) != 1 {
		t.Fatalf("summary of the others: %+v", got)
	}
	s := got[0]
	if s.Params["ip"] != "" || s.Params["count"] != 7 || s.Params["distinct_ips"] != 5 || s.Params["aggregated"] != true ||
		s.Actor.IP != "" || s.CorrelationID != fmt.Sprintf("ipal-%d-others", h.now.Add(-2*time.Minute).Unix()) {
		t.Fatalf("others: %+v", s)
	}
}

// TestIPDenialsDistinctCap: a scan rotating far more addresses than MaxDistinctDenials remembers at most that many;
// every denial is still counted and the summary marks distinct_ips as a lower bound.
func TestIPDenialsDistinctCap(t *testing.T) {
	h := newDenialHarness(time.Minute)
	total := MaxImmediateDenials + MaxDistinctDenials + 500
	for i := range total {
		h.note(netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 14: byte(i >> 8), 15: byte(i)}).String())
	}
	h.flush()
	if n := len(h.d.otherIPs); n != MaxDistinctDenials {
		t.Fatalf("%d remembered addresses, want %d", n, MaxDistinctDenials)
	}
	h.now = h.now.Add(2 * time.Minute)
	got := h.flush()
	if len(got) != 1 {
		t.Fatalf("summary of the others: %d events", len(got))
	}
	p := got[0].Params
	if p["count"] != total-MaxImmediateDenials || p["distinct_ips"] != MaxDistinctDenials || p["distinct_ips_capped"] != true {
		t.Fatalf("capped summary: %+v", p)
	}
	h.note("2001:db8::1")
	h.note("2001:db8::2")
	h.now = h.now.Add(2 * time.Minute)
	h.flush()
	if h.d.capped || len(h.d.otherIPs) != 0 {
		t.Fatalf("a new window starts uncapped: capped %v, %d addresses", h.d.capped, len(h.d.otherIPs))
	}
}

// TestIPDenialsNoteNeverBlocks: Note returns at once however many denials are queued (the recorder may be down).
func TestIPDenialsNoteNeverBlocks(t *testing.T) {
	h := newDenialHarness(time.Minute)
	done := make(chan struct{})
	go func() {
		for i := range 10000 {
			h.note(fmt.Sprintf("203.0.113.%d", i%200))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Note blocked")
	}
}
