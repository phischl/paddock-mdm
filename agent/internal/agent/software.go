package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"slices"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/health"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

const (
	// softwareResend is how often the check-in repeats unchanged software items (plan M13a decision 27).
	softwareResend = 24 * time.Hour
	// maxCheckinHealth bounds the health of a check-in: the server refuses a check-in body above 96 KiB (PDK-700), and
	// the rest of the request is small.
	maxCheckinHealth = 96<<10 - 4<<10
)

// serverReachable reports whether the last successful check-in is at most reconcile.RemovalWindow old (plan M13a
// decision 25); the software reconciler removes packages only then. A check-in in the future means the clock stepped
// back since: its age is unknown, so it does not count (design contract 8).
func (a *Agent) serverReachable() bool {
	info, err := os.Stat(a.d.Layout.LastCheckin())
	if err != nil {
		return false
	}
	age := a.d.Now().Sub(info.ModTime())
	return age >= 0 && age <= reconcile.RemovalWindow
}

// refreshSoftware puts the status of the software reconciler's last pass into the health report.
func (a *Agent) refreshSoftware() {
	if a.d.Software == nil {
		return
	}
	if st := a.d.Software.Status(); st != nil {
		a.d.Health.Update(func(r *health.Report) { r.Software = st })
	}
}

// softwareCheckin reduces the software status of r to what the check-in sends: the digest always, the items when
// the server has other ones or got them more than softwareResend ago, cut to fit the check-in (PDK-700).
func (a *Agent) softwareCheckin(ctx context.Context, r *health.Report) {
	a.softwarePending = ""
	sw := r.Software
	if sw == nil || sw.Items == nil {
		return
	}
	r.Software = &protocol.SoftwareHealth{Digest: sw.Digest}
	if sw.Digest == a.lastSoftwareDigest && a.d.Now().Sub(a.lastSoftwareFullAt) < softwareResend {
		return
	}
	empty := []protocol.SoftwareItem{}
	r.Software.Items = &empty
	base, err := json.Marshal(r)
	if err != nil {
		r.Software.Items = nil
		return
	}
	items, truncated, ok := fitSoftware(*sw.Items, maxCheckinHealth-len(base))
	if !ok {
		// The hard rule of PDK-700: the software report never makes the server refuse the check-in. Without items
		// the server keeps what it has.
		slog.WarnContext(ctx, "software report too large even with failed items only; sending the digest alone", "items", len(*sw.Items))
		r.Software.Items = nil
		return
	}
	r.Software.Items, r.Software.Truncated = &items, truncated
	a.softwarePending = sw.Digest
}

// softwareDelivered records the items of a successful check-in as the server's.
func (a *Agent) softwareDelivered() {
	if a.softwarePending != "" {
		a.lastSoftwareDigest, a.lastSoftwareFullAt = a.softwarePending, a.d.Now()
	}
	a.softwarePending = ""
}

// fitSoftware drops items until at most protocol.MaxSoftwareItems remain and their JSON fits room bytes: applied
// items (installed, held, absent) first, then pending ones, never a failed one (architect decision 2026-11-02,
// PDK-700). ok is false when the failed items alone do not fit.
func fitSoftware(items []protocol.SoftwareItem, room int) (out []protocol.SoftwareItem, truncated, ok bool) {
	sizes := make([]int, len(items))
	total := 0
	for i, it := range items {
		b, _ := json.Marshal(it)
		sizes[i] = len(b) + 1
		total += sizes[i]
	}
	dropped := make([]bool, len(items))
	count := len(items)
	for _, droppable := range []func(string) bool{
		func(s string) bool { return s != protocol.SoftwareStatePending && s != protocol.SoftwareStateFailed },
		func(s string) bool { return s == protocol.SoftwareStatePending },
	} {
		for i := len(items) - 1; i >= 0 && (total > room || count > protocol.MaxSoftwareItems); i-- {
			if !dropped[i] && droppable(items[i].State) {
				dropped[i], total, count, truncated = true, total-sizes[i], count-1, true
			}
		}
	}
	if total > room || count > protocol.MaxSoftwareItems {
		return nil, truncated, false
	}
	out = make([]protocol.SoftwareItem, 0, count)
	for i, it := range items {
		if !dropped[i] {
			out = append(out, it)
		}
	}
	return slices.Clip(out), truncated, true
}
