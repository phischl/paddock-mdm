package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/health"
	"github.com/phischl/paddock-mdm/agent/internal/testgw"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

func setSoftware(a *Agent, digest string, items ...protocol.SoftwareItem) {
	if items == nil {
		items = []protocol.SoftwareItem{}
	}
	a.d.Health.Update(func(r *health.Report) { r.Software = &protocol.SoftwareHealth{Digest: digest, Items: &items} })
}

// sentSoftware is health.software of the last check-in, with the raw items ("" when absent).
func sentSoftware(t *testing.T, g *testgw.Gateway) (protocol.SoftwareHealth, string) {
	t.Helper()
	g.Mu.Lock()
	defer g.Mu.Unlock()
	var raw struct {
		Software *struct {
			Items json.RawMessage `json:"items"`
		} `json:"software"`
	}
	var h health.Report
	req := g.Checkins[len(g.Checkins)-1].Req
	if err := json.Unmarshal(req.Health, &raw); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(req.Health, &h); err != nil || h.Software == nil || raw.Software == nil {
		t.Fatalf("no software in the check-in health: %s", req.Health)
	}
	return *h.Software, string(raw.Software.Items)
}

// TestCheckinSoftwareItems (plan M13a decision 27, PDK-701): the digest goes with every check-in, the items with the
// first, after a change, after a failed delivery and once a day; no items is an explicit empty list.
func TestCheckinSoftwareItems(t *testing.T) {
	g := testgw.New(t)
	a := newAgent(t, g)
	now := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	a.d.Now = func() time.Time { return now }
	ctx := context.Background()
	a.Cycle(ctx)
	if strings.Contains(string(g.Checkins[0].Req.Health), `"software"`) {
		t.Fatalf("software reported before the reconciler ran: %s", g.Checkins[0].Req.Health)
	}
	setSoftware(a, "d0")
	a.Cycle(ctx)
	if sw, items := sentSoftware(t, g); sw.Digest != "d0" || items != "[]" {
		t.Fatalf("no items: digest %q items %q", sw.Digest, items)
	}
	item := protocol.SoftwareItem{CatalogEntryID: "e1", Package: "nano", Intent: "required", State: "installed", Version: "7.2"}
	setSoftware(a, "d1", item)
	for i, want := range []bool{true, false} {
		a.Cycle(ctx)
		if sw, items := sentSoftware(t, g); sw.Digest != "d1" || (items != "") != want {
			t.Fatalf("check-in %d: digest %q items %q", i, sw.Digest, items)
		}
	}
	setSoftware(a, "d2", item)
	g.Mu.Lock()
	g.CheckinFail = http.StatusServiceUnavailable
	g.Mu.Unlock()
	a.Cycle(ctx)
	g.Mu.Lock()
	g.CheckinFail = 0
	g.Mu.Unlock()
	for i, want := range []bool{true, false} {
		a.Cycle(ctx)
		if sw, items := sentSoftware(t, g); sw.Digest != "d2" || (items != "") != want {
			t.Fatalf("after a failed check-in %d: digest %q items %q", i, sw.Digest, items)
		}
	}
	now = now.Add(softwareResend)
	a.Cycle(ctx)
	if _, items := sentSoftware(t, g); items == "" {
		t.Fatal("no items after 24 h")
	}
}

// TestCheckinSoftwareFits (PDK-700): 200 failing items with long errors are all sent within the check-in limit;
// beyond the item limit applied items are dropped and the report marked truncated; failed items are never dropped,
// and a report that cannot fit is left out rather than refused.
func TestCheckinSoftwareFits(t *testing.T) {
	g := testgw.New(t)
	a := newAgent(t, g)
	ctx := context.Background()
	item := func(i int, state string) protocol.SoftwareItem {
		return protocol.SoftwareItem{CatalogEntryID: fmt.Sprintf("0b9e2c4e-4b7a-4f43-9a51-%012d", i), Package: fmt.Sprintf("package-%03d", i),
			Intent: "required", State: state, Version: "1:2.34.5-1ubuntu1", Reason: protocol.SoftwareWouldRemoveDependents,
			Error: strings.Repeat("e", 120)}
	}
	var failed []protocol.SoftwareItem
	for i := range 200 {
		failed = append(failed, item(i, protocol.SoftwareStateFailed))
	}
	setSoftware(a, "f", failed...)
	a.Cycle(ctx)
	body, _ := json.Marshal(g.Checkins[0].Req)
	if sw, _ := sentSoftware(t, g); len(*sw.Items) != 200 || sw.Truncated || len(body) > 96<<10 {
		t.Fatalf("%d items, truncated %v, body %d bytes", len(*sw.Items), sw.Truncated, len(body))
	}

	mixed := append([]protocol.SoftwareItem{}, failed[:150]...)
	for i := 150; i < 260; i++ {
		mixed = append(mixed, item(i, protocol.SoftwareStateInstalled))
	}
	mixed = append(mixed, item(300, protocol.SoftwareStatePending))
	setSoftware(a, "m", mixed...)
	a.Cycle(ctx)
	sw, _ := sentSoftware(t, g)
	counts := map[string]int{}
	for _, it := range *sw.Items {
		counts[it.State]++
	}
	if !sw.Truncated || len(*sw.Items) != protocol.MaxSoftwareItems || counts[protocol.SoftwareStateFailed] != 150 || counts[protocol.SoftwareStatePending] != 1 {
		t.Fatalf("truncated %v, counts %v", sw.Truncated, counts)
	}

	huge := append([]protocol.SoftwareItem{}, failed...)
	for i := range huge {
		huge[i].Error = strings.Repeat("ü", 120)
		huge[i].Package = strings.Repeat("p", 120) + fmt.Sprint(i)
		huge[i].Version = strings.Repeat("9", 128)
	}
	setSoftware(a, "h", huge...)
	n := len(g.Checkins)
	a.Cycle(ctx)
	if len(g.Checkins) != n+1 {
		t.Fatal("the check-in was not sent")
	}
	if sw, items := sentSoftware(t, g); sw.Digest != "h" || items != "" {
		t.Fatalf("an unfittable report must leave the items out: %q", items)
	}
	if a.failures != 0 {
		t.Fatal("the check-in was refused")
	}
}

func TestServerReachable(t *testing.T) {
	g := testgw.New(t)
	a := newAgent(t, g)
	if a.serverReachable() {
		t.Fatal("reachable without a check-in")
	}
	a.Cycle(context.Background())
	info, err := os.Stat(a.d.Layout.LastCheckin())
	if err != nil {
		t.Fatal(err)
	}
	a.d.Now = func() time.Time { return info.ModTime().Add(14 * time.Minute) }
	if !a.serverReachable() {
		t.Fatal("unreachable 14 minutes after a check-in")
	}
	a.d.Now = func() time.Time { return info.ModTime().Add(16 * time.Minute) }
	if a.serverReachable() {
		t.Fatal("reachable 16 minutes after a check-in")
	}
	a.d.Now = func() time.Time { return info.ModTime().Add(-time.Hour) }
	if a.serverReachable() {
		t.Fatal("reachable after the clock stepped back behind the check-in")
	}
}
