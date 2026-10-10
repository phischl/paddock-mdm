package acceptance

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

type overview struct {
	GeneratedAt string `json:"generated_at"`
	Encryption  struct {
		Encrypted    int `json:"encrypted"`
		NotEncrypted int `json:"not_encrypted"`
	} `json:"encryption"`
	Updates struct {
		SecurityOverdue int `json:"security_overdue"`
	} `json:"updates"`
	Devices struct {
		Total, Active, Pending, Quarantined, Online, Silent, SilentCritical, PresumedLost, NeverContacted int
	} `json:"devices"`
	Vulnerabilities struct {
		ByHighestSeverity struct{ Critical, High, Medium, Low, Unknown, None int } `json:"by_highest_severity"`
		CriticalHighCVEs  int                                                      `json:"critical_high_cves"`
		Top               []struct {
			CVE     string `json:"cve"`
			Devices int    `json:"devices"`
		} `json:"top"`
	} `json:"vulnerabilities"`
	Attention struct{ Conditions, Devices int } `json:"attention"`
}

func getOverview(t *testing.T, p *env.Portal) (overview, time.Duration) {
	t.Helper()
	start := time.Now()
	res := call(t, p, http.MethodGet, "/api/v1/overview", nil)
	took := time.Since(start)
	expectStatus(t, res, http.StatusOK, "")
	var o overview
	if err := res.JSON(&o); err != nil {
		t.Fatal(err)
	}
	return o, took
}

func listCount(t *testing.T, p *env.Portal, path string, q url.Values) int {
	t.Helper()
	res := call(t, p, http.MethodGet, path+"?"+q.Encode(), nil)
	expectStatus(t, res, http.StatusOK, "")
	var page struct {
		Total int `json:"total"`
	}
	if err := res.JSON(&page); err != nil {
		t.Fatal(err)
	}
	return page.Total
}

// TestOverviewGate (plan M7c step 5, AC1, AC17): GET /api/v1/overview answers the numbers of the caller's
// organization, each equal to the matching list's total, and every bucket partitions its population; a globex
// principal sees globex numbers only; platform admins are refused. The response time of the development seed is
// reported (plan M7c §12: above 300 ms p95 a materialized summary follows in M7d).
func TestOverviewGate(t *testing.T) {
	alice := login(t, env.Alice)
	group := namedGroup(t, alice, "overview gate")
	d := activeDevice(t, alice, group, "ov-gate-"+uniqueSuffix())
	ctx := testContext(t, time.Minute)
	if _, _, err := d.Checkin(ctx); err != nil {
		t.Fatal(err)
	}
	hostname := getDevice(t, alice, d.DeviceID).Hostname
	o, _ := getOverview(t, alice)
	size := url.Values{"page_size": {"10"}}
	if want := listCount(t, alice, "/api/v1/devices", url.Values{"state": {"pending", "active", "quarantined"}, "page_size": {"10"}}); o.Devices.Total != want {
		t.Fatalf("devices.total %d, device list %d", o.Devices.Total, want)
	}
	if want := listCount(t, alice, "/api/v1/devices", url.Values{"state": {"active"}, "page_size": {"10"}}); o.Devices.Active != want {
		t.Fatalf("devices.active %d, device list %d", o.Devices.Active, want)
	}
	for contact, got := range map[string]int{"ok": o.Devices.Online, "stale_warning": o.Devices.Silent, "stale_critical": o.Devices.SilentCritical,
		"presumed_lost": o.Devices.PresumedLost, "never": o.Devices.NeverContacted} {
		if want := listCount(t, alice, "/api/v1/devices", url.Values{"state": {"active"}, "contact": {contact}, "page_size": {"10"}}); got != want {
			t.Fatalf("devices.%s %d, device list %d", contact, got, want)
		}
	}
	// AC1 (plan M7c amendment 2026-10-10): the KPI cells link to these lists; their totals equal the numbers.
	for name, kpi := range map[string]struct {
		value int
		path  string
		query url.Values
	}{
		"encrypted":     {o.Encryption.Encrypted, "/api/v1/devices", url.Values{"state": {"active"}, "disk_state": {"compliant"}, "page_size": {"10"}}},
		"not encrypted": {o.Encryption.NotEncrypted, "/api/v1/devices", url.Values{"state": {"active"}, "disk_state": {"not_encrypted"}, "page_size": {"10"}}},
		"critical/high": {o.Vulnerabilities.CriticalHighCVEs, "/api/v1/vulnerabilities", url.Values{"severity": {"critical", "high"}, "page_size": {"10"}}},
		"overdue":       {o.Updates.SecurityOverdue, "/api/v1/devices", url.Values{"state": {"active"}, "security_updates": {"overdue"}, "page_size": {"10"}}},
	} {
		if want := listCount(t, alice, kpi.path, kpi.query); kpi.value != want {
			t.Fatalf("%s: overview %d, list %d", name, kpi.value, want)
		}
	}
	if sum := o.Devices.Online + o.Devices.Silent + o.Devices.SilentCritical + o.Devices.PresumedLost + o.Devices.NeverContacted; sum != o.Devices.Active {
		t.Fatalf("contact buckets %d, active %d", sum, o.Devices.Active)
	}
	b := o.Vulnerabilities.ByHighestSeverity
	if sum := b.Critical + b.High + b.Medium + b.Low + b.Unknown + b.None; sum != o.Devices.Active+o.Devices.Quarantined {
		t.Fatalf("severity buckets %d, active+quarantined %d", sum, o.Devices.Active+o.Devices.Quarantined)
	}
	if len(o.Vulnerabilities.Top) > 5 {
		t.Fatalf("top %d CVEs", len(o.Vulnerabilities.Top))
	}
	for _, c := range o.Vulnerabilities.Top {
		if want := listCount(t, alice, "/api/v1/vulnerabilities/"+c.CVE+"/devices", size); c.Devices != want {
			t.Fatalf("top %s devices %d, list %d", c.CVE, c.Devices, want)
		}
	}
	if want := listCount(t, alice, "/api/v1/attention", size); o.Attention.Conditions != want {
		t.Fatalf("attention.conditions %d, list %d", o.Attention.Conditions, want)
	}
	if want := listCount(t, alice, "/api/v1/attention/devices", size); o.Attention.Devices != want {
		t.Fatalf("attention.devices %d, grouped list %d", o.Attention.Devices, want)
	}
	if _, err := time.Parse(time.RFC3339Nano, o.GeneratedAt); err != nil {
		t.Fatalf("generated_at %q: %v", o.GeneratedAt, err)
	}

	carol := login(t, env.Carol)
	c, _ := getOverview(t, carol)
	if want := listCount(t, carol, "/api/v1/devices", url.Values{"state": {"pending", "active", "quarantined"}, "page_size": {"10"}}); c.Devices.Total != want {
		t.Fatalf("globex devices.total %d, device list %d", c.Devices.Total, want)
	}
	if res := call(t, carol, http.MethodGet, "/api/v1/devices?q="+url.QueryEscape(hostname), nil); listTotalOf(t, res) != 0 {
		t.Fatalf("carol sees the acme device %s", hostname)
	}
	root := login(t, env.PlatformAdmin)
	expectStatus(t, call(t, root, http.MethodGet, "/api/v1/overview", nil), http.StatusForbidden, "no_organization")

	var worst time.Duration
	for range 5 {
		if _, took := getOverview(t, alice); took > worst {
			worst = took
		}
	}
	t.Logf("GET /api/v1/overview: slowest of 5 calls %s (plan M7c §12: 300 ms budget)", worst)
}

func listTotalOf(t *testing.T, res env.Response) int {
	t.Helper()
	expectStatus(t, res, http.StatusOK, "")
	var page struct {
		Total int `json:"total"`
	}
	if err := res.JSON(&page); err != nil {
		t.Fatal(err)
	}
	return page.Total
}
