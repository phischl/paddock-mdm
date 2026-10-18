package acceptance

import (
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/semver"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

type overview struct {
	GeneratedAt string `json:"generated_at"`
	Encryption  struct {
		Encrypted    int `json:"encrypted"`
		NotEncrypted int `json:"not_encrypted"`
	} `json:"encryption"`
	Updates struct {
		SecurityOverdue int           `json:"security_overdue"`
		Agent           overviewAgent `json:"agent"`
	} `json:"updates"`
	Devices struct {
		Total, Active, Pending, Quarantined, Online, Silent int
		NoRecentContact                                     int `json:"no_recent_contact"`
		SilentCritical                                      int `json:"silent_critical"`
		PresumedLost                                        int `json:"presumed_lost"`
		NeverContacted                                      int `json:"never_contacted"`
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

// overviewAgent is updates.agent (plan M7c decision 26, amendment 2026-10-12).
type overviewAgent struct {
	CurrentVersion  *string `json:"current_version"`
	OnCurrent       int     `json:"on_current"`
	Outdated        int     `json:"outdated"`
	Ahead           int     `json:"ahead"`
	Unknown         int     `json:"unknown"`
	LatestPublished *string `json:"latest_published"`
	Rollout         *struct {
		Version              string
		Wave, Waves, Percent int
	} `json:"rollout"`
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
	// The worker records the check-in asynchronously; until it has, the device is "never contacted" in one read and
	// may not be in the next, so the overview and the list totals would be compared across that change.
	hostname := waitDevice(t, alice, d.DeviceID, time.Minute, func(s deviceState) bool { return s.LastContactAt != nil }).Hostname
	o, _ := getOverview(t, alice)
	size := url.Values{"page_size": {"10"}}
	if want := listCount(t, alice, "/api/v1/devices", url.Values{"state": {"pending", "active", "quarantined"}, "page_size": {"10"}}); o.Devices.Total != want {
		t.Fatalf("devices.total %d, device list %d", o.Devices.Total, want)
	}
	if want := listCount(t, alice, "/api/v1/devices", url.Values{"state": {"active"}, "page_size": {"10"}}); o.Devices.Active != want {
		t.Fatalf("devices.active %d, device list %d", o.Devices.Active, want)
	}
	for contact, got := range map[string]int{"ok": o.Devices.Online, "unseen": o.Devices.NoRecentContact, "stale_warning": o.Devices.Silent, "stale_critical": o.Devices.SilentCritical,
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
	if sum := o.Devices.Online + o.Devices.NoRecentContact + o.Devices.Silent + o.Devices.SilentCritical + o.Devices.PresumedLost +
		o.Devices.NeverContacted; sum != o.Devices.Active {
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
	releases := agentReleases(t, root)
	expectCurrentAgentRelease(t, releases, o.Updates.Agent.CurrentVersion)
	expectLatestPublishedAndRollout(t, root, releases, o.Updates.Agent)
	if a := o.Updates.Agent; a.CurrentVersion != nil {
		if sum := a.OnCurrent + a.Outdated + a.Ahead + a.Unknown; sum != o.Devices.Active {
			t.Fatalf("agent buckets %d (on %d, outdated %d, ahead %d, unknown %d), active %d", sum, a.OnCurrent, a.Outdated, a.Ahead, a.Unknown, o.Devices.Active)
		}
	} else if a.OnCurrent != 0 || a.Outdated != 0 || a.Ahead != 0 {
		t.Fatalf("no current release, but agent buckets on %d, outdated %d, ahead %d", a.OnCurrent, a.Outdated, a.Ahead)
	}

	var worst time.Duration
	for range 5 {
		if _, took := getOverview(t, alice); took > worst {
			worst = took
		}
	}
	t.Logf("GET /api/v1/overview: slowest of 5 calls %s (plan M7c §12: 300 ms budget)", worst)
}

// agentRelease is one row of the platform release list.
type agentRelease struct {
	Version       string `json:"version"`
	Status        string `json:"status"`
	RolloutStatus string `json:"rollout_status"`
}

// agentReleases reads every agent release through the platform API.
func agentReleases(t *testing.T, root *env.Portal) []agentRelease {
	t.Helper()
	var all []agentRelease
	for page := 1; page <= 100; page++ {
		res := call(t, root, http.MethodGet, "/api/platform/v1/agent-releases?page_size=100&page="+strconv.Itoa(page), nil)
		expectStatus(t, res, http.StatusOK, "")
		var p struct {
			Items []agentRelease `json:"items"`
		}
		if err := res.JSON(&p); err != nil {
			t.Fatal(err)
		}
		all = append(all, p.Items...)
		if len(p.Items) < 100 {
			break
		}
	}
	return all
}

// expectCurrentAgentRelease (PDK-040): the agent release the overview names is one whose rollout completed, and there
// is one exactly when a rollout completed; a release that is only published is not current (plan M7c step 5,
// paddock_current_agent_version), so the overview shows "No agent rollout completed yet" for it.
func expectCurrentAgentRelease(t *testing.T, releases []agentRelease, current *string) {
	t.Helper()
	completed := map[string]bool{}
	for _, r := range releases {
		if r.RolloutStatus == "completed" {
			completed[r.Version] = true
		}
	}
	switch {
	case current == nil && len(completed) > 0:
		t.Fatalf("updates.agent.current_version is null, but %d rollouts completed", len(completed))
	case current != nil && !completed[*current]:
		t.Fatalf("updates.agent.current_version %q is not a release whose rollout completed", *current)
	}
}

// expectLatestPublishedAndRollout (PDK-051): latest_published is the newest published release of the platform list
// by SemVer precedence (null without one); rollout is the release whose rollout runs, with the wave, the number of
// waves and the percentage of its rollout, or null while none runs.
func expectLatestPublishedAndRollout(t *testing.T, root *env.Portal, releases []agentRelease, agent overviewAgent) {
	t.Helper()
	newest, running := "", ""
	for _, r := range releases {
		if r.Status == "published" && (newest == "" || semver.Compare(r.Version, newest) > 0) {
			newest = r.Version
		}
		if r.RolloutStatus == "running" {
			running = r.Version
		}
	}
	switch {
	case newest == "" && agent.LatestPublished != nil:
		t.Fatalf("updates.agent.latest_published %q, but no release is published", *agent.LatestPublished)
	case newest != "" && (agent.LatestPublished == nil || semver.Compare(*agent.LatestPublished, newest) != 0):
		t.Fatalf("updates.agent.latest_published %v, want %s", agent.LatestPublished, newest)
	}
	if running == "" {
		if agent.Rollout != nil {
			t.Fatalf("updates.agent.rollout %+v, but no rollout runs", *agent.Rollout)
		}
		return
	}
	if agent.Rollout == nil || agent.Rollout.Version != running {
		t.Fatalf("updates.agent.rollout %+v, want the running rollout of %s", agent.Rollout, running)
	}
	res := call(t, root, http.MethodGet, "/api/platform/v1/agent-releases/"+url.PathEscape(running), nil)
	expectStatus(t, res, http.StatusOK, "")
	var detail struct {
		Rollout struct {
			Waves            []int `json:"waves"`
			CurrentWaveIndex int   `json:"current_wave_index"`
		} `json:"rollout"`
	}
	if err := res.JSON(&detail); err != nil {
		t.Fatal(err)
	}
	ro := detail.Rollout
	if ro.CurrentWaveIndex >= len(ro.Waves) || agent.Rollout.Wave != ro.CurrentWaveIndex+1 || agent.Rollout.Waves != len(ro.Waves) ||
		agent.Rollout.Percent != ro.Waves[ro.CurrentWaveIndex] {
		t.Fatalf("updates.agent.rollout %+v, rollout of %s has waves %v at index %d", *agent.Rollout, running, ro.Waves, ro.CurrentWaveIndex)
	}
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

// TestOverviewNoRecentContact (PDK-295, plan M8x decisions 58 and 62): an active device whose last check-in is more
// than 15 minutes old, below the staleness thresholds, has the contact state unseen: the contact filter unseen lists
// it, ok does not, and the overview counts it in no_recent_contact. A check-in makes it ok again.
func TestOverviewNoRecentContact(t *testing.T) {
	alice := login(t, env.Alice)
	d := activeDevice(t, alice, namedGroup(t, alice, "no recent contact"), "ov-unseen-"+uniqueSuffix())
	ctx := testContext(t, time.Minute)
	if _, _, err := d.Checkin(ctx); err != nil {
		t.Fatal(err)
	}
	hostname := waitDevice(t, alice, d.DeviceID, time.Minute, func(s deviceState) bool { return s.LastContactAt != nil }).Hostname
	contactOf := func() string {
		t.Helper()
		v, _ := getDeviceDetail(t, alice, d.DeviceID)["contact"].(string)
		return v
	}
	listed := func(contact string) int {
		t.Helper()
		return listCount(t, alice, "/api/v1/devices", url.Values{"q": {hostname}, "contact": {contact}, "page_size": {"10"}})
	}
	if c := contactOf(); c != "ok" || listed("ok") != 1 || listed("unseen") != 0 {
		t.Fatalf("after the check-in: contact %q, want ok", c)
	}
	db := ownerDB(t)
	for _, ago := range []string{"16 minutes", "14 minutes"} {
		if _, err := db.Exec(ctx, "UPDATE device_status SET last_contact_at = now() - $2::interval WHERE device_id = $1", d.DeviceID, ago); err != nil {
			t.Fatal(err)
		}
		want := map[string]string{"16 minutes": "unseen", "14 minutes": "ok"}[ago]
		if c := contactOf(); c != want || listed(want) != 1 {
			t.Fatalf("last contact %s ago: contact %q, want %s", ago, c, want)
		}
		if ago == "16 minutes" {
			if listed("ok") != 0 {
				t.Fatalf("last contact 16 minutes ago: listed as ok")
			}
			o, _ := getOverview(t, alice)
			if o.Devices.NoRecentContact < 1 {
				t.Fatalf("overview no_recent_contact %d, want at least this device", o.Devices.NoRecentContact)
			}
		}
	}
}
