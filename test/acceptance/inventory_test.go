package acceptance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/test/acceptance/devicesim"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// TestInventoryF0FleetNotPublic is gate F0 of plan M5a (AC2): from outside, Fleet's UI, admin API and file carving
// answer 404 under fleet.<domain>, while the device endpoints of osquery and fleetd reach Fleet; a production
// deployment publishes no Fleet port, MySQL and Redis are on an internal network; paddock-worker keeps Fleet's data
// minimization settings (plan M5a decision 2).
func TestInventoryF0FleetNotPublic(t *testing.T) {
	ctx := testContext(t, 3*time.Minute)
	client, err := env.NewHTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	status := func(method, path string) int {
		t.Helper()
		res, err := env.Call(ctx, client, method, stack.FleetURL()+path, map[string]any{}, false)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		return res.Status
	}
	t.Run("not public", func(t *testing.T) {
		for _, c := range []struct{ method, path string }{
			{http.MethodGet, "/"},
			{http.MethodGet, "/login"},
			{http.MethodGet, "/dashboard"},
			{http.MethodGet, "/api/latest/fleet/version"},
			{http.MethodGet, "/api/v1/fleet/hosts"},
			{http.MethodPatch, "/api/latest/fleet/config"},
			{http.MethodPost, "/api/v1/fleet/login"},
			{http.MethodPost, "/api/v1/setup"},
			{http.MethodGet, "/healthz"},
			{http.MethodPost, "/api/v1/osquery/carve/begin"},
			{http.MethodPost, "/api/osquery/carve/block"},
		} {
			if got := status(c.method, c.path); got != http.StatusNotFound {
				t.Errorf("%s %s: HTTP %d, want 404", c.method, c.path, got)
			}
		}
	})
	t.Run("device paths", func(t *testing.T) {
		// An unknown enroll secret or node key is refused by Fleet itself (401), not by the proxy.
		for _, path := range []string{"/api/v1/osquery/enroll", "/api/osquery/enroll", "/api/v1/osquery/config",
			"/api/fleet/orbit/enroll", "/api/fleet/orbit/config"} {
			if got := status(http.MethodPost, path); got != http.StatusUnauthorized {
				t.Errorf("POST %s: HTTP %d, want 401 from Fleet", path, got)
			}
		}
		if got := status(http.MethodHead, "/api/fleet/orbit/ping"); got != http.StatusOK {
			t.Errorf("HEAD /api/fleet/orbit/ping: HTTP %d, want 200", got)
		}
	})
	t.Run("production compose", func(t *testing.T) {
		out, err := stack.ComposeProduction(ctx, nil, "config", "--format", "json")
		if err != nil {
			t.Fatal(err)
		}
		var cfg struct {
			Services map[string]struct {
				Networks map[string]any `json:"networks"`
				Ports    []any          `json:"ports"`
			} `json:"services"`
			Networks map[string]struct {
				Internal bool `json:"internal"`
			} `json:"networks"`
		}
		if err := json.Unmarshal([]byte(out), &cfg); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"fleet", "fleet-mysql", "fleet-redis"} {
			if svc, ok := cfg.Services[name]; !ok || len(svc.Ports) != 0 {
				t.Errorf("%s: present %v, ports %v", name, ok, svc.Ports)
			}
		}
		for _, name := range []string{"fleet-mysql", "fleet-redis"} {
			nets := cfg.Services[name].Networks
			if _, on := nets["fleet"]; len(nets) != 1 || !on {
				t.Errorf("%s on networks %v, want fleet only", name, nets)
			}
		}
		if !cfg.Networks["fleet"].Internal {
			t.Error("network fleet is not internal")
		}
	})
	t.Run("settings", func(t *testing.T) {
		dir, err := stack.SecretsDir()
		if err != nil {
			t.Fatal(err)
		}
		token, err := os.ReadFile(filepath.Join(dir, "fleet_api_token"))
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, stack.FleetAdminURL()+"/api/latest/fleet/config", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var cfg struct {
			ServerSettings map[string]any `json:"server_settings"`
			Features       struct {
				EnableHostUsers      bool               `json:"enable_host_users"`
				DetailQueryOverrides map[string]*string `json:"detail_query_overrides"`
			} `json:"features"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
			t.Fatalf("HTTP %d: %v", resp.StatusCode, err)
		}
		for key, want := range map[string]any{"enable_analytics": false, "live_query_disabled": true, "scripts_disabled": true} {
			if cfg.ServerSettings[key] != want {
				t.Errorf("server_settings.%s = %v, want %v", key, cfg.ServerSettings[key], want)
			}
		}
		if cfg.Features.EnableHostUsers {
			t.Error("Fleet collects host users")
		}
		if q, ok := cfg.Features.DetailQueryOverrides["software_deb_last_opened_at"]; !ok || q != nil {
			t.Errorf("last-use times of packages are collected: %v", cfg.Features.DetailQueryOverrides)
		}
	})
}

// inventoryPage is one page of an inventory list of the admin API.
type inventoryPage struct {
	Items       []map[string]any `json:"items"`
	Page        int              `json:"page"`
	PageSize    int              `json:"page_size"`
	Total       int              `json:"total"`
	TotalCapped bool             `json:"total_capped"`
	Sort        string           `json:"sort"`
}

func listInventory(t *testing.T, p *env.Portal, path string) inventoryPage {
	t.Helper()
	res := call(t, p, http.MethodGet, path, nil)
	expectStatus(t, res, http.StatusOK, "")
	var page inventoryPage
	if err := res.JSON(&page); err != nil {
		t.Fatal(err)
	}
	return page
}

// field returns the values of one field of every item.
func (p inventoryPage) field(name string) []string {
	out := make([]string, len(p.Items))
	for i, it := range p.Items {
		out[i] = fmt.Sprint(it[name])
	}
	return out
}

// Packages that Fleet (free, this version) matched to CVEs on the Ubuntu 24.04 test VM (recorded in
// server/internal/adapters/fleet/testdata/get_software_versions.json).
var (
	acmeVulnerable   = [2]string{"apport", "2.28.3-0ubuntu0.1"}
	acmeCVE          = "CVE-2022-28653"
	globexVulnerable = [2]string{"cpio", "2.15+dfsg-1ubuntu2.1"}
	globexCVE        = "CVE-2023-7216"
)

// TestInventoryF3SoftwareAndVulnerabilities is gate F3 of plan M5a (AC1, AC2): a host of acme and one of globex
// enroll in Fleet through its public device endpoints and report their packages; within 10 minutes the portal's API
// lists each device's packages and matched CVEs, per device and organization-wide, following the list contract, and
// acme never sees globex's inventory (nor the other way round). Fleet free reports no CVSS score or severity: the
// findings are "unknown".
func TestInventoryF3SoftwareAndVulnerabilities(t *testing.T) {
	waitFleetVulnerabilityData(t, acmeCVE, globexCVE)
	alice, carol := login(t, env.Alice), login(t, env.Carol)
	suffix := uniqueSuffix()
	acmeDevice := activeDevice(t, alice, "", "inv-f3-acme-"+suffix)
	globexDevice := activeDevice(t, carol, "", "inv-f3-globex-"+suffix)
	acmePackage, globexPackage := [2]string{"paddock-f3-acme-" + suffix, "1.0-1"}, [2]string{"paddock-f3-globex-" + suffix, "2.0-1"}
	hosts := []*devicesim.FleetHost{
		enrollFleetHost(t, acmeDevice.HardwareUUID(), "inv-f3-acme-"+suffix, [][2]string{acmeVulnerable, acmePackage}),
		enrollFleetHost(t, globexDevice.HardwareUUID(), "inv-f3-globex-"+suffix, [][2]string{globexVulnerable, globexPackage}),
	}
	start := time.Now()
	for _, h := range hosts {
		if err := h.WaitAnswered(testContext(t, 2*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}

	acmeFindings := "/api/v1/devices/" + acmeDevice.DeviceID + "/vulnerabilities"
	globexFindings := "/api/v1/devices/" + globexDevice.DeviceID + "/vulnerabilities"
	var triggered time.Time
	var triggerErr error
	for deadline := start.Add(10 * time.Minute); ; time.Sleep(10 * time.Second) {
		// A run matches only the software Fleet had stored when it started, and Fleet refuses a trigger while a run is
		// pending: trigger again until both devices' findings are in instead of relying on one run.
		if time.Since(triggered) >= fleetRetrigger {
			if triggerErr = triggerFleetVulnerabilities(t); triggerErr != nil {
				t.Log(triggerErr)
			}
			triggered = time.Now()
		}
		a, g := listInventory(t, alice, acmeFindings), listInventory(t, carol, globexFindings)
		if slices.Contains(a.field("cve"), acmeCVE) && slices.Contains(g.field("cve"), globexCVE) {
			t.Logf("inventory and vulnerabilities in the portal after %s", time.Since(start).Round(time.Second))
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no findings within 10 minutes: acme %v, globex %v; software acme %v, globex %v; last trigger error: %v; "+
				"errors of Fleet's vulnerability job: %s", a.field("cve"), g.field("cve"),
				listInventory(t, alice, "/api/v1/devices/"+acmeDevice.DeviceID+"/software").field("name"),
				listInventory(t, carol, "/api/v1/devices/"+globexDevice.DeviceID+"/software").field("name"),
				triggerErr, fleetVulnerabilityErrors(t, start))
		}
		for _, h := range hosts { // keep the hosts online and answering
			if _, err := h.Answer(testContext(t, time.Minute)); err != nil {
				t.Fatal(err)
			}
		}
	}

	t.Run("per device", func(t *testing.T) {
		sw := listInventory(t, alice, "/api/v1/devices/"+acmeDevice.DeviceID+"/software?sort=-name&page_size=10")
		if sw.Total != 2 || sw.Sort != "-name" || sw.PageSize != 10 || sw.Page != 1 ||
			!slices.Equal(sw.field("name"), []string{acmePackage[0], acmeVulnerable[0]}) || sw.Items[0]["version"] != acmePackage[1] ||
			sw.Items[0]["source"] != "deb_packages" {
			t.Errorf("acme device software %+v", sw)
		}
		if sw := listInventory(t, alice, "/api/v1/devices/"+acmeDevice.DeviceID+"/software?q=apport"); sw.Total != 1 {
			t.Errorf("software search %+v", sw)
		}
		f := listInventory(t, alice, acmeFindings+"?q="+acmeCVE)
		if f.Total != 1 || f.Items[0]["software_name"] != acmeVulnerable[0] || f.Items[0]["software_version"] != acmeVulnerable[1] ||
			f.Items[0]["severity"] != "unknown" || f.Items[0]["cvss_score"] != nil || f.Items[0]["first_seen_at"] == nil {
			t.Errorf("acme finding %+v", f)
		}
		if f := listInventory(t, alice, acmeFindings+"?severity=unknown&q="+acmeCVE); f.Total != 1 {
			t.Errorf("severity unknown %+v", f)
		}
		if f := listInventory(t, alice, acmeFindings+"?severity=critical&severity=high"); f.Total != 0 {
			t.Errorf("critical or high without scores %+v", f)
		}
	})

	t.Run("organization-wide", func(t *testing.T) {
		sw := listInventory(t, alice, "/api/v1/software?q=paddock-f3-")
		if names := sw.field("name"); slices.Contains(names, globexPackage[0]) || !slices.Contains(names, acmePackage[0]) {
			t.Errorf("acme software %v", names)
		}
		sw = listInventory(t, alice, "/api/v1/software?has_vulnerabilities=true&q="+acmeVulnerable[0])
		if !slices.Contains(sw.field("version"), acmeVulnerable[1]) {
			t.Errorf("acme vulnerable software %+v", sw)
		}
		v := listInventory(t, alice, "/api/v1/vulnerabilities?q="+acmeCVE)
		if v.Total != 1 || v.Items[0]["severity"] != "unknown" || v.Items[0]["device_count"].(float64) < 1 {
			t.Errorf("acme vulnerabilities %+v", v)
		}
		d := listInventory(t, alice, "/api/v1/vulnerabilities/"+acmeCVE+"/devices?q=inv-f3-acme-"+suffix)
		if d.Total != 1 || d.Items[0]["device_id"] != acmeDevice.DeviceID || d.Items[0]["software_name"] != acmeVulnerable[0] {
			t.Errorf("devices with %s: %+v", acmeCVE, d)
		}
		res := call(t, alice, http.MethodGet, "/api/v1/vulnerabilities/summary", nil)
		expectStatus(t, res, http.StatusOK, "")
		var s struct {
			CriticalHigh int `json:"critical_high_devices"`
			Unknown      int `json:"unknown_severity_devices"`
			Affected     int `json:"affected_devices"`
		}
		if err := res.JSON(&s); err != nil || s.Unknown < 1 || s.Affected < s.Unknown {
			t.Errorf("summary %+v, %v", s, err)
		}
	})

	t.Run("isolation", func(t *testing.T) {
		for _, c := range []struct {
			viewer        *env.Portal
			foreignDevice string
			foreign       []string // values the viewer must never see
		}{
			{alice, globexDevice.DeviceID, []string{globexDevice.DeviceID, globexPackage[0], "inv-f3-globex-" + suffix}},
			{carol, acmeDevice.DeviceID, []string{acmeDevice.DeviceID, acmePackage[0], "inv-f3-acme-" + suffix}},
		} {
			for _, path := range []string{"/software", "/vulnerabilities"} {
				res := call(t, c.viewer, http.MethodGet, "/api/v1/devices/"+c.foreignDevice+path, nil)
				expectStatus(t, res, http.StatusNotFound, "not_found")
			}
			for _, path := range []string{"/api/v1/software?q=paddock-f3-&page_size=100", "/api/v1/vulnerabilities?page_size=100",
				"/api/v1/vulnerabilities/" + acmeCVE + "/devices?page_size=100", "/api/v1/vulnerabilities/" + globexCVE + "/devices?page_size=100"} {
				res := call(t, c.viewer, http.MethodGet, path, nil)
				if res.Status != http.StatusOK && res.Status != http.StatusNotFound {
					t.Errorf("GET %s: HTTP %d", path, res.Status)
				}
				if leaked := containsAny(res.Body, c.foreign); leaked != "" {
					t.Errorf("GET %s shows the other organization's %s: %s", path, leaked, res.Body)
				}
			}
		}
	})

	t.Run("list contract", func(t *testing.T) {
		for _, path := range []string{"/api/v1/devices/" + acmeDevice.DeviceID + "/software", acmeFindings, "/api/v1/software",
			"/api/v1/vulnerabilities", "/api/v1/vulnerabilities/" + acmeCVE + "/devices"} {
			if p := listInventory(t, alice, path+"?page_size=10&page=1"); p.PageSize != 10 || p.Page != 1 || p.Sort == "" || p.Items == nil {
				t.Errorf("GET %s: %+v", path, p)
			}
			expectStatus(t, call(t, alice, http.MethodGet, path+"?page_size=7", nil), http.StatusBadRequest, "invalid_request")
			expectStatus(t, call(t, alice, http.MethodGet, path+"?sort=no_such_field", nil), http.StatusBadRequest, "invalid_request")
			expectStatus(t, call(t, alice, http.MethodGet, path+"?page=401&page_size=25", nil), http.StatusBadRequest, "page_out_of_range")
		}
	})
}

// agentBinaryCode is the audit code of the agent binary policy (plan M5a amendment 2026-11-16, A3).
const agentBinaryCode = "device.tamper_agent_binary_changed"

// publishAgentBinary publishes a release without rollout whose amd64 artifact is a fresh binary, and returns the
// binary's SHA-256: from the next inventory round the agent binary policy accepts it.
func publishAgentBinary(t *testing.T, root *env.Portal) string {
	t.Helper()
	v := gateVersion()
	bin := []byte("agent binary policy gate " + v)
	expectStatus(t, call(t, root, http.MethodPost, "/api/platform/v1/agent-releases", map[string]string{"version": v}), http.StatusCreated, "")
	expectStatus(t, uploadArtifact(t, root, v, bin, signBinary(t, bin, v)), http.StatusOK, "")
	expectStatus(t, call(t, root, http.MethodPost, "/api/platform/v1/agent-releases/"+v+"/publish", nil), http.StatusOK, "")
	sum := sha256.Sum256(bin)
	return hex.EncodeToString(sum[:])
}

// TestInventoryAgentBinaryPolicy is the gate of plan M5a amendment 2026-11-16, part A (PDK-1122b): three simulated
// hosts mapped to acme devices answer Fleet's policies as osquery would for the paddockd they run.
//   - changed runs a binary of no published release: the org admin sees exactly one
//     device.tamper_agent_binary_changed in the device's audit log and a tamper finding; further rounds add none.
//   - genuine runs a published binary: every policy passes, no event.
//   - updated switches to the binary of a release published during the gate (a regular update): its evaluations of
//     the previous definition fail but predate the worker's apply, so no event; the new definition passes.
//
// After the second publish the gate waits until Fleet sent the new definition, every host evaluated it 2 minutes
// later and two more sync rounds ran; then changed still has exactly one event and its result is still marked.
func TestInventoryAgentBinaryPolicy(t *testing.T) {
	root, alice := login(t, env.PlatformAdmin), login(t, env.Alice)
	suffix := uniqueSuffix()
	published := publishAgentBinary(t, root)
	start := time.Now()
	devices := map[string]*devicesim.Device{}
	hosts := map[string]*devicesim.FleetHost{}
	for _, name := range []string{"changed", "genuine", "updated"} {
		hostname := "inv-bin-" + name + "-" + suffix
		devices[name] = activeDevice(t, alice, "", hostname)
		hosts[name] = enrollFleetHost(t, devices[name].HardwareUUID(), hostname, nil)
		hosts[name].AgentBinarySHA256 = published
	}
	unknown := sha256.Sum256([]byte("a rebuilt paddockd " + suffix))
	hosts["changed"].AgentBinarySHA256 = hex.EncodeToString(unknown[:])

	answer := func() {
		for _, h := range hosts {
			if _, err := h.Answer(testContext(t, time.Minute)); err != nil {
				t.Fatal(err)
			}
		}
	}
	events := func(device string) int {
		all, err := alice.AuditEventsSince(testContext(t, time.Minute), agentBinaryCode, start.Add(-time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, e := range all {
			if e.Target != nil && e.Target.ID == device {
				n++
			}
		}
		return n
	}
	// The worker applies the policy at most one round (60 s on the development stack) after the publish; the host
	// evaluates every 30 s; only evaluations 2 minutes after the apply count. Releases other gates publish restart that
	// wait, hence the margin.
	for deadline := time.Now().Add(10 * time.Minute); events(devices["changed"].DeviceID) == 0; time.Sleep(10 * time.Second) {
		if time.Now().After(deadline) {
			t.Fatalf("no %s for the device with an unknown binary within 10 minutes", agentBinaryCode)
		}
		answer()
	}
	t.Logf("%s after %s", agentBinaryCode, time.Since(start).Round(time.Second))

	// Phase 2 waits on observed conditions only (plan M5a amendment 2026-11-16, review round 1, A11). The publish
	// makes Fleet reset every host's binary policy result; a worker round that reads the changed host before it answers
	// again exercises A7, which this gate does not assert. A7's regression test is
	// TestInventoryRoundAgentBinaryUnansweredAfterPublish.
	newHash := publishAgentBinary(t, root)
	hosts["updated"].AgentBinarySHA256 = newHash
	db := ownerDB(t)
	ids := []string{}
	for _, d := range devices {
		ids = append(ids, d.DeviceID)
	}
	deadline := time.Now().Add(10 * time.Minute)
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("not within 10 minutes of the second publish: %s", what)
			}
			answer()
			time.Sleep(10 * time.Second)
		}
	}
	var bound time.Time
	waitFor("Fleet's agent binary policy lists the new release", func() bool {
		var ok bool
		bound, ok = hosts["updated"].BinaryPolicyListedAt(newHash)
		return ok
	})
	waitFor("every gate host evaluated the new definition and updated passes it", func() bool {
		var evaluated int
		var passing bool
		err := db.QueryRow(testContext(t, time.Minute), `SELECT
			(SELECT count(*) FROM device_inventory_ref WHERE device_id::text = ANY($1::text[]) AND policy_updated_at >= $2),
			coalesce((SELECT passing FROM inventory_policy_result WHERE device_id = $3 AND policy_key = 'paddock_agent_binary_known'), false)`,
			ids, bound.Add(2*time.Minute), devices["updated"].DeviceID).Scan(&evaluated, &passing)
		if err != nil {
			t.Fatal(err)
		}
		return evaluated == len(ids) && passing
	})
	synced := func() map[string]time.Time {
		rows, err := db.Query(testContext(t, time.Minute), "SELECT device_id::text, synced_at FROM device_inventory_ref WHERE device_id::text = ANY($1::text[])", ids)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]time.Time{}
		for rows.Next() {
			var id string
			var at time.Time
			if err := rows.Scan(&id, &at); err != nil {
				t.Fatal(err)
			}
			out[id] = at
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	last, rounds := synced(), map[string]int{}
	waitFor("two further sync rounds of every gate device", func() bool {
		done := true
		for id, at := range synced() {
			if at.After(last[id]) {
				last[id] = at
				rounds[id]++
			}
			done = done && rounds[id] >= 2
		}
		return done && len(rounds) == len(ids)
	})
	for name, want := range map[string]int{"changed": 1, "genuine": 0, "updated": 0} {
		if n := events(devices[name].DeviceID); n != want {
			t.Errorf("%s: %d %s events, want %d", name, n, agentBinaryCode, want)
		}
	}
	f := tamperFindingOf(t, alice, devices["changed"].DeviceID, 1)
	if f.Code != agentBinaryCode || f.Subject != "" {
		t.Errorf("tamper finding %+v", f)
	}
	for _, name := range []string{"genuine", "updated"} {
		q := url.Values{"device_id": {devices[name].DeviceID}, "kind": {"tamper"}}
		if got := listFindings(t, alice, q); len(got) != 0 {
			t.Errorf("%s: tamper findings %+v", name, got)
		}
	}
	var alerted bool
	if err := db.QueryRow(testContext(t, time.Minute), `SELECT alerted_at IS NOT NULL FROM inventory_policy_result
		WHERE device_id = $1 AND policy_key = 'paddock_agent_binary_known'`, devices["changed"].DeviceID).Scan(&alerted); err != nil || !alerted {
		t.Errorf("changed: the binary policy result is not marked as reported (%v, %v)", alerted, err)
	}
}

// agentNotRunningCode is the audit code of the mutual watch (plan M5a decision 8).
const agentNotRunningCode = "device.tamper_agent_not_running"

// TestInventoryAgentAbsentWhileCheckingIn is the gate of plan M5a amendment 2026-11-16 b (PDK-1122c, AC-C1, AC-C5):
// three acme devices keep checking in while their simulated hosts answer Fleet.
//   - impostor answers paddock_agent_running as failing throughout: once the failure spans 15 minutes of Fleet's
//     evaluations, the org admin sees exactly one device.tamper_agent_not_running with last_contact_at later than
//     failing_since, and a tamper finding.
//   - restart fails briefly and passes again (an agent restart): failing_since is cleared, no event.
//   - genuine passes every policy: no event.
//
// The 15 minutes are seeded by moving the start of impostor's failure back instead of waited for; the evaluation
// count is proven by TestReportAgentNotRunningWhileCheckingIn. carol (globex) sees none of the events.
func TestInventoryAgentAbsentWhileCheckingIn(t *testing.T) {
	alice := login(t, env.Alice)
	suffix := uniqueSuffix()
	start := time.Now()
	devices := map[string]*devicesim.Device{}
	hosts := map[string]*devicesim.FleetHost{}
	for _, name := range []string{"impostor", "restart", "genuine"} {
		hostname := "inv-abs-" + name + "-" + suffix
		devices[name] = activeDevice(t, alice, "", hostname)
		hosts[name] = enrollFleetHost(t, devices[name].HardwareUUID(), hostname, nil)
	}
	hosts["impostor"].AgentNotRunning, hosts["restart"].AgentNotRunning = true, true
	db := ownerDB(t)
	// Steps 2 to 5 share one failure bound (plan M5a amendment 2026-11-16, review round 1, A11): the worker syncs every
	// 60 s and Fleet asks for policies every 30 s on the development stack.
	deadline := time.Now().Add(10 * time.Minute)
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		for {
			for _, d := range devices {
				if _, _, err := d.Checkin(testContext(t, time.Minute)); err != nil {
					t.Fatal(err)
				}
			}
			for _, h := range hosts {
				if _, err := h.Answer(testContext(t, time.Minute)); err != nil {
					t.Fatal(err)
				}
			}
			if cond() {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("not within 10 minutes: %s", what)
			}
			time.Sleep(10 * time.Second)
		}
	}
	passingCleared := func(name string) bool {
		var n int
		if err := db.QueryRow(testContext(t, time.Minute), `SELECT count(*) FROM inventory_policy_result
			WHERE device_id = $1 AND policy_key = 'paddock_agent_running' AND passing AND failing_since IS NULL`,
			devices[name].DeviceID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}
	failingWithStart := func(name string) bool {
		var n int
		if err := db.QueryRow(testContext(t, time.Minute), `SELECT count(*) FROM inventory_policy_result
			WHERE device_id = $1 AND policy_key = 'paddock_agent_running' AND NOT passing AND failing_since IS NOT NULL`,
			devices[name].DeviceID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}
	waitFor("impostor and restart fail paddock_agent_running with failing_since", func() bool {
		return failingWithStart("impostor") && failingWithStart("restart")
	})
	hosts["restart"].AgentNotRunning = false
	waitFor("restart passes again with failing_since cleared", func() bool {
		return passingCleared("restart")
	})
	if _, err := db.Exec(testContext(t, time.Minute), `UPDATE inventory_policy_result SET failing_since = failing_since - interval '16 minutes'
		WHERE device_id = $1 AND policy_key = 'paddock_agent_running'`, devices["impostor"].DeviceID); err != nil {
		t.Fatal(err)
	}

	eventsOf := func(p *env.Portal, device string) []env.AuditEvent {
		all, err := p.AuditEventsSince(testContext(t, time.Minute), agentNotRunningCode, start.Add(-time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		var out []env.AuditEvent
		for _, e := range all {
			if e.Target != nil && e.Target.ID == device {
				out = append(out, e)
			}
		}
		return out
	}
	waitFor("alice sees device.tamper_agent_not_running for impostor", func() bool {
		return len(eventsOf(alice, devices["impostor"].DeviceID)) > 0
	})
	t.Logf("%s after %s", agentNotRunningCode, time.Since(start).Round(time.Second))
	ev := eventsOf(alice, devices["impostor"].DeviceID)
	if len(ev) != 1 {
		t.Fatalf("impostor: %d events, want 1", len(ev))
	}
	stamp := func(key string) time.Time {
		s, _ := ev[0].Params[key].(string)
		at, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			t.Fatalf("param %s %q: %v (params %v)", key, s, err, ev[0].Params)
		}
		return at
	}
	if contact, since := stamp("last_contact_at"), stamp("failing_since"); !contact.After(since) {
		t.Errorf("last_contact_at %v is not later than failing_since %v", contact, since)
	}
	stamp("evaluated_at")

	ids := []string{}
	for _, d := range devices {
		ids = append(ids, d.DeviceID)
	}
	synced := func() map[string]time.Time {
		rows, err := db.Query(testContext(t, time.Minute), "SELECT device_id::text, synced_at FROM device_inventory_ref WHERE device_id::text = ANY($1::text[])", ids)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]time.Time{}
		for rows.Next() {
			var id string
			var at time.Time
			if err := rows.Scan(&id, &at); err != nil {
				t.Fatal(err)
			}
			out[id] = at
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	last, rounds := synced(), map[string]int{}
	waitFor("two further sync rounds of every gate device", func() bool {
		done := true
		for id, at := range synced() {
			if at.After(last[id]) {
				last[id] = at
				rounds[id]++
			}
			done = done && rounds[id] >= 2
		}
		return done && len(rounds) == len(ids)
	})
	carol := login(t, env.Carol)
	for name, want := range map[string]int{"impostor": 1, "restart": 0, "genuine": 0} {
		if n := len(eventsOf(alice, devices[name].DeviceID)); n != want {
			t.Errorf("%s: %d %s events, want %d", name, n, agentNotRunningCode, want)
		}
		if n := len(eventsOf(carol, devices[name].DeviceID)); n != 0 {
			t.Errorf("carol sees %d %s events of the acme device %s", n, agentNotRunningCode, name)
		}
	}
	if f := tamperFindingOf(t, alice, devices["impostor"].DeviceID, 1); f.Code != agentNotRunningCode {
		t.Errorf("tamper finding %+v", f)
	}
	for _, name := range []string{"restart", "genuine"} {
		q := url.Values{"device_id": {devices[name].DeviceID}, "kind": {"tamper"}}
		if got := listFindings(t, alice, q); len(got) != 0 {
			t.Errorf("%s: tamper findings %+v", name, got)
		}
	}
}

// fleetHostClaimedCode is the audit code of a claim on a device's inventory host (ADR 0057).
const fleetHostClaimedCode = "device.tamper_fleet_host_claimed"

// TestInventoryHostBinding is the gate of plan M5a amendment 2026-11-17 e (PDK-1123, AC-H1 to AC-H5, AC-H8): simulated
// hosts answer Fleet for acme devices while the devices check in.
//  1. bound: a host enrolled first with D1's hardware UUID fails the agent binary policy; D1 reports the token of its
//     own host, which passes. D1 is bound to its host, stores only its data, and the other host is reported as
//     second_host with binding device.
//  2. reenrolled: D2's bound host is enrolled again under its identifier and fails the binary policy; the org admin sees
//     one reenrolled claim and no agent binary event, which waits 60 minutes.
//  3. first: D3 reports no token; the host enrolled first is stored, a later one is reported with binding first.
//  4. refused: D4 reports D1's token, whose host has another hardware UUID; D4 stays unbound.
//  5. same_uuid: D5 shares D1's hardware UUID; D1's inventory keeps syncing, and nothing is stored for D5.
//
// Claim episodes are seeded 16 minutes back instead of waited for; WatchClaims' unit tests prove the confirmation.
// carol (globex) sees none of the events.
func TestInventoryHostBinding(t *testing.T) {
	root, alice, carol := login(t, env.PlatformAdmin), login(t, env.Alice), login(t, env.Carol)
	suffix := uniqueSuffix()
	published := publishAgentBinary(t, root)
	sum := sha256.Sum256([]byte("another paddockd " + suffix))
	unknown := hex.EncodeToString(sum[:])
	start := time.Now()
	db := ownerDB(t)
	value := func(query string, args ...any) string {
		t.Helper()
		var v *string
		if err := db.QueryRow(testContext(t, time.Minute), query, args...).Scan(&v); err != nil || v == nil {
			return ""
		}
		return *v
	}
	hostOf := func(d *devicesim.Device) string {
		return value("SELECT host_id FROM device_fleet_binding WHERE device_id = $1", d.DeviceID)
	}
	storedOf := func(d *devicesim.Device) string {
		return value("SELECT external_id FROM device_inventory_ref WHERE device_id = $1", d.DeviceID)
	}
	syncedOf := func(d *devicesim.Device) string {
		return value("SELECT synced_at::text FROM device_inventory_ref WHERE device_id = $1", d.DeviceID)
	}

	var devices []*devicesim.Device
	var hosts []*devicesim.FleetHost
	var extra []string
	t.Cleanup(func() {
		for _, id := range fleetHostIDs(t, extra...) {
			deleteFleetHost(t, id)
		}
	})
	device := func(name string) *devicesim.Device {
		d := activeDevice(t, alice, "", "acc-bind-"+name+"-"+suffix)
		devices = append(devices, d)
		return d
	}
	host := func(h *devicesim.FleetHost, binary string) *devicesim.FleetHost {
		h.AgentBinarySHA256 = binary
		hosts = append(hosts, h)
		extra = append(extra, h.Identifier)
		return h
	}
	tick := func() {
		for _, d := range devices {
			if _, _, err := d.Checkin(testContext(t, time.Minute)); err != nil {
				t.Logf("%s: check-in: %v", d.DeviceID, err)
			}
		}
		for _, h := range hosts {
			if _, err := h.Answer(testContext(t, time.Minute)); err != nil && strings.Contains(err.Error(), "node_invalid") {
				if err := h.EnrollAgain(testContext(t, time.Minute)); err != nil {
					t.Logf("%s: enroll again: %v", h.Identifier, err)
				} else if _, err := h.Answer(testContext(t, time.Minute)); err != nil {
					t.Logf("%s: answer after enrolling again: %v", h.Identifier, err)
				}
			}
		}
	}
	deadline := time.Now().Add(20 * time.Minute)
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("not within 20 minutes: %s", what)
			}
			tick()
			time.Sleep(10 * time.Second)
		}
	}
	rounds := func(what string, n int, ds ...*devicesim.Device) {
		t.Helper()
		last, seen := map[string]string{}, map[string]int{}
		for _, d := range ds {
			last[d.DeviceID] = syncedOf(d)
		}
		waitFor(what, func() bool {
			done := true
			for _, d := range ds {
				if at := syncedOf(d); at != last[d.DeviceID] {
					last[d.DeviceID] = at
					seen[d.DeviceID]++
				}
				done = done && seen[d.DeviceID] >= n
			}
			return done
		})
	}
	claims := func(p *env.Portal, d *devicesim.Device) []env.AuditEvent {
		all, err := p.AuditEventsSince(testContext(t, time.Minute), fleetHostClaimedCode, start.Add(-time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		var out []env.AuditEvent
		for _, e := range all {
			if e.Target != nil && e.Target.ID == d.DeviceID {
				out = append(out, e)
			}
		}
		return out
	}
	events := func(code string, d *devicesim.Device) int {
		all, err := alice.AuditEventsSince(testContext(t, time.Minute), code, start.Add(-time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, e := range all {
			if e.Target != nil && e.Target.ID == d.DeviceID {
				n++
			}
		}
		return n
	}
	seedClaim := func(d *devicesim.Device) {
		t.Helper()
		waitFor("a claim episode of "+d.DeviceID, func() bool {
			return value("SELECT fleet_claim_since::text FROM device_inventory_ref WHERE device_id = $1", d.DeviceID) != ""
		})
		if _, err := db.Exec(testContext(t, time.Minute), "UPDATE device_inventory_ref SET fleet_claim_since = now() - interval '16 minutes' WHERE device_id = $1",
			d.DeviceID); err != nil {
			t.Fatal(err)
		}
	}
	claimed := func(d *devicesim.Device, kind, binding, bound string) {
		t.Helper()
		var got []env.AuditEvent
		waitFor(fleetHostClaimedCode+" for "+d.DeviceID, func() bool { got = claims(alice, d); return len(got) > 0 })
		p := got[0].Params
		if len(got) != 1 || p["kind"] != kind || p["binding"] != binding || p["bound_host"] != bound {
			t.Errorf("%s: claims %+v, want one %s/%s/%s", d.DeviceID, got, kind, binding, bound)
		}
	}

	d1 := device("d1")
	host(enrollFleetHostAs(t, "acc-bind-early-"+suffix, d1.HardwareUUID(), "acc-bind-early-"+suffix), unknown)
	b1 := host(enrollFleetHostBound(t, d1.HardwareUUID(), "acc-bind-d1-"+suffix), published)
	d1.FleetDeviceToken = b1.Token
	b1ID := fmt.Sprint(fleetHostIDs(t, b1.Identifier)[0])
	waitFor("D1 bound to and storing its host "+b1ID, func() bool { return hostOf(d1) == b1ID && storedOf(d1) == b1ID })
	rounds("two further rounds of D1", 2, d1)
	if storedOf(d1) != b1ID || value(`SELECT passing::text FROM inventory_policy_result WHERE device_id = $1 AND policy_key = 'paddock_agent_binary_known'`, d1.DeviceID) != "true" {
		t.Errorf("D1 stores %s, binary policy %s", storedOf(d1), value(`SELECT passing::text FROM inventory_policy_result WHERE device_id = $1 AND policy_key = 'paddock_agent_binary_known'`, d1.DeviceID))
	}
	if n := events(agentBinaryCode, d1); n != 0 {
		t.Errorf("D1: %d %s events", n, agentBinaryCode)
	}
	seedClaim(d1)
	claimed(d1, "second_host", "device", b1ID)

	d2 := device("d2")
	b2 := host(enrollFleetHostBound(t, d2.HardwareUUID(), "acc-bind-d2-"+suffix), published)
	d2.FleetDeviceToken = b2.Token
	b2ID := fmt.Sprint(fleetHostIDs(t, b2.Identifier)[0])
	waitFor("D2 bound and its enrollment time recorded", func() bool {
		return hostOf(d2) == b2ID && value("SELECT fleet_enrolled_at::text FROM device_inventory_ref WHERE device_id = $1", d2.DeviceID) != ""
	})
	host(enrollFleetHostAs(t, b2.Identifier, d2.HardwareUUID(), "acc-bind-d2-"+suffix), unknown)
	claimed(d2, "reenrolled", "device", b2ID)
	rounds("two further rounds of D2", 2, d2)
	if n := events(agentBinaryCode, d2); n != 0 {
		t.Errorf("D2: %d %s events during the hold", n, agentBinaryCode)
	}

	d3 := device("d3")
	host(enrollFleetHost(t, d3.HardwareUUID(), "acc-bind-d3-"+suffix, nil), published)
	host(enrollFleetHostAs(t, "acc-first-late-"+suffix, d3.HardwareUUID(), "acc-first-late-"+suffix), unknown)
	f3ID := fmt.Sprint(fleetHostIDs(t, d3.HardwareUUID())[0])
	waitFor("D3 stores its first host", func() bool { return storedOf(d3) == f3ID })
	rounds("two further rounds of D3", 2, d3)
	if storedOf(d3) != f3ID || value(`SELECT passing::text FROM inventory_policy_result WHERE device_id = $1 AND policy_key = 'paddock_agent_binary_known'`, d3.DeviceID) != "true" {
		t.Errorf("D3 stores %s", storedOf(d3))
	}
	seedClaim(d3)
	claimed(d3, "second_host", "first", f3ID)

	d4 := device("d4")
	d4.FleetDeviceToken = b1.Token
	rounds("two rounds of D1 after D4 checked in", 2, d1)
	if got := hostOf(d4); got != "" {
		t.Errorf("D4 bound to %s", got)
	}

	tok := createTokenWith(t, alice, tokenOptions{autoApprove: true}, true)
	d5 := newSim(t, tok.EnrollmentConfig)
	d5.HardwareUUIDOverride = d1.HardwareUUID()
	if res, err := d5.Enroll(testContext(t, time.Minute), "acc-bind-d5-"+suffix); err != nil || res.Status != http.StatusAccepted {
		t.Fatalf("enroll D5: %v HTTP %d", err, res.Status)
	}
	if s, err := d5.WaitEnrollment(testContext(t, 30*time.Second), func(s protocol.EnrollStatus) bool { return s.Status != protocol.EnrollProcessing }); err != nil || s.Status != protocol.EnrollActive {
		t.Fatalf("D5: %+v %v", s, err)
	}
	devices = append(devices, d5)
	rounds("two rounds of D1 beside D5", 2, d1)
	if got := storedOf(d5); got != "" {
		t.Errorf("D5 stores host %s although its hardware UUID is D1's", got)
	}

	for _, d := range devices {
		if got := claims(carol, d); len(got) != 0 {
			t.Errorf("carol sees %d claims of %s", len(got), d.DeviceID)
		}
		if n := events(agentNotRunningCode, d); n != 0 {
			t.Errorf("%s: %d %s events", d.DeviceID, n, agentNotRunningCode)
		}
	}
}

// fleetdSilentCode is the audit code of a fleetd that falls silent while its device checks in (plan M5a amendments
// 2026-11-16 c and d).
const fleetdSilentCode = "device.tamper_fleetd_silent"

// TestInventoryFleetdSilent is the acceptance gate of plan M5a amendment 2026-11-16 c (PDK-1122d, AC-D1, AC-D4):
//  1. three peers check in and their simulated hosts answer Fleet every iteration, so that most live devices reach
//     Fleet;
//  2. silent checks in every iteration and has no host in Fleet; its inventory reference is seeded with a last contact
//     20 minutes ago, a silence that started 16 minutes ago and a check-in noted 10 minutes ago (the branch of a host
//     deleted in Fleet, confirmed);
//  3. quiet is seeded alike without a silence start and stops checking in after the first iteration.
//
// alice sees exactly one device.tamper_fleetd_silent for silent with its params and a tamper finding; quiet gets a
// silence start and no event; after two further sync rounds silent still has one event and the peers none; carol
// (globex) sees none. The 15-minute thresholds are proven by TestInventoryRoundFleetSilence.
func TestInventoryFleetdSilent(t *testing.T) {
	alice := login(t, env.Alice)
	suffix := uniqueSuffix()
	start := time.Now()
	peers := map[string]*devicesim.Device{}
	hosts := []*devicesim.FleetHost{}
	for _, name := range []string{"peer1", "peer2", "peer3"} {
		hostname := "inv-silent-" + name + "-" + suffix
		peers[name] = activeDevice(t, alice, "", hostname)
		hosts = append(hosts, enrollFleetHost(t, peers[name].HardwareUUID(), hostname, nil))
	}
	silent := activeDevice(t, alice, "", "inv-silent-silent-"+suffix)
	quiet := activeDevice(t, alice, "", "inv-silent-quiet-"+suffix)
	db := ownerDB(t)
	for _, d := range []*devicesim.Device{silent, quiet} {
		if _, _, err := d.Checkin(testContext(t, time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(testContext(t, time.Minute), `INSERT INTO device_inventory_ref
		(device_id, organization_id, external_id, last_seen_at, fleet_silent_since, fleet_silent_checkin_at)
		SELECT id, organization_id, 'acceptance-missing', now() - interval '20 minutes',
		       CASE WHEN id = $1 THEN now() - interval '16 minutes' END,
		       CASE WHEN id = $1 THEN now() - interval '10 minutes' END
		FROM device WHERE id = ANY($2::uuid[])`, silent.DeviceID, []string{silent.DeviceID, quiet.DeviceID}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), "DELETE FROM device_inventory_ref WHERE device_id = ANY($1::uuid[])",
			[]string{silent.DeviceID, quiet.DeviceID})
	})
	deadline := time.Now().Add(10 * time.Minute)
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		for {
			for _, d := range append([]*devicesim.Device{silent}, peers["peer1"], peers["peer2"], peers["peer3"]) {
				if _, _, err := d.Checkin(testContext(t, time.Minute)); err != nil {
					t.Fatal(err)
				}
			}
			for _, h := range hosts {
				if _, err := h.Answer(testContext(t, time.Minute)); err != nil {
					t.Fatal(err)
				}
			}
			if cond() {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("not within 10 minutes: %s", what)
			}
			time.Sleep(10 * time.Second)
		}
	}
	eventsOf := func(p *env.Portal, device string) []env.AuditEvent {
		all, err := p.AuditEventsSince(testContext(t, time.Minute), fleetdSilentCode, start.Add(-time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		var out []env.AuditEvent
		for _, e := range all {
			if e.Target != nil && e.Target.ID == device {
				out = append(out, e)
			}
		}
		return out
	}
	quietStarted := func() bool {
		var n int
		if err := db.QueryRow(testContext(t, time.Minute), `SELECT count(*) FROM device_inventory_ref
			WHERE device_id = $1 AND fleet_silent_since IS NOT NULL`, quiet.DeviceID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}
	waitFor("alice sees device.tamper_fleetd_silent for silent and quiet has a silence start", func() bool {
		return len(eventsOf(alice, silent.DeviceID)) > 0 && quietStarted()
	})
	t.Logf("%s after %s", fleetdSilentCode, time.Since(start).Round(time.Second))
	ev := eventsOf(alice, silent.DeviceID)
	if len(ev) != 1 {
		t.Fatalf("silent: %d events, want 1", len(ev))
	}
	stamp := func(key string) time.Time {
		s, _ := ev[0].Params[key].(string)
		at, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			t.Fatalf("param %s %q: %v (params %v)", key, s, err, ev[0].Params)
		}
		return at
	}
	if contact, seen := stamp("last_contact_at"), stamp("fleetd_seen_at"); !contact.After(seen) {
		t.Errorf("last_contact_at %v is not later than fleetd_seen_at %v", contact, seen)
	}
	stamp("silent_since")
	if reason := ev[0].Params["reason"]; reason != "contact" {
		t.Errorf("reason %v, want contact", reason)
	}
	if f := tamperFindingOf(t, alice, silent.DeviceID, 1); f.Code != fleetdSilentCode {
		t.Errorf("tamper finding %+v", f)
	}

	ids := []string{}
	for _, d := range peers {
		ids = append(ids, d.DeviceID)
	}
	synced := func() map[string]time.Time {
		rows, err := db.Query(testContext(t, time.Minute), "SELECT device_id::text, synced_at FROM device_inventory_ref WHERE device_id::text = ANY($1::text[])", ids)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]time.Time{}
		for rows.Next() {
			var id string
			var at time.Time
			if err := rows.Scan(&id, &at); err != nil {
				t.Fatal(err)
			}
			out[id] = at
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	last, rounds := synced(), map[string]int{}
	waitFor("two further sync rounds of every peer", func() bool {
		done := true
		for id, at := range synced() {
			if at.After(last[id]) {
				last[id] = at
				rounds[id]++
			}
			done = done && rounds[id] >= 2
		}
		return done && len(rounds) == len(ids)
	})
	carol := login(t, env.Carol)
	all := map[string]*devicesim.Device{"silent": silent, "quiet": quiet, "peer1": peers["peer1"], "peer2": peers["peer2"],
		"peer3": peers["peer3"]}
	for name, d := range all {
		want := 0
		if name == "silent" {
			want = 1
		}
		if n := len(eventsOf(alice, d.DeviceID)); n != want {
			t.Errorf("%s: %d %s events, want %d", name, n, fleetdSilentCode, want)
		}
		if n := len(eventsOf(carol, d.DeviceID)); n != 0 {
			t.Errorf("carol sees %d %s events of the acme device %s", n, fleetdSilentCode, name)
		}
	}
}

// TestInventoryAgentRunningQueryFails is the acceptance gate of plan M5a amendment 2026-11-16 d, F6 (AC-d3): a host
// first passes paddock_agent_running, then its query fails on the device (status 1, no answer). The stored result
// becomes failing with failing_since; seeded 16 minutes back, the next failing evaluation while the device checks in
// records device.tamper_agent_not_running for alice.
func TestInventoryAgentRunningQueryFails(t *testing.T) {
	alice := login(t, env.Alice)
	hostname := "inv-qfail-" + uniqueSuffix()
	start := time.Now()
	device := activeDevice(t, alice, "", hostname)
	host := enrollFleetHost(t, device.HardwareUUID(), hostname, nil)
	db := ownerDB(t)
	deadline := time.Now().Add(10 * time.Minute)
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		for {
			if _, _, err := device.Checkin(testContext(t, time.Minute)); err != nil {
				t.Fatal(err)
			}
			if _, err := host.Answer(testContext(t, time.Minute)); err != nil {
				t.Fatal(err)
			}
			if cond() {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("not within 10 minutes: %s", what)
			}
			time.Sleep(10 * time.Second)
		}
	}
	stored := func(passing bool) bool {
		var n int
		if err := db.QueryRow(testContext(t, time.Minute), `SELECT count(*) FROM inventory_policy_result
			WHERE device_id = $1 AND policy_key = 'paddock_agent_running' AND passing = $2
			  AND (passing OR failing_since IS NOT NULL)`, device.DeviceID, passing).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}
	waitFor("paddock_agent_running is stored as passing", func() bool { return stored(true) })
	host.AgentRunningQueryFails = true
	waitFor("the unanswered paddock_agent_running is stored as failing with failing_since", func() bool { return stored(false) })
	if _, err := db.Exec(testContext(t, time.Minute), `UPDATE inventory_policy_result SET failing_since = failing_since - interval '16 minutes'
		WHERE device_id = $1 AND policy_key = 'paddock_agent_running'`, device.DeviceID); err != nil {
		t.Fatal(err)
	}
	events := func() int {
		all, err := alice.AuditEventsSince(testContext(t, time.Minute), agentNotRunningCode, start.Add(-time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, e := range all {
			if e.Target != nil && e.Target.ID == device.DeviceID {
				n++
			}
		}
		return n
	}
	waitFor("alice sees device.tamper_agent_not_running", func() bool { return events() > 0 })
	t.Logf("%s after %s", agentNotRunningCode, time.Since(start).Round(time.Second))
	if n := events(); n != 1 {
		t.Fatalf("%d events, want 1", n)
	}
}
