package acceptance

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

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
	triggerFleetVulnerabilities(t)

	acmeFindings := "/api/v1/devices/" + acmeDevice.DeviceID + "/vulnerabilities"
	globexFindings := "/api/v1/devices/" + globexDevice.DeviceID + "/vulnerabilities"
	for deadline := start.Add(10 * time.Minute); ; time.Sleep(10 * time.Second) {
		a, g := listInventory(t, alice, acmeFindings), listInventory(t, carol, globexFindings)
		if slices.Contains(a.field("cve"), acmeCVE) && slices.Contains(g.field("cve"), globexCVE) {
			t.Logf("inventory and vulnerabilities in the portal after %s", time.Since(start).Round(time.Second))
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no findings within 10 minutes: acme %v, globex %v", a.field("cve"), g.field("cve"))
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
