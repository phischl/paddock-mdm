package admin_test

import (
	"context"
	"net/http"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// insertInventory stores packages and findings of a device as the worker's sync would; findings are
// "cve:package:version:cvss" with an empty cvss for an unknown score.
func (e *env) insertInventory(org, device uuid.UUID, packages [][2]string, findings [][4]string) {
	e.t.Helper()
	ctx := context.Background()
	for _, p := range packages {
		if _, err := e.super.Exec(ctx, `INSERT INTO installed_software (device_id, organization_id, name, version, source)
			VALUES ($1, $2, $3, $4, 'deb_packages')`, device, org, p[0], p[1]); err != nil {
			e.t.Fatal(err)
		}
	}
	for _, f := range findings {
		if _, err := e.super.Exec(ctx, `INSERT INTO vulnerability_finding (device_id, organization_id, cve, software_name, software_version,
			cvss_score, severity) VALUES ($1, $2, $3, $4, $5, NULLIF($6, '')::numeric,
			CASE WHEN $6 = '' THEN NULL WHEN $6::numeric >= 9 THEN 'critical' WHEN $6::numeric >= 7 THEN 'high' ELSE 'medium' END)`,
			device, org, f[0], f[1], f[2], f[3]); err != nil {
			e.t.Fatal(err)
		}
	}
}

// get calls a GET of the admin API and decodes its 200 answer into v.
func (e *env) get(t *testing.T, cookie *http.Cookie, path string, v any) {
	t.Helper()
	res := e.do(call{method: "GET", path: path, cookie: cookie})
	if res.status != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, res.status, res.body)
	}
	res.decode(t, v)
}

// TestInventoryEndpoints (plan M5a decision 9, gate F3 at the handler level): software and vulnerabilities per device
// and per organization with their filters and sorts; another organization's device is 404, and the organization-wide
// lists never contain its rows.
func TestInventoryEndpoints(t *testing.T) {
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAuditor)
	carol := e.session(e.globex, principal.RoleOrgAdmin)
	a1 := e.insertDevice(e.acme, "inv-a1", "active")
	a2 := e.insertDevice(e.acme, "inv-a2", "active")
	g1 := e.insertDevice(e.globex, "inv-g1", "active")
	e.insertInventory(e.acme, a1, [][2]string{{"openssl", "3.0.13"}, {"curl", "8.5.0"}, {"bash", "5.2"}},
		[][4]string{{"CVE-2024-0001", "openssl", "3.0.13", "9.8"}, {"CVE-2024-0002", "curl", "8.5.0", ""}})
	e.insertInventory(e.acme, a2, [][2]string{{"openssl", "3.0.13"}}, [][4]string{{"CVE-2024-0001", "openssl", "3.0.13", "9.8"}})
	// A retired device keeps its last inventory on its own pages but is not counted organization-wide.
	retired := e.insertDevice(e.acme, "inv-a3", "retired")
	e.insertInventory(e.acme, retired, [][2]string{{"retired-only", "1.0"}}, [][4]string{{"CVE-2024-0003", "retired-only", "1.0", "9.1"}})
	e.insertInventory(e.globex, g1, [][2]string{{"globex-only", "1.0"}}, [][4]string{{"CVE-2024-9999", "globex-only", "1.0", "7.5"}})

	var sw adminapi.InstalledSoftwarePage
	e.get(t, alice, "/api/v1/devices/"+a1.String()+"/software?sort=-name", &sw)
	if sw.Total != 3 || sw.Items[0].Name != "openssl" || sw.Items[2].Name != "bash" || sw.Items[0].Source != "deb_packages" {
		t.Fatalf("device software %+v", sw)
	}
	e.get(t, alice, "/api/v1/devices/"+a1.String()+"/software?q=ssl", &sw)
	if sw.Total != 1 || sw.Items[0].Name != "openssl" {
		t.Fatalf("software search %+v", sw)
	}

	var findings adminapi.VulnerabilityFindingPage
	e.get(t, alice, "/api/v1/devices/"+a1.String()+"/vulnerabilities?sort=cvss_score", &findings)
	if findings.Total != 2 || findings.Sort != "cvss_score" || findings.Items[0].Cve != "CVE-2024-0001" ||
		findings.Items[0].Severity != "critical" || findings.Items[0].CvssScore == nil || *findings.Items[0].CvssScore != 9.8 ||
		findings.Items[1].Severity != "unknown" || findings.Items[1].CvssScore != nil {
		t.Fatalf("device vulnerabilities %+v", findings)
	}
	e.get(t, alice, "/api/v1/devices/"+a1.String()+"/vulnerabilities?sort=-cvss_score", &findings) // unknown scores last
	if findings.Total != 2 || findings.Items[0].Cve != "CVE-2024-0001" || findings.Items[1].Cve != "CVE-2024-0002" {
		t.Fatalf("device vulnerabilities by descending score %+v", findings)
	}
	e.get(t, alice, "/api/v1/devices/"+a1.String()+"/vulnerabilities?severity=unknown", &findings)
	if findings.Total != 1 || findings.Items[0].Cve != "CVE-2024-0002" {
		t.Fatalf("unknown severity %+v", findings)
	}

	e.get(t, alice, "/api/v1/devices/"+retired.String()+"/vulnerabilities", &findings)
	if findings.Total != 1 || findings.Items[0].Cve != "CVE-2024-0003" {
		t.Fatalf("retired device vulnerabilities %+v", findings)
	}

	var software adminapi.SoftwareSummaryPage
	e.get(t, alice, "/api/v1/software?sort=-device_count", &software)
	if software.Total != 3 || software.Items[0].Name != "openssl" || software.Items[0].DeviceCount != 2 || !software.Items[0].HasVulnerabilities {
		t.Fatalf("software %+v", software)
	}
	e.get(t, alice, "/api/v1/software?has_vulnerabilities=false", &software)
	if software.Total != 1 || software.Items[0].Name != "bash" {
		t.Fatalf("software without vulnerabilities %+v", software)
	}

	var vulns adminapi.VulnerabilityPage
	e.get(t, alice, "/api/v1/vulnerabilities?sort=cve", &vulns)
	if vulns.Total != 2 || vulns.Items[0].Cve != "CVE-2024-0001" || vulns.Items[0].DeviceCount != 2 || vulns.Items[0].Severity != "critical" {
		t.Fatalf("vulnerabilities %+v", vulns)
	}
	e.get(t, alice, "/api/v1/vulnerabilities?severity=critical&severity=high", &vulns)
	if vulns.Total != 1 {
		t.Fatalf("critical or high %+v", vulns)
	}
	var devices adminapi.VulnerableDevicePage
	e.get(t, alice, "/api/v1/vulnerabilities/cve-2024-0001/devices", &devices)
	hosts := []string{}
	for _, d := range devices.Items {
		hosts = append(hosts, d.Hostname)
	}
	if devices.Total != 2 || !slices.Equal(hosts, []string{"inv-a1", "inv-a2"}) {
		t.Fatalf("affected devices %+v", devices)
	}
	var summary adminapi.VulnerabilitySummary
	e.get(t, alice, "/api/v1/vulnerabilities/summary", &summary)
	if summary != (adminapi.VulnerabilitySummary{CriticalHighDevices: 2, UnknownSeverityDevices: 1, AffectedDevices: 2}) {
		t.Fatalf("summary %+v", summary)
	}

	// Isolation: globex sees only its own rows; acme's device and acme's CVE are 404 for it, and vice versa.
	for _, path := range []string{"/api/v1/devices/" + a1.String() + "/software", "/api/v1/devices/" + a1.String() + "/vulnerabilities",
		"/api/v1/vulnerabilities/CVE-2024-0001/devices"} {
		if res := e.do(call{method: "GET", path: path, cookie: carol}); res.status != http.StatusNotFound || res.problemCode(t) != "not_found" {
			t.Errorf("globex GET %s: %d %s", path, res.status, res.body)
		}
	}
	if res := e.do(call{method: "GET", path: "/api/v1/devices/" + g1.String() + "/software", cookie: alice}); res.status != http.StatusNotFound {
		t.Errorf("acme reads globex's device: %d", res.status)
	}
	e.get(t, carol, "/api/v1/software", &software)
	if software.Total != 1 || software.Items[0].Name != "globex-only" {
		t.Fatalf("globex software %+v", software)
	}
	e.get(t, carol, "/api/v1/vulnerabilities", &vulns)
	if vulns.Total != 1 || vulns.Items[0].Cve != "CVE-2024-9999" || vulns.Items[0].Severity != "high" {
		t.Fatalf("globex vulnerabilities %+v", vulns)
	}
	if res := e.do(call{method: "GET", path: "/api/v1/vulnerabilities/not-a-cve/devices", cookie: alice, skipReqCheck: true}); res.status != http.StatusBadRequest {
		t.Errorf("invalid CVE: %d", res.status)
	}
}
