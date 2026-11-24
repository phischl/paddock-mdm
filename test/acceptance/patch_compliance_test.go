package acceptance

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// patchReport is the part of GET /api/v1/patch-compliance the gate reads.
type patchReport struct {
	Summary struct {
		Devices   int `json:"devices"`
		Compliant int `json:"compliant"`
		Breached  int `json:"breached"`
	} `json:"summary"`
	BySeverity []struct {
		Severity         string `json:"severity"`
		FindingsOpen     int    `json:"findings_open"`
		FindingsBreached int    `json:"findings_breached"`
	} `json:"by_severity"`
	ByGroup []struct {
		DeviceGroup string `json:"device_group"`
		Devices     int    `json:"devices"`
		Breached    int    `json:"breached"`
	} `json:"by_group"`
	Devices []struct {
		Hostname string `json:"hostname"`
		Breached []struct {
			CVE      string `json:"cve"`
			DaysOpen int    `json:"days_open"`
			SLADays  int    `json:"sla_days"`
		} `json:"breached"`
	} `json:"devices"`
	DevicesTotal int `json:"devices_total"`
}

func (r patchReport) breached(severity string) int {
	for _, s := range r.BySeverity {
		if s.Severity == severity {
			return s.FindingsBreached
		}
	}
	return -1
}

// TestPatchCompliance is gate C5 of plan M13c (decision 18, PDK-814): with the SLA set to 7 critical days, seeded
// findings give the breached counts per severity and per device group (an 8-day-old critical finding is breached, a
// 6-day-old one is not, a finding without a fixed version is not counted); the operator and the auditor read the
// report; the CSV export has a row for every breached finding and is recorded as patch_compliance.exported; the
// worker's daily vulnerability.sla_breached summary appears once per day with the counts (pending stack run).
func TestPatchCompliance(t *testing.T) {
	if left := time.Until(time.Now().UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)); left < 8*time.Minute {
		time.Sleep(left + 5*time.Second) // the summary part must not straddle the UTC day
	}
	slug, org := gateOrganization(t)
	admin := tempPortal(t, "pc-admin", env.RoleGroup(slug, "admins"))
	operator := tempPortal(t, "pc-operator", env.RoleGroup(slug, "operators"))
	auditor := tempPortal(t, "pc-auditor", env.RoleGroup(slug, "auditors"))
	suffix := uniqueSuffix()

	dsn, err := stack.PaddockOwnerDSN()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.Connect(testContext(t, time.Minute), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := conn.Exec(testContext(t, time.Minute), sql, args...); err != nil {
			t.Fatal(err)
		}
	}

	expectStatus(t, call(t, admin, http.MethodPut, "/api/v1/settings/patch-sla",
		map[string]any{"critical_days": 7, "high_days": 30, "medium_days": 90, "low_days": 0}), http.StatusOK, "")
	expectStatus(t, call(t, operator, http.MethodPut, "/api/v1/settings/patch-sla",
		map[string]any{"critical_days": 1, "high_days": 30, "medium_days": 90, "low_days": 0}), http.StatusForbidden, "forbidden")

	group := uuid.Must(uuid.NewV7())
	exec("INSERT INTO device_group (id, organization_id, name) VALUES ($1, $2, $3)", group, org, "pc-laptops-"+suffix)
	now := time.Now()
	devices := make([]uuid.UUID, 3)
	for i := range devices {
		devices[i] = uuid.Must(uuid.NewV7())
		exec("INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, $3, 'active')", devices[i], org,
			fmt.Sprintf("pc-%d-%s", i, suffix))
		exec("INSERT INTO device_inventory_ref (device_id, organization_id, external_id) VALUES ($1, $2, $3)", devices[i], org,
			"pc-"+devices[i].String())
	}
	exec("INSERT INTO device_group_member (organization_id, device_group_id, device_id) VALUES ($1, $2, $3), ($1, $2, $4)",
		org, group, devices[0], devices[1])
	finding := func(dev uuid.UUID, severity string, fixed *string, days float64) {
		t.Helper()
		exec(`INSERT INTO vulnerability_finding (device_id, organization_id, cve, software_name, software_version, severity,
			fixed_version, first_seen_at) VALUES ($1, $2, $3, 'pc-pkg', '1.0', $4, $5, $6)`, dev, org, uniqueCVE(), severity, fixed,
			now.Add(-time.Duration(days*float64(24*time.Hour))))
	}
	fixed := "1.1"
	finding(devices[0], "critical", &fixed, 8) // breached
	finding(devices[0], "high", &fixed, 31)    // breached
	finding(devices[1], "critical", &fixed, 6) // within the SLA
	finding(devices[2], "critical", &fixed, 20)
	finding(devices[2], "critical", nil, 400) // no fix: not counted
	finding(devices[2], "low", &fixed, 400)   // low has no SLA

	read := func(p *env.Portal, path string) patchReport {
		t.Helper()
		res := call(t, p, http.MethodGet, path, nil)
		expectStatus(t, res, http.StatusOK, "")
		var r patchReport
		if err := res.JSON(&r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	for _, p := range []*env.Portal{operator, auditor} {
		r := read(p, "/api/v1/patch-compliance")
		if r.Summary.Devices != 3 || r.Summary.Breached != 2 || r.Summary.Compliant != 1 || r.DevicesTotal != 2 ||
			r.breached("critical") != 2 || r.breached("high") != 1 || r.breached("low") != 0 {
			t.Fatalf("report: %+v", r)
		}
		if len(r.ByGroup) != 1 || r.ByGroup[0].Devices != 2 || r.ByGroup[0].Breached != 1 {
			t.Fatalf("by group: %+v", r.ByGroup)
		}
	}
	grouped := read(auditor, "/api/v1/patch-compliance?device_group_id="+group.String())
	if grouped.Summary.Devices != 2 || grouped.Summary.Breached != 1 || len(grouped.Devices) != 1 ||
		grouped.Devices[0].Hostname != "pc-0-"+suffix || len(grouped.Devices[0].Breached) != 2 {
		t.Fatalf("group filter: %+v", grouped)
	}
	expectStatus(t, call(t, auditor, http.MethodGet, "/api/v1/patch-compliance?device_group_id="+uuid.NewString(), nil),
		http.StatusNotFound, "not_found")

	res := call(t, auditor, http.MethodGet, "/api/v1/patch-compliance/export?format=csv", nil)
	expectStatus(t, res, http.StatusOK, "")
	rows, err := csv.NewReader(strings.NewReader(string(res.Body))).ReadAll()
	if err != nil || len(rows) < 2 || rows[0][0] != "section" {
		t.Fatalf("csv: %v %v", err, rows)
	}
	breaches := 0
	for _, row := range rows[1:] {
		if row[0] == "breach" {
			breaches++
		}
	}
	if breaches != 3 {
		t.Fatalf("csv has %d breach rows, want 3", breaches)
	}
	expectOneEvent(t, admin, res.RequestID, "patch_compliance.exported", "success")

	summaries := func() []map[string]any {
		t.Helper()
		rows, err := conn.Query(testContext(t, time.Minute), `SELECT params FROM action
			WHERE code = 'vulnerability.sla_breached' AND organization_id = $1 ORDER BY started_at`, org)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := pgx.CollectRows(rows, pgx.RowTo[[]byte])
		if err != nil {
			t.Fatal(err)
		}
		out := make([]map[string]any, len(raw))
		for i, r := range raw {
			if err := json.Unmarshal(r, &out[i]); err != nil {
				t.Fatal(err)
			}
		}
		return out
	}
	waitOSV(t, "the patch SLA summary", 4*time.Minute, 5*time.Second, func() bool { return len(summaries()) > 0 })
	ev := summaries()
	if len(ev) != 1 || ev[0]["critical"] != float64(2) || ev[0]["high"] != float64(1) || ev[0]["low"] != float64(0) ||
		ev[0]["devices"] != float64(2) {
		t.Fatalf("summaries %v", ev)
	}
	time.Sleep(3 * time.Minute) // several more inventory rounds (60 s in the development stack)
	if n := len(summaries()); n != 1 {
		t.Errorf("%d summaries after further rounds of the same day, want 1", n)
	}
}

// patchComplianceAuditCases are the A3 cases of the PDK-814 operations: the SLA change and the export. The view is not
// listed: it is recorded only under a privacy setting and has no x-paddock-audit.
var patchComplianceAuditCases = map[string][]auditCase{
	"PUT /api/v1/settings/patch-sla": {
		{"success", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPut, "/api/v1/settings/patch-sla", currentPatchSLA(t, w.alice))
			expectStatus(t, res, http.StatusOK, "")
			expectOneEvent(t, w.alice, res.RequestID, "settings.patch_sla_changed", "success")
		}},
		{"invalid value", func(t *testing.T, w *auditWorld) {
			s := currentPatchSLA(t, w.alice)
			s["critical_days"] = 366
			res := call(t, w.alice, http.MethodPut, "/api/v1/settings/patch-sla", s)
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectOneEvent(t, w.alice, res.RequestID, "settings.patch_sla_changed", "failure")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			operator := tempPortal(t, "a3-sla-op", env.RoleGroup("acme", "operators"))
			res := call(t, operator, http.MethodPut, "/api/v1/settings/patch-sla", currentPatchSLA(t, w.alice))
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, "settings.patch_sla_changed", "denied")
		}},
	},
	"GET /api/v1/patch-compliance/export": {
		{"success", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodGet, "/api/v1/patch-compliance/export?format=csv", nil)
			expectStatus(t, res, http.StatusOK, "")
			expectOneEvent(t, w.alice, res.RequestID, "patch_compliance.exported", "success")
		}},
		{"unknown device group", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodGet, "/api/v1/patch-compliance/export?format=json&device_group_id="+uuid.NewString(), nil)
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneEvent(t, w.alice, res.RequestID, "patch_compliance.exported", "failure")
		}},
	},
}

// currentPatchSLA returns acme's patch SLA as an update body (unchanged values).
func currentPatchSLA(t *testing.T, p *env.Portal) map[string]any {
	t.Helper()
	res := call(t, p, http.MethodGet, "/api/v1/settings/patch-sla", nil)
	expectStatus(t, res, http.StatusOK, "")
	var s map[string]any
	if err := res.JSON(&s); err != nil {
		t.Fatal(err)
	}
	delete(s, "updated_at")
	return s
}
