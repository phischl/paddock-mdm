package app_test

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/patchsla"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// patchWorld is one organization of the harness with the patch SLA and the report on the API role and a settable
// clock.
type patchWorld struct {
	harness
	sla    *app.PatchSLA
	report *app.PatchCompliance
	now    time.Time
}

func newPatchWorld(t *testing.T) *patchWorld {
	t.Helper()
	w := &patchWorld{harness: newHarness(t), now: time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)}
	pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	w.sla = app.NewPatchSLA(w.runner, pool)
	w.report = app.NewPatchCompliance(w.runner, pool)
	w.report.SetClock(func() time.Time { return w.now })
	return w
}

func (w *patchWorld) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := w.super.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// inventoried inserts an active device of org that the inventory system knows.
func (w *patchWorld) inventoried(t *testing.T, org uuid.UUID, hostname string) uuid.UUID {
	t.Helper()
	dev := w.device(t, org, hostname)
	w.exec(t, "INSERT INTO device_inventory_ref (device_id, organization_id, external_id) VALUES ($1, $2, $3)", dev, org, "fleet-"+dev.String())
	return dev
}

func (w *patchWorld) vuln(t *testing.T, org, dev uuid.UUID, cve, severity string, fixed *string, daysAgo float64) {
	t.Helper()
	seen := w.now.Add(-time.Duration(daysAgo * float64(24*time.Hour)))
	w.exec(t, `INSERT INTO vulnerability_finding (device_id, organization_id, cve, software_name, software_version, severity,
		fixed_version, first_seen_at) VALUES ($1, $2, $3, 'openssl', '3.0.2-0', $4, $5, $6)`, dev, org, cve, severity, fixed, seen)
}

func (w *patchWorld) member(t *testing.T, org, group, dev uuid.UUID) {
	t.Helper()
	w.exec(t, "INSERT INTO device_group_member (organization_id, device_group_id, device_id) VALUES ($1, $2, $3)", org, group, dev)
}

func roleCtx(org uuid.UUID, role principal.Role) context.Context {
	return as(org, principal.Principal{ID: uuid.Must(uuid.NewV7()), Display: string(role), Role: role})
}

// TestPatchSLASettings (plan M13c decision 17): every organization starts with 7/30/90/0; an administrator changes it,
// audited with the four values; operators and auditors read it but are denied the change; a value out of range is a
// failure; another organization's SLA is untouched.
func TestPatchSLASettings(t *testing.T) {
	w := newPatchWorld(t)
	other := w.otherOrg(t)
	for _, role := range []principal.Role{principal.RoleOrgAdmin, principal.RoleOrgOperator, principal.RoleOrgAuditor} {
		got, err := w.sla.Get(roleCtx(w.org, role))
		if err != nil || got.SLA != patchsla.Defaults() {
			t.Fatalf("%s: Get = %+v, %v", role, got, err)
		}
	}
	want := patchsla.SLA{CriticalDays: 3, HighDays: 14, MediumDays: 60, LowDays: 180}
	got, err := w.sla.Update(roleCtx(w.org, principal.RoleOrgAdmin), want)
	if err != nil || got.SLA != want {
		t.Fatalf("Update = %+v, %v", got, err)
	}
	ev := w.events(t, w.org, audit.CodeSettingsPatchSLAChanged)
	if len(ev) != 1 || ev[0].Outcome != audit.OutcomeSuccess || ev[0].Params["critical_days"] != float64(3) ||
		ev[0].Params["low_days"] != float64(180) || ev[0].Params["change_set_id"] == nil {
		t.Fatalf("events %+v", ev)
	}
	for _, role := range []principal.Role{principal.RoleOrgOperator, principal.RoleOrgAuditor} {
		if _, err := w.sla.Update(roleCtx(w.org, role), patchsla.Defaults()); !errors.Is(err, problem.Forbidden) {
			t.Errorf("%s: Update = %v, want forbidden", role, err)
		}
	}
	if _, err := w.sla.Update(roleCtx(w.org, principal.RoleOrgAdmin), patchsla.SLA{CriticalDays: 366}); !errors.Is(err, problem.InvalidRequest) {
		t.Errorf("out of range = %v", err)
	}
	ev = w.events(t, w.org, audit.CodeSettingsPatchSLAChanged)
	if len(ev) != 4 || ev[1].Outcome != audit.OutcomeDenied || ev[2].Outcome != audit.OutcomeDenied || ev[3].Outcome != audit.OutcomeFailure {
		t.Fatalf("events %+v", ev)
	}
	if got, err := w.sla.Get(roleCtx(other, principal.RoleOrgAdmin)); err != nil || got.SLA != patchsla.Defaults() {
		t.Errorf("other organization = %+v, %v", got, err)
	}
	if got, err := w.sla.Get(roleCtx(w.org, principal.RoleOrgAuditor)); err != nil || got.SLA != want {
		t.Errorf("after the failures = %+v, %v", got, err)
	}
}

// TestPatchComplianceReport (plan M13c decision 18, §3.8 L10): seeded findings against the SLA give breached counts
// per severity and group; administrators, operators and auditors read it, another role is denied; another
// organization's devices and findings never appear, nor its device group; an organization without inventory gets
// empty sections.
func TestPatchComplianceReport(t *testing.T) {
	w := newPatchWorld(t)
	w.switches(t, w.org, false, false)
	fixed := "3.0.2-1"
	a, b := w.inventoried(t, w.org, "alpha"), w.inventoried(t, w.org, "bravo")
	notInventoried := w.device(t, w.org, "charlie")
	retired := w.inventoried(t, w.org, "retired")
	w.exec(t, "UPDATE device SET state = 'retired' WHERE id = $1", retired)
	laptops := w.group(t, w.org)
	w.member(t, w.org, laptops, a)
	w.vuln(t, w.org, a, "CVE-2026-0001", "critical", &fixed, 8)
	w.vuln(t, w.org, a, "CVE-2026-0002", "high", &fixed, 10)
	w.vuln(t, w.org, a, "CVE-2026-0003", "critical", nil, 400) // no fixed version: not counted
	w.vuln(t, w.org, b, "CVE-2026-0001", "critical", &fixed, 6.5)
	w.vuln(t, w.org, notInventoried, "CVE-2026-0001", "critical", &fixed, 30)
	w.vuln(t, w.org, retired, "CVE-2026-0001", "critical", &fixed, 30)
	if _, err := w.sla.Update(roleCtx(w.org, principal.RoleOrgAdmin), patchsla.SLA{CriticalDays: 7, HighDays: 30}); err != nil {
		t.Fatal(err)
	}

	other := w.otherOrg(t)
	foreignDev := w.inventoried(t, other, "foreign")
	w.vuln(t, other, foreignDev, "CVE-2026-0001", "critical", &fixed, 100)
	foreignGroup := w.group(t, other)

	for _, role := range []principal.Role{principal.RoleOrgAdmin, principal.RoleOrgOperator, principal.RoleOrgAuditor} {
		r, err := w.report.Report(roleCtx(w.org, role), app.PatchComplianceQuery{})
		if err != nil {
			t.Fatalf("%s: %v", role, err)
		}
		if r.Summary != (patchsla.Summary{Devices: 2, Compliant: 1, Breached: 1}) || r.DevicesTotal != 1 ||
			len(r.Devices) != 1 || r.Devices[0].DeviceID != a || len(r.Devices[0].Breached) != 1 ||
			r.Devices[0].Breached[0].CVE != "CVE-2026-0001" || r.Devices[0].Breached[0].DaysOpen != 8 || r.Devices[0].Breached[0].SLADays != 7 {
			t.Fatalf("%s: report %+v", role, r.Report)
		}
		if len(r.BySeverity) != 2 || r.BySeverity[0] != (patchsla.SeverityStats{Severity: "critical", FindingsOpen: 2, FindingsBreached: 1,
			MedianDaysOpen: 6, P90DaysOpen: 8}) || r.BySeverity[1].FindingsBreached != 0 {
			t.Errorf("%s: by severity %+v", role, r.BySeverity)
		}
		if len(r.ByGroup) != 1 || r.ByGroup[0].GroupID != laptops || r.ByGroup[0].Devices != 1 || r.ByGroup[0].Breached != 1 {
			t.Errorf("%s: by group %+v", role, r.ByGroup)
		}
		if r.SLA.CriticalDays != 7 || !r.GeneratedAt.Equal(w.now) {
			t.Errorf("%s: sla %+v, generated at %s", role, r.SLA, r.GeneratedAt)
		}
	}
	if _, err := w.report.Report(roleCtx(w.org, principal.RolePlatform), app.PatchComplianceQuery{}); !errors.Is(err, problem.Forbidden) {
		t.Errorf("platform role = %v, want forbidden", err)
	}

	byGroup, err := w.report.Report(roleCtx(w.org, principal.RoleOrgAuditor),
		app.PatchComplianceQuery{DeviceGroupID: uuid.NullUUID{UUID: laptops, Valid: true}})
	if err != nil || byGroup.Summary.Devices != 1 || byGroup.Summary.Breached != 1 || !byGroup.DeviceGroupID.Valid {
		t.Errorf("group filter = %+v, %v", byGroup.Summary, err)
	}
	if _, err := w.report.Report(roleCtx(w.org, principal.RoleOrgAdmin),
		app.PatchComplianceQuery{DeviceGroupID: uuid.NullUUID{UUID: foreignGroup, Valid: true}}); !errors.Is(err, problem.NotFound) {
		t.Errorf("foreign group = %v, want not_found", err)
	}

	// The report is the state at generated_at (plan M13c amendment 2026-11-14): two days later bravo's 6.5-day-old
	// critical finding is 8 days old and breached as well.
	w.now = w.now.Add(48 * time.Hour)
	later, err := w.report.Report(roleCtx(w.org, principal.RoleOrgAuditor), app.PatchComplianceQuery{})
	if err != nil || later.Summary.Breached != 2 || !later.GeneratedAt.Equal(w.now) || later.BySeverity[0].FindingsBreached != 2 {
		t.Errorf("two days later = %+v, %v", later.Summary, err)
	}
	w.now = w.now.Add(-48 * time.Hour)

	foreign, err := w.report.Report(roleCtx(other, principal.RoleOrgAdmin), app.PatchComplianceQuery{})
	if err != nil || foreign.Summary != (patchsla.Summary{Devices: 1, Compliant: 0, Breached: 1}) || foreign.Devices[0].DeviceID != foreignDev {
		t.Errorf("other organization = %+v, %v", foreign.Summary, err)
	}

	empty := w.otherOrg(t)
	r, err := w.report.Report(roleCtx(empty, principal.RoleOrgAuditor), app.PatchComplianceQuery{})
	if err != nil || r.Summary != (patchsla.Summary{}) || len(r.BySeverity)+len(r.ByGroup)+len(r.Devices)+len(r.Catalog) != 0 ||
		r.BySeverity == nil || r.Devices == nil {
		t.Errorf("without inventory = %+v, %v", r, err)
	}
}

// TestPatchComplianceCatalog (plan M13c decision 18): a pinned required assignment counts the devices it targets that
// run an older version of its package; a device it does not target, a newer version and an unpinned assignment do not
// count.
func TestPatchComplianceCatalog(t *testing.T) {
	w := newPatchWorld(t)
	w.switches(t, w.org, false, false)
	old, current, untargeted, owned := w.inventoried(t, w.org, "old"), w.inventoried(t, w.org, "current"),
		w.inventoried(t, w.org, "untargeted"), w.inventoried(t, w.org, "owned")
	group := w.group(t, w.org)
	w.member(t, w.org, group, old)
	w.member(t, w.org, group, current)
	for dev, version := range map[uuid.UUID]string{old: "119.0-1", current: "120.0-1", untargeted: "1.0", owned: "100.0"} {
		w.exec(t, `INSERT INTO installed_software (device_id, organization_id, name, version, source) VALUES ($1, $2, 'firefox', $3, 'deb_packages')`,
			dev, w.org, version)
	}
	entry := uuid.Must(uuid.NewV7())
	w.exec(t, `INSERT INTO software_catalog_entry (id, organization_id, name, packages) VALUES ($1, $2, 'Firefox', $3::jsonb)`, entry, w.org,
		`[{"distribution":"ubuntu","release":"*","architecture":"*","package":"firefox"}]`)
	pinned := uuid.Must(uuid.NewV7())
	w.exec(t, `INSERT INTO software_assignment (id, organization_id, catalog_entry_id, device_group_id, intent, update_rule, version)
		VALUES ($1, $2, $3, $4, 'required', 'pinned', '120.0-1')`, pinned, w.org, entry, group)
	user := uuid.Must(uuid.NewV7())
	w.exec(t, "INSERT INTO app_user (id, organization_id, authentik_pk, username, source) VALUES ($1, $2, 'pk-owner', 'owner@c.test', 'local')", user, w.org)
	w.exec(t, "INSERT INTO device_owner (organization_id, device_id, user_id) VALUES ($1, $2, $3)", w.org, owned, user)
	byUser := uuid.Must(uuid.NewV7())
	w.exec(t, `INSERT INTO software_assignment (id, organization_id, catalog_entry_id, user_id, intent, update_rule, version)
		VALUES ($1, $2, $3, $4, 'required', 'pinned', '101.0')`, byUser, w.org, entry, user)
	w.exec(t, `INSERT INTO software_assignment (id, organization_id, catalog_entry_id, intent) VALUES ($1, $2, $3, 'required')`,
		uuid.Must(uuid.NewV7()), w.org, entry)

	r, err := w.report.Report(roleCtx(w.org, principal.RoleOrgOperator), app.PatchComplianceQuery{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[uuid.UUID]patchsla.CatalogRow{}
	for _, c := range r.Catalog {
		got[c.AssignmentID] = c
	}
	if len(r.Catalog) != 2 || got[pinned].DevicesBehind != 1 || got[pinned].RequiredVersion != "120.0-1" || got[pinned].Entry != "Firefox" ||
		got[byUser].DevicesBehind != 1 {
		t.Errorf("catalog %+v", r.Catalog)
	}
}

// TestPatchComplianceReadAudit (plan M13c decision 18): the view is recorded once per actor and UTC day while
// inventory_view_recorded is on, never while it is off; every export is recorded, its CSV has a row for every breach.
func TestPatchComplianceReadAudit(t *testing.T) {
	w := newPatchWorld(t)
	fixed := "1.1"
	for i, host := range []string{"a", "b", "c"} {
		dev := w.inventoried(t, w.org, host)
		w.vuln(t, w.org, dev, "CVE-2026-000"+string(rune('1'+i)), "critical", &fixed, 20)
		w.vuln(t, w.org, dev, "CVE-2026-0100", "high", &fixed, 40)
	}
	auditor := as(w.org, principal.Principal{ID: uuid.Must(uuid.NewV7()), Display: "auditor", Role: principal.RoleOrgAuditor})

	w.switches(t, w.org, false, false)
	if _, err := w.report.Report(auditor, app.PatchComplianceQuery{}); err != nil {
		t.Fatal(err)
	}
	if ev := w.events(t, w.org, audit.CodePatchComplianceViewed); len(ev) != 0 {
		t.Fatalf("recorded while off: %+v", ev)
	}
	w.switches(t, w.org, false, true)
	for range 2 {
		if _, err := w.report.Report(auditor, app.PatchComplianceQuery{}); err != nil {
			t.Fatal(err)
		}
	}
	ev := w.events(t, w.org, audit.CodePatchComplianceViewed)
	if len(ev) != 1 || ev[0].Outcome != audit.OutcomeSuccess || ev[0].Params["window_start"] != "2026-11-14T00:00:00Z" {
		t.Fatalf("views %+v", ev)
	}
	w.now = w.now.Add(24 * time.Hour)
	if _, err := w.report.Report(auditor, app.PatchComplianceQuery{}); err != nil {
		t.Fatal(err)
	}
	if ev := w.events(t, w.org, audit.CodePatchComplianceViewed); len(ev) != 2 {
		t.Fatalf("next day: %d views", len(ev))
	}

	operator := roleCtx(w.org, principal.RoleOrgOperator)
	e, err := w.report.Export(operator, app.PatchComplianceQuery{}, app.AccessReviewCSV)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(string(e.CSV))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	breaches := 0
	for _, r := range rows[1:] {
		if r[0] == "breach" {
			breaches++
		}
	}
	if breaches != 6 || !strings.HasPrefix(e.Filename, "paddock-patch-compliance-") || !strings.HasSuffix(e.Filename, ".csv") {
		t.Errorf("csv %d breach rows, filename %s", breaches, e.Filename)
	}
	if _, err := w.report.Export(operator, app.PatchComplianceQuery{}, "xml"); !errors.Is(err, problem.InvalidRequest) {
		t.Errorf("format xml = %v", err)
	}
	if _, err := w.report.Export(roleCtx(w.org, principal.RolePlatform), app.PatchComplianceQuery{}, app.AccessReviewJSON); !errors.Is(err, problem.Forbidden) {
		t.Errorf("platform role = %v", err)
	}
	ev = w.events(t, w.org, audit.CodePatchComplianceExported)
	if len(ev) != 3 || ev[0].Outcome != audit.OutcomeSuccess || ev[0].Params["format"] != "csv" ||
		ev[1].Outcome != audit.OutcomeFailure || ev[2].Outcome != audit.OutcomeDenied {
		t.Fatalf("exports %+v", ev)
	}
}

// TestPatchSLAAttention (plan M13c decision 18): a device with a finding open longer than its severity's SLA has the
// attention condition patch_sla_breached with the number of such findings; the API role reads it for its own
// organization only.
func TestPatchSLAAttention(t *testing.T) {
	w := newPatchWorld(t)
	w.now = time.Now().UTC()
	fixed := "2.0"
	breached, fresh := w.device(t, w.org, "breached"), w.device(t, w.org, "fresh")
	w.vuln(t, w.org, breached, "CVE-2026-0001", "critical", &fixed, 9)
	w.vuln(t, w.org, breached, "CVE-2026-0002", "high", &fixed, 31)
	w.vuln(t, w.org, breached, "CVE-2026-0003", "low", &fixed, 900)
	w.vuln(t, w.org, fresh, "CVE-2026-0001", "critical", &fixed, 6)
	other := w.otherOrg(t)
	foreign := w.device(t, other, "foreign")
	w.vuln(t, other, foreign, "CVE-2026-0001", "critical", &fixed, 30)

	attention := app.NewAttention(w.reportPool(t))
	res, err := attention.List(roleCtx(w.org, principal.RoleOrgAuditor), app.AttentionQuery{
		Page: app.ListPage{Sort: "kind", Limit: 10}, Kinds: []string{"patch_sla_breached"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Count != 1 || len(res.Items) != 1 || res.Items[0].DeviceID != breached || res.Items[0].Detail != "2" {
		t.Fatalf("attention %+v", res)
	}
	if want := w.now.Add(-9 * 24 * time.Hour).Add(8 * 24 * time.Hour); res.Items[0].Since.Sub(want).Abs() > time.Minute {
		t.Errorf("since %s, want about %s", res.Items[0].Since, want)
	}
}

func (w *patchWorld) reportPool(t *testing.T) *db.OrgPool {
	t.Helper()
	pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TestVulnerabilitySLASummary (plan M13c decision 18): the worker records one vulnerability.sla_breached per UTC day
// with the breached findings per severity and the devices, nothing while no finding breaches, and the next day again.
func TestVulnerabilitySLASummary(t *testing.T) {
	h := newSummaryHarness(t)
	env := pgtest.SharedPaddock(t)
	worker, err := db.NewOrgPool(context.Background(), env.Worker, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(worker.Close)
	platform, err := db.NewPlatformPool(context.Background(), env.Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	summary := app.NewVulnerabilitySLASummary(app.NewActionRunner(worker, platform, httpx.RequestID))
	loads := summary.CountLoads()
	now := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	record := func(at time.Time) {
		t.Helper()
		ctx := httpx.WithRequestID(principal.With(context.Background(),
			principal.Principal{Kind: principal.KindSystem, Display: "worker", OrganizationID: h.org}), "test")
		if err := summary.Record(ctx, at); err != nil {
			t.Fatal(err)
		}
	}
	events := func() []map[string]any {
		t.Helper()
		rows, err := h.super.Query(context.Background(),
			"SELECT params FROM action WHERE organization_id = $1 AND code = 'vulnerability.sla_breached' ORDER BY started_at", h.org)
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
	a, b := h.device(t), h.device(t)
	for _, d := range []uuid.UUID{a, b} {
		h.exec(t, "INSERT INTO device_inventory_ref (device_id, organization_id, external_id) VALUES ($1, $2, $3)", d, h.org, "f-"+d.String())
	}
	finding := func(dev uuid.UUID, cve, severity string, days int) {
		h.exec(t, `INSERT INTO vulnerability_finding (device_id, organization_id, cve, software_name, software_version, severity,
			fixed_version, first_seen_at) VALUES ($1, $2, $3, 'pkg', '1', $4, '2', $5)`, dev, h.org, cve, severity,
			now.Add(-time.Duration(days)*24*time.Hour))
	}
	finding(a, "CVE-2026-0001", "critical", 3)
	record(now)
	if ev := events(); len(ev) != 0 {
		t.Fatalf("without a breach: %+v", ev)
	}
	finding(a, "CVE-2026-0002", "critical", 8)
	finding(b, "CVE-2026-0002", "critical", 8)
	finding(b, "CVE-2026-0003", "high", 31)
	record(now)
	if n := loads(); n != 2 {
		t.Fatalf("%d findings loads before the claim, want 2", n)
	}
	record(now.Add(time.Hour))
	if n := loads(); n != 2 {
		t.Fatalf("%d findings loads, want 2: a claimed day must not read the findings again", n)
	}
	ev := events()
	if len(ev) != 1 || ev[0]["critical"] != float64(2) || ev[0]["high"] != float64(1) || ev[0]["medium"] != float64(0) ||
		ev[0]["low"] != float64(0) || ev[0]["devices"] != float64(2) {
		t.Fatalf("events %+v", ev)
	}
	record(now.Add(24 * time.Hour))
	if ev := events(); len(ev) != 2 {
		t.Fatalf("next day: %d events", len(ev))
	}
}
