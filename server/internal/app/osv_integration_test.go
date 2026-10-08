package app_test

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/osv"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

type osvHarness struct {
	osv    *app.OSV
	worker *db.OrgPool
	super  *pgx.Conn
}

func newOSVHarness(t *testing.T) osvHarness {
	t.Helper()
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	platform, err := db.NewPlatformPool(ctx, env.Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	worker, err := db.NewOrgPool(ctx, env.Worker, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(worker.Close)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	runner := app.NewActionRunner(worker, platform, httpx.RequestID)
	return osvHarness{osv: app.NewOSV(runner, worker, platform), worker: worker, super: super}
}

func (h osvHarness) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := h.super.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// osvZip is a zip of the real OSV records of server/internal/osv/testdata.
func osvZip(t *testing.T) []byte {
	t.Helper()
	files, err := filepath.Glob("../osv/testdata/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("osv testdata: %v", err)
	}
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		fw, err := w.Create(filepath.Base(f))
		if err == nil {
			_, err = fw.Write(body)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func systemPlatform() context.Context {
	return principal.With(context.Background(), principal.Principal{Kind: principal.KindSystem, Display: "worker"})
}

func readZip(data []byte) func(fn func(osv.Entry) error) (osv.Stats, error) {
	return func(fn func(osv.Entry) error) (osv.Stats, error) { return osv.Read(bytes.NewReader(data), fn) }
}

// TestOSVImport (plan M5c decision 1, AC2): an import replaces the data in one transaction and records the ETag; a
// failing or empty read leaves the previous data and state; 304 and failures are recorded.
func TestOSVImport(t *testing.T) {
	h := newOSVHarness(t)
	ctx := systemPlatform()
	before, err := h.osv.State(ctx)
	if err != nil {
		t.Fatal(err)
	}

	st, err := h.osv.Import(ctx, `"etag-1"`, readZip(osvZip(t)))
	if err != nil || st.Entries != 8 {
		t.Fatalf("import: %+v %v", st, err)
	}
	if n := h.count(t, "SELECT count(*) FROM osv_ubuntu"); n != 8 {
		t.Errorf("osv_ubuntu has %d rows, want 8", n)
	}
	if n := h.count(t, `SELECT count(*) FROM osv_ubuntu WHERE cve = 'CVE-2026-11386' AND release = '26.04'
		AND package = 'ubuntu-advantage-tools' AND priority = 'high' AND fixed_version = '37.2ubuntu0.1'
		AND cvss_vector = 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H'`); n != 1 {
		t.Error("CVE-2026-11386 in 26.04 missing")
	}
	if n := h.count(t, "SELECT count(*) FROM osv_ubuntu WHERE fixed_version IS NULL AND cve = 'CVE-2008-7320' AND priority = ''"); n != 1 {
		t.Error("CVE-2008-7320 without fix and priority missing")
	}
	// Binary packages of other names than their source package, per release: libcg and libcggl in both, six of
	// openssh in 24.04, four of ubuntu-advantage-tools in both.
	if n := h.count(t, "SELECT count(*) FROM osv_ubuntu_binary"); n != 2*2+6+2*4 {
		t.Errorf("osv_ubuntu_binary has %d rows, want 18", n)
	}
	if n := h.count(t, "SELECT count(*) FROM osv_ubuntu_binary WHERE release = '24.04' AND binary_name = 'openssh-client' AND package = 'openssh'"); n != 1 {
		t.Error("openssh-client → openssh missing")
	}
	after, err := h.osv.State(ctx)
	if err != nil || after.ETag != `"etag-1"` || after.DataVersion != before.DataVersion+1 || after.Entries != 8 ||
		after.LastSuccessAt == nil || after.LastError != "" {
		t.Fatalf("state %+v %v", after, err)
	}

	t.Run("failed read keeps the data", func(t *testing.T) {
		data := osvZip(t)
		if _, err := h.osv.Import(ctx, `"etag-2"`, readZip(data[:len(data)-200])); err == nil {
			t.Fatal("truncated zip imported")
		}
		if _, err := h.osv.Import(ctx, `"etag-3"`, func(func(osv.Entry) error) (osv.Stats, error) { return osv.Stats{}, nil }); err == nil {
			t.Fatal("empty import accepted")
		}
		if n := h.count(t, "SELECT count(*) FROM osv_ubuntu"); n != 8 {
			t.Errorf("osv_ubuntu has %d rows after failed imports", n)
		}
		if st, _ := h.osv.State(ctx); st.ETag != `"etag-1"` || st.DataVersion != after.DataVersion {
			t.Errorf("state changed by failed imports: %+v", st)
		}
	})

	t.Run("failure and 304", func(t *testing.T) {
		if err := h.osv.Failed(ctx, errors.New("osv: download: HTTP 503")); err != nil {
			t.Fatal(err)
		}
		st, _ := h.osv.State(ctx)
		if st.LastError != "osv: download: HTTP 503" || st.LastAttemptAt == nil || !st.LastSuccessAt.Equal(*after.LastSuccessAt) {
			t.Errorf("after failure %+v", st)
		}
		if err := h.osv.NotModified(ctx); err != nil {
			t.Fatal(err)
		}
		st, _ = h.osv.State(ctx)
		if st.LastError != "" || !st.LastSuccessAt.After(*after.LastSuccessAt) || st.DataVersion != after.DataVersion || st.ETag != `"etag-1"` {
			t.Errorf("after 304 %+v", st)
		}
	})

	t.Run("stale alert once", func(t *testing.T) {
		alerts := func() int { return h.count(t, "SELECT count(*) FROM action WHERE code = 'platform.osv_stale'") }
		start := alerts()
		if stale, err := h.osv.AlertIfStale(ctx, time.Now().Add(71*time.Hour)); err != nil || stale {
			t.Fatalf("after 71 h: stale %v %v", stale, err)
		}
		for range 2 {
			if stale, err := h.osv.AlertIfStale(ctx, time.Now().Add(73*time.Hour)); err != nil || !stale {
				t.Fatalf("after 73 h: stale %v %v", stale, err)
			}
		}
		if n := alerts() - start; n != 1 {
			t.Fatalf("%d platform.osv_stale events, want 1", n)
		}
		if n := h.count(t, `SELECT count(*) FROM action WHERE code = 'platform.osv_stale' AND outcome = 'success'
			AND organization_id = '00000000-0000-0000-0000-000000000000' AND params ? 'last_success_at'`); n < 1 {
			t.Error("platform.osv_stale not in the platform pseudo-organization with last_success_at")
		}
		// A success ends the stale period: the next one is alerted again.
		if err := h.osv.NotModified(ctx); err != nil {
			t.Fatal(err)
		}
		if st, _ := h.osv.State(ctx); st.StaleAlerted {
			t.Error("stale alert not cleared by a success")
		}
		if _, err := h.osv.AlertIfStale(ctx, time.Now().Add(73*time.Hour)); err != nil {
			t.Fatal(err)
		}
		if n := alerts() - start; n != 2 {
			t.Errorf("%d platform.osv_stale events, want 2", n)
		}
	})
}

// TestOSVEnrich (plan M5c decision 2, AC1): findings get Ubuntu's severity, fixed version and CVSS vector for the
// release of their device, by source package or by the binary package Fleet reports; Ubuntu's priority negligible is
// low; a finding without priority keeps Fleet's values; devices of other releases or without OS stay unchanged.
// The inventory sync enriches a host's findings in the transaction that stores them.
func TestOSVEnrich(t *testing.T) {
	h := newOSVHarness(t)
	ctx := context.Background()
	if _, err := h.osv.Import(systemPlatform(), `"enrich"`, readZip(osvZip(t))); err != nil {
		t.Fatal(err)
	}
	inv := newInventoryHarness(t)
	org, noble := inv.device(t, uuid.Nil, uuid.NewString(), "active")
	_, resolute := inv.device(t, org, uuid.NewString(), "active")
	_, jammy := inv.device(t, org, uuid.NewString(), "active")
	_, unknown := inv.device(t, org, uuid.NewString(), "active")
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := h.super.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	for dev, os := range map[uuid.UUID]string{noble: "Ubuntu 24.04.3 LTS", resolute: "Ubuntu 26.04 LTS", jammy: "Ubuntu 22.04.5 LTS"} {
		exec("INSERT INTO device_inventory_ref (device_id, organization_id, external_id, os_version) VALUES ($1, $2, $3, $4)",
			dev, org, uuid.NewString(), os)
	}
	finding := func(dev uuid.UUID, cve, pkg, severity string) {
		exec(`INSERT INTO vulnerability_finding (device_id, organization_id, cve, software_name, software_version, severity, fixed_version,
			fleet_severity, fleet_fixed_version)
			VALUES ($1, $2, $3, $4, '1.0', NULLIF($5, ''), CASE WHEN $5 = '' THEN NULL ELSE 'fleet-fix' END,
			NULLIF($5, ''), CASE WHEN $5 = '' THEN NULL ELSE 'fleet-fix' END)`, dev, org, cve, pkg, severity)
	}
	for _, dev := range []uuid.UUID{noble, resolute, jammy, unknown} {
		finding(dev, "CVE-2026-11386", "ubuntu-pro-client", "")
	}
	finding(noble, "CVE-2024-6387", "openssh-client", "")
	finding(noble, "CVE-2008-5144", "libcg", "")
	finding(noble, "CVE-2014-3495", "duplicity", "")
	finding(noble, "CVE-2008-7320", "seahorse", "medium")
	finding(noble, "CVE-2099-0001", "paddock-unknown", "")

	n, err := h.osv.Enrich(systemOrg(org))
	if err != nil || n != 6 {
		t.Fatalf("enriched %d, %v; want 6", n, err)
	}
	type row struct{ severity, fixed, vector string }
	get := func(dev uuid.UUID, cve string) row {
		t.Helper()
		var r row
		if err := h.super.QueryRow(ctx, `SELECT coalesce(severity, ''), coalesce(fixed_version, ''), coalesce(cvss_vector, '')
			FROM vulnerability_finding WHERE device_id = $1 AND cve = $2`, dev, cve).Scan(&r.severity, &r.fixed, &r.vector); err != nil {
			t.Fatal(err)
		}
		return r
	}
	const uaVector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H"
	for _, c := range []struct {
		name string
		dev  uuid.UUID
		cve  string
		want row
	}{
		{"binary package in 24.04", noble, "CVE-2026-11386", row{"high", "37.2ubuntu~24.04.1", uaVector}},
		{"binary package in 26.04", resolute, "CVE-2026-11386", row{"high", "37.2ubuntu0.1", uaVector}},
		{"release without data", jammy, "CVE-2026-11386", row{}},
		{"device without OS", unknown, "CVE-2026-11386", row{}},
		{"openssh-client", noble, "CVE-2024-6387", row{"high", "1:9.6p1-3ubuntu13.3", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
		{"negligible is low", noble, "CVE-2008-5144", row{"low", "", ""}},
		{"priority of the package", noble, "CVE-2014-3495", row{"low", "", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}},
		{"no priority keeps Fleet's", noble, "CVE-2008-7320", row{"medium", "fleet-fix", "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
		{"CVE unknown to Ubuntu", noble, "CVE-2099-0001", row{}},
	} {
		if got := get(c.dev, c.cve); got != c.want {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
	if n, err := h.osv.Enrich(systemOrg(org)); err != nil || n != 0 {
		t.Errorf("second enrichment changed %d, %v", n, err)
	}

	t.Run("inventory sync", func(t *testing.T) {
		_, dev := inv.device(t, org, uuid.NewString(), "active")
		err := inv.sync.StoreHost(systemOrg(org), dev, "77", ports.HostInventory{OSVersion: "Ubuntu 26.04 LTS",
			Software: []ports.SoftwarePackage{{Name: "ubuntu-pro-client", Version: "37.1", Source: "deb_packages",
				Vulnerabilities: []ports.Vulnerability{{CVE: "CVE-2026-11386"}}}}})
		if err != nil {
			t.Fatal(err)
		}
		if got := get(dev, "CVE-2026-11386"); got != (row{"high", "37.2ubuntu0.1", uaVector}) {
			t.Errorf("stored finding %+v", got)
		}
	})
	t.Run("lists by severity", func(t *testing.T) {
		inventory := app.NewInventory(h.worker)
		auditor := principal.With(context.Background(), principal.Principal{Kind: principal.KindAdmin, Display: "auditor",
			Role: principal.RoleOrgAuditor, OrganizationID: org})
		order := func(sort string) []string {
			t.Helper()
			res, err := inventory.DeviceVulnerabilities(auditor, noble, app.VulnerabilityQuery{Page: app.ListPage{Sort: sort, Limit: 10}})
			if err != nil {
				t.Fatal(err)
			}
			var out []string
			for _, r := range res.Items {
				out = append(out, r.Severity+" "+r.Cve)
			}
			return out
		}
		if got, want := order("-severity"), []string{"high CVE-2024-6387", "high CVE-2026-11386", "medium CVE-2008-7320",
			"low CVE-2008-5144", "low CVE-2014-3495", "unknown CVE-2099-0001"}; !slices.Equal(got, want) {
			t.Errorf("-severity: %v, want %v", got, want)
		}
		if got, want := order("severity"), []string{"low CVE-2008-5144", "low CVE-2014-3495", "medium CVE-2008-7320",
			"high CVE-2024-6387", "high CVE-2026-11386", "unknown CVE-2099-0001"}; !slices.Equal(got, want) {
			t.Errorf("severity: %v, want %v", got, want)
		}
		res, err := inventory.Vulnerabilities(auditor, app.VulnerabilityQuery{Page: app.ListPage{Sort: "-severity", Limit: 10},
			Severities: []string{"high"}})
		if err != nil {
			t.Fatal(err)
		}
		// Of CVE-2026-11386's findings (high on 24.04 and 26.04, unknown on 22.04 and without OS) the high one counts.
		if len(res.Items) != 2 || res.Count != 2 || res.Items[1].Cve != "CVE-2026-11386" || res.Items[1].Severity != "high" ||
			res.Items[1].CvssVector == nil || res.Items[1].FixedVersion == nil || res.Items[1].DeviceCount != 5 {
			t.Errorf("high vulnerabilities %+v (count %d)", res.Items, res.Count)
		}
	})
	t.Run("dropped CVE reverts to Fleet's values", func(t *testing.T) {
		finding(noble, "CVE-2026-11386", "paddock-dropped", "medium")
		exec(`UPDATE vulnerability_finding SET severity = 'critical', fixed_version = 'osv-fix', cvss_vector = 'CVSS:3.1/AV:N'
			WHERE device_id = $1 AND software_name = 'paddock-dropped'`, noble)
		if _, err := h.osv.Enrich(systemOrg(org)); err != nil {
			t.Fatal(err)
		}
		var severity, fixed string
		var vector *string
		if err := h.super.QueryRow(ctx, `SELECT severity, fixed_version, cvss_vector FROM vulnerability_finding
			WHERE device_id = $1 AND software_name = 'paddock-dropped'`, noble).Scan(&severity, &fixed, &vector); err != nil {
			t.Fatal(err)
		}
		if severity != "medium" || fixed != "fleet-fix" || vector != nil {
			t.Errorf("finding without Ubuntu data: %q %q %v, want Fleet's medium, fleet-fix and no vector", severity, fixed, vector)
		}
	})
	t.Run("isolation", func(t *testing.T) {
		other, foreign := inv.device(t, uuid.Nil, uuid.NewString(), "active")
		exec("INSERT INTO device_inventory_ref (device_id, organization_id, external_id, os_version) VALUES ($1, $2, $3, 'Ubuntu 24.04 LTS')",
			foreign, other, uuid.NewString())
		exec(`INSERT INTO vulnerability_finding (device_id, organization_id, cve, software_name, software_version)
			VALUES ($1, $2, 'CVE-2024-6387', 'openssh-server', '1.0')`, foreign, other)
		if _, err := h.osv.Enrich(systemOrg(org)); err != nil {
			t.Fatal(err)
		}
		if got := get(foreign, "CVE-2024-6387"); got != (row{}) {
			t.Errorf("enriching %s changed a finding of %s: %+v", org, other, got)
		}
	})
}

func systemOrg(org uuid.UUID) context.Context {
	return principal.With(context.Background(), principal.Principal{Kind: principal.KindSystem, Display: "worker", OrganizationID: org})
}

// TestOSVImportFeed imports a downloaded bulk zip of the real feed (PADDOCK_OSV_ZIP) and enriches a finding with it.
func TestOSVImportFeed(t *testing.T) {
	path := os.Getenv("PADDOCK_OSV_ZIP")
	if path == "" {
		t.Skip("PADDOCK_OSV_ZIP not set")
	}
	h := newOSVHarness(t)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	start := time.Now()
	st, err := h.osv.Import(systemPlatform(), "", func(fn func(osv.Entry) error) (osv.Stats, error) { return osv.Read(f, fn) })
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("imported %+v in %s; %d binary mappings", st, time.Since(start).Round(time.Second),
		h.count(t, "SELECT count(*) FROM osv_ubuntu_binary"))
	inv := newInventoryHarness(t)
	org, dev := inv.device(t, uuid.Nil, uuid.NewString(), "active")
	if err := inv.sync.StoreHost(systemOrg(org), dev, "1", ports.HostInventory{OSVersion: "Ubuntu 24.04.3 LTS",
		Software: []ports.SoftwarePackage{{Name: "openssh-server", Version: "1:9.6p1-3ubuntu13", Source: "deb_packages",
			Vulnerabilities: []ports.Vulnerability{{CVE: "CVE-2024-6387"}}}}}); err != nil {
		t.Fatal(err)
	}
	if n := h.count(t, `SELECT count(*) FROM vulnerability_finding WHERE device_id = $1 AND severity = 'high'
		AND fixed_version = '1:9.6p1-3ubuntu13.3'`, dev); n != 1 {
		t.Error("CVE-2024-6387 of openssh-server not enriched")
	}
}

// TestOSVImportFileAudited (plan M5c decision 3): an operator's import is recorded as platform.osv_imported in the
// platform pseudo-organization with the counts and the data version, a failed one as failure.
func TestOSVImportFileAudited(t *testing.T) {
	h := newOSVHarness(t)
	ctx := systemPlatform()
	if _, err := h.osv.ImportFile(ctx, readZip(osvZip(t))); err != nil {
		t.Fatal(err)
	}
	st, err := h.osv.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n := h.count(t, `SELECT count(*) FROM action WHERE code = 'platform.osv_imported' AND outcome = 'success'
		AND organization_id = '00000000-0000-0000-0000-000000000000' AND (params ->> 'records')::int = 6
		AND (params ->> 'entries')::int = 8 AND (params ->> 'data_version')::bigint = $1`, st.DataVersion); n != 1 {
		t.Errorf("%d platform.osv_imported success events with the counts and data version %d", n, st.DataVersion)
	}
	if _, err := h.osv.ImportFile(ctx, readZip([]byte("not a zip"))); err == nil {
		t.Fatal("a damaged file was imported")
	}
	if n := h.count(t, "SELECT count(*) FROM action WHERE code = 'platform.osv_imported' AND outcome = 'failure'"); n < 1 {
		t.Error("no platform.osv_imported failure event")
	}
}
