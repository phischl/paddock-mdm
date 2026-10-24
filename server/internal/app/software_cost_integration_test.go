package app_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// TestSoftwareVulnerabilityProbe (PDK-406, migration 00067): the software list and its count ask per software group
// (or package row) whether the organization has a finding for that name and version. Without an index on the
// finding's software, that probe was a sequential scan of vulnerability_finding per group: about a minute per page at
// 3 000 groups and 200 000 findings, beyond the API client's timeout. The test pins the plan property, not timings:
// in the executed plans of ListSoftware and CountSoftware, for every documented sort, with and without
// has_vulnerabilities and in custom and generic plans, no node scans vulnerability_finding sequentially more than
// once. Everything runs in one transaction that is rolled back.
func TestSoftwareVulnerabilityProbe(t *testing.T) {
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	tx, err := super.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	org := uuid.Must(uuid.NewV7())
	exec("INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'O', 'active')", org, "o"+org.String()[24:])
	exec(`INSERT INTO device (id, organization_id, hostname, state)
		SELECT gen_random_uuid(), $1, 'h' || g, 'active' FROM generate_series(1, 10) g`, org)
	exec(`INSERT INTO installed_software (device_id, organization_id, name, version, source)
		SELECT d.id, $1, 'pkg-' || lpad(g::text, 4, '0'), '1.' || g % 7 || '.0', 'deb_packages'
		FROM device d CROSS JOIN generate_series(1, 500) g WHERE d.organization_id = $1`, org)
	// Every 20th group is vulnerable, with 20 CVEs on every device.
	exec(`INSERT INTO vulnerability_finding (device_id, organization_id, cve, software_name, software_version, severity)
		SELECT d.id, $1, 'CVE-2026-' || (g * 100 + c), 'pkg-' || lpad(g::text, 4, '0'), '1.' || g % 7 || '.0', 'high'
		FROM device d CROSS JOIN generate_series(1, 500, 20) g CROSS JOIN generate_series(1, 20) c
		WHERE d.organization_id = $1`, org)
	exec("ANALYZE device, installed_software, vulnerability_finding")
	exec("SET LOCAL ROLE paddock_api")
	exec("SELECT set_config('paddock.org_id', $1, true)", org.String())

	vulnerable := true
	for _, mode := range []string{"force_custom_plan", "force_generic_plan"} {
		exec("SET LOCAL plan_cache_mode = " + mode)
		for _, sort := range []string{"name", "-name", "version", "-version", "device_count", "-device_count"} {
			for _, hv := range []*bool{nil, &vulnerable} {
				rec := &sqlRecorder{Tx: tx}
				q := pgstore.New(rec)
				rows, err := q.ListSoftware(ctx, pgstore.ListSoftwareParams{HasVulnerabilities: hv, Sort: sort, MaxRows: 100})
				if err != nil {
					t.Fatal(err)
				}
				n, err := q.CountSoftware(ctx, pgstore.CountSoftwareParams{HasVulnerabilities: hv, CountLimit: 10001})
				if err != nil {
					t.Fatal(err)
				}
				want, vuln := int64(500), "NULL"
				if hv != nil {
					want, vuln = 25, "true"
				}
				label := mode + " sort=" + sort + " has_vulnerabilities=" + vuln
				if n != want || len(rows) != int(min(want, 100)) {
					t.Fatalf("%s: %d rows, total %d; want %d", label, len(rows), n, want)
				}
				assertNoRepeatedFindingScan(ctx, t, tx, rec.sql[0], "NULL, "+vuln+", '"+sort+"', 0, 100", "ListSoftware "+label)
				assertNoRepeatedFindingScan(ctx, t, tx, rec.sql[1], "NULL, "+vuln+", 10001", "CountSoftware "+label)
			}
		}
	}
}

// assertNoRepeatedFindingScan executes sql as a prepared statement with the literal arguments under EXPLAIN ANALYZE
// and fails if a node scans vulnerability_finding sequentially in more than one loop. A prepared statement, because
// plan_cache_mode only applies to those.
func assertNoRepeatedFindingScan(ctx context.Context, t *testing.T, tx pgx.Tx, sql, args, label string) {
	t.Helper()
	if _, err := tx.Exec(ctx, "PREPARE software_probe AS "+sql); err != nil {
		t.Fatalf("%s: prepare: %v", label, err)
	}
	defer func() { _, _ = tx.Exec(ctx, "DEALLOCATE software_probe") }()
	var raw []byte
	if err := tx.QueryRow(ctx, "EXPLAIN (ANALYZE, FORMAT JSON) EXECUTE software_probe("+args+")").Scan(&raw); err != nil {
		t.Fatalf("%s: explain: %v", label, err)
	}
	var plan []struct {
		Plan map[string]any `json:"Plan"`
	}
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatalf("%s: explain: %v", label, err)
	}
	var walk func(node map[string]any)
	walk = func(node map[string]any) {
		if node["Relation Name"] == "vulnerability_finding" && node["Node Type"] == "Seq Scan" {
			if loops, _ := node["Actual Loops"].(float64); loops > 1 {
				t.Errorf("%s: vulnerability_finding scanned sequentially in %v loops", label, loops)
			}
		}
		children, _ := node["Plans"].([]any)
		for _, c := range children {
			if child, ok := c.(map[string]any); ok {
				walk(child)
			}
		}
	}
	walk(plan[0].Plan)
}
