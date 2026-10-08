package acceptance

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// osvFixtureAlias is the host name under which the development worker downloads Ubuntu's OSV data
// (compose.dev.yaml: http://osv-fixture:8080/Ubuntu/all.zip).
const osvFixtureAlias = "osv-fixture"

// startOSVFixture serves dir on the stack's network cp as http://osv-fixture:8080/ with Caddy's file server, which
// answers like the OSV bucket: 200 with an ETag, 304 for a matching If-None-Match, 404 for a missing file. Fixture
// containers of an earlier run are removed first.
func startOSVFixture(t *testing.T, dir string) {
	t.Helper()
	ctx := testContext(t, 2*time.Minute)
	image, err := stack.Image("CADDY_IMAGE")
	if err != nil {
		t.Fatal(err)
	}
	const label = "paddock.osv-fixture"
	if old, err := stack.Docker(ctx, nil, "ps", "-aq", "--filter", "label="+label); err == nil && strings.TrimSpace(old) != "" {
		_, _ = stack.Docker(ctx, nil, append([]string{"rm", "-f"}, strings.Fields(old)...)...)
	}
	name := "paddock-osv-fixture-" + uniqueSuffix()
	if out, err := stack.Docker(ctx, nil, "run", "-d", "--rm", "--name", name, "--label", label, "--network", "paddock_cp",
		"--network-alias", osvFixtureAlias, "-v", dir+":/srv:ro", image, "caddy", "file-server", "--root", "/srv",
		"--listen", ":8080"); err != nil {
		t.Fatalf("start the OSV fixture server: %v: %s", err, out)
	}
	t.Cleanup(func() { _, _ = stack.Docker(context.Background(), nil, "rm", "-f", name) })
}

// osvRecord is an OSV record (schema 1.7) of a CVE as Ubuntu's feed has it, for a source package that builds binary
// in 24.04 and 26.04 with a fix in each.
func osvRecord(cve, source, binary string) map[string]any {
	affected := func(release, fixed string) map[string]any {
		return map[string]any{
			"package": map[string]any{"name": source, "ecosystem": "Ubuntu:" + release + ":LTS"},
			"ranges":  []any{map[string]any{"type": "ECOSYSTEM", "events": []any{map[string]any{"introduced": "0"}, map[string]any{"fixed": fixed}}}},
			"ecosystem_specific": map[string]any{"binaries": []any{
				map[string]any{"binary_name": binary, "binary_version": fixed},
				map[string]any{"binary_name": source, "binary_version": fixed},
			}},
		}
	}
	return map[string]any{
		"id": "UBUNTU-" + cve, "schema_version": "1.7.3", "modified": "2026-10-01T00:00:00Z", "upstream": []string{cve},
		"severity": []any{
			map[string]any{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
			map[string]any{"type": "Ubuntu", "score": "high"},
		},
		"affected": []any{
			affected("22.04", "1.0-1ubuntu0.22.04.1"), affected("24.04", "1.0-1ubuntu0.24.04.1"),
			affected("26.04", "1.0-1ubuntu0.26.04.1"),
			map[string]any{"package": map[string]any{"name": source, "ecosystem": "Ubuntu:Pro:24.04:LTS"}},
		},
	}
}

func osvZip(t *testing.T, records ...map[string]any) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, r := range records {
		fw, err := w.Create(r["id"].(string) + ".json")
		if err == nil {
			err = json.NewEncoder(fw).Encode(r)
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

// waitOSV polls cond every interval until it holds or timeout passes.
func waitOSV(t *testing.T, what string, timeout, interval time.Duration, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(timeout); !cond(); time.Sleep(interval) {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %s", what, timeout)
		}
	}
}

// osvState is paddock-worker's download state.
type osvState struct {
	dataVersion int64
	lastSuccess time.Time
	lastError   string
}

func readOSVState(t *testing.T, conn *pgx.Conn) osvState {
	t.Helper()
	var s osvState
	var success *time.Time
	if err := conn.QueryRow(testContext(t, time.Minute),
		"SELECT data_version, last_success_at, last_error FROM osv_sync_state WHERE source = 'ubuntu'").
		Scan(&s.dataVersion, &success, &s.lastError); err != nil {
		t.Fatal(err)
	}
	if success != nil {
		s.lastSuccess = *success
	}
	return s
}

// TestOSVO1Severity is gate O1 of plan M5c (AC1, AC2): with a fixture OSV zip served like the OSV bucket, a finding
// of a binary package (as Fleet reports it) gets Ubuntu's priority and the fixed version of its device's release,
// 24.04 and 26.04 differing; with a 304 answer nothing is imported again; with a failing download the data stays.
func TestOSVO1Severity(t *testing.T) {
	alice := login(t, env.Alice)
	suffix := uniqueSuffix()
	source, binary, cve := "paddock-o1-"+suffix, "libpaddock-o1-"+suffix, uniqueCVE()
	noble := activeDevice(t, alice, "", "osv-o1-noble-"+suffix)
	resolute := activeDevice(t, alice, "", "osv-o1-resolute-"+suffix)

	dsn, err := stack.PaddockOwnerDSN()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.Connect(testContext(t, time.Minute), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	// The device's OS as the inventory sync stores it from Fleet, and an F4-style finding of the binary package.
	for id, os := range map[string]string{noble.DeviceID: "Ubuntu 24.04.3 LTS", resolute.DeviceID: "Ubuntu 26.04 LTS"} {
		if _, err := conn.Exec(testContext(t, time.Minute), `INSERT INTO device_inventory_ref (device_id, organization_id,
			external_id, os_version) SELECT id, organization_id, $2, $3 FROM device WHERE id = $1`, id, "o1-"+id, os); err != nil {
			t.Fatal(err)
		}
		storeInventory(t, id, [][2]string{{binary, "1.0-1"}}, [][4]string{{cve, binary, "1.0-1", ""}})
	}

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "Ubuntu", "all.zip")
	if err := os.MkdirAll(filepath.Dir(zipPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil { // Caddy reads it as another user
		t.Fatal(err)
	}
	if err := os.WriteFile(zipPath, osvZip(t, osvRecord(cve, source, binary)), 0o644); err != nil { //nolint:gosec // public test data
		t.Fatal(err)
	}
	startOSVFixture(t, dir)
	before := readOSVState(t, conn)

	finding := func(device string) map[string]any {
		t.Helper()
		page := listInventory(t, alice, "/api/v1/devices/"+device+"/vulnerabilities?q="+cve)
		if page.Total != 1 {
			t.Fatalf("device %s: %d findings of %s", device, page.Total, cve)
		}
		return page.Items[0]
	}
	start := time.Now()
	for deadline := start.Add(3 * time.Minute); ; time.Sleep(5 * time.Second) {
		if f := finding(noble.DeviceID); f["severity"] == "high" {
			t.Logf("finding enriched %s after the fixture server started", time.Since(start).Round(time.Second))
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no enrichment within 3 minutes; download state %+v", readOSVState(t, conn))
		}
	}
	const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	for device, fixed := range map[string]string{noble.DeviceID: "1.0-1ubuntu0.24.04.1", resolute.DeviceID: "1.0-1ubuntu0.26.04.1"} {
		if f := finding(device); f["severity"] != "high" || f["fixed_version"] != fixed || f["cvss_vector"] != vector || f["cvss_score"] != nil {
			t.Errorf("device %s: finding %+v, want high, fixed in %s", device, f, fixed)
		}
	}
	if v := listInventory(t, alice, "/api/v1/vulnerabilities?severity=high&q="+cve); v.Total != 1 || v.Items[0]["cvss_vector"] != vector {
		t.Errorf("organization's vulnerabilities %+v", v)
	}
	imported := readOSVState(t, conn)
	if imported.dataVersion <= before.dataVersion || imported.lastError != "" {
		t.Fatalf("state after the import %+v (before %+v)", imported, before)
	}

	t.Run("304 imports nothing", func(t *testing.T) {
		// Two more successful attempts: the file is unchanged, so the worker sent its ETag and got 304.
		var st osvState
		waitOSV(t, "two downloads answered with 304", 2*time.Minute, 5*time.Second, func() bool {
			st = readOSVState(t, conn)
			return st.lastSuccess.Sub(imported.lastSuccess) >= 50*time.Second || st.lastError != ""
		})
		if st.dataVersion != imported.dataVersion || st.lastError != "" {
			t.Errorf("after 304: state %+v (imported %+v)", st, imported)
		}
		if f := finding(noble.DeviceID); f["severity"] != "high" || f["fixed_version"] != "1.0-1ubuntu0.24.04.1" {
			t.Errorf("finding after 304 %+v", f)
		}
	})

	t.Run("failing download keeps the data", func(t *testing.T) {
		if err := os.Remove(zipPath); err != nil {
			t.Fatal(err)
		}
		waitOSV(t, "a failed download", 2*time.Minute, 5*time.Second, func() bool {
			return strings.Contains(readOSVState(t, conn).lastError, "HTTP 404")
		})
		if st := readOSVState(t, conn); st.dataVersion != imported.dataVersion {
			t.Errorf("failed download changed the data: %+v", st)
		}
		var rows int
		if err := conn.QueryRow(testContext(t, time.Minute), "SELECT count(*) FROM osv_ubuntu WHERE cve = $1", cve).Scan(&rows); err != nil || rows != 2 {
			t.Errorf("%d rows of %s after the failed download (want 24.04 and 26.04), %v", rows, cve, err)
		}
		if f := finding(resolute.DeviceID); f["severity"] != "high" || f["fixed_version"] != "1.0-1ubuntu0.26.04.1" {
			t.Errorf("finding after the failed download %+v", f)
		}
	})
}
