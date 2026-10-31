package acceptance

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/test/acceptance/devicesim"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// enrollFleetHost enrolls a simulated osquery host whose hardware UUID is uuid (a devicesim device's, so that it maps
// to that device) and reports the deb packages.
func enrollFleetHost(t *testing.T, uuid, hostname string, packages [][2]string) *devicesim.FleetHost {
	t.Helper()
	client, err := env.NewHTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := stack.Secret("fleet_enroll_secret")
	if err != nil {
		t.Fatal(err)
	}
	h, err := devicesim.EnrollFleet(testContext(t, time.Minute), client, stack.FleetURL(), strings.TrimSpace(secret), uuid, hostname, packages)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// enrollFleetHostWithHardware enrolls a simulated osquery host like enrollFleetHost that also reports hardware facts.
func enrollFleetHostWithHardware(t *testing.T, uuid, hostname string, hw devicesim.FleetHardware) *devicesim.FleetHost {
	t.Helper()
	h := enrollFleetHost(t, uuid, hostname, nil)
	h.Hardware = &hw
	return h
}

// fleetHostExists asks Fleet's admin API on the development host whether a host with the hardware UUID is enrolled.
func fleetHostExists(t *testing.T, uuid string) bool {
	t.Helper()
	dir, err := stack.SecretsDir()
	if err != nil {
		t.Fatal(err)
	}
	token, err := os.ReadFile(filepath.Join(dir, "fleet_api_token"))
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(testContext(t, time.Minute), http.MethodGet,
		stack.FleetAdminURL()+"/api/latest/fleet/hosts/identifier/"+url.PathEscape(uuid), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true
	case http.StatusNotFound:
		return false
	}
	t.Fatalf("Fleet host %s: HTTP %d", uuid, resp.StatusCode)
	return false
}

// triggerFleetVulnerabilities runs Fleet's vulnerability job now instead of at its next period, as the development
// administrator through fleetctl in Fleet's network namespace. Fleet refuses a trigger while a run is still pending,
// so callers that trigger repeatedly only log the error.
func triggerFleetVulnerabilities(t *testing.T) error {
	t.Helper()
	ctx := testContext(t, 5*time.Minute)
	image, err := stack.Image("FLEETCTL_IMAGE")
	if err != nil {
		t.Fatal(err)
	}
	password, err := stack.Secret("fleet_admin_password")
	if err != nil {
		t.Fatal(err)
	}
	fleet, err := stack.Compose(ctx, nil, "ps", "-q", "fleet")
	if err != nil || strings.TrimSpace(fleet) == "" {
		t.Fatalf("fleet container: %v %q", err, fleet)
	}
	script := "fleetctl config set --address http://localhost:8080 >/dev/null && " +
		"EMAIL=admin@paddock-mdm.invalid fleetctl login >/dev/null && fleetctl trigger --name vulnerabilities"
	out, err := stack.Docker(ctx, nil, "run", "--rm", "--network", "container:"+strings.TrimSpace(fleet), "-e", "HOME=/tmp",
		"-e", "PASSWORD="+strings.TrimSpace(password), "--entrypoint", "sh", image, "-c", script)
	if err != nil {
		return fmt.Errorf("fleetctl trigger: %w: %s", err, strings.TrimSpace(out))
	}
	t.Logf("fleetctl trigger: %s", strings.TrimSpace(out))
	return nil
}

// fleetRetrigger is how long a gate waits for a triggered run of Fleet's vulnerability job before it triggers again;
// a run takes well under a minute once Fleet has its data.
const fleetRetrigger = 2 * time.Minute

// fleetDataTimeout bounds the wait for Fleet's vulnerability data. Fleet's first runs on a fresh stack (CI) are minutes
// after its start and F3 runs about 40 minutes later, so the data is normally in place; the bound covers a slow
// download, not a rate limit.
const fleetDataTimeout = 20 * time.Minute

// waitFleetVulnerabilityData waits until Fleet has the vulnerability data that matches the given CVEs, triggering its
// vulnerability job again every fleetRetrigger. That data is a precondition of plan M5a AC1, not part of a device's
// 10 minutes. The development stack passes Fleet direct URLs for the CPE dictionary, its translations and the NVD
// feeds (compose.dev.yaml, ADR 0009 amendment 2026-10-12), so their download makes no anonymous GitHub API call and
// does not hit GitHub's hourly rate limit on shared CI runners (PDK-053, PDK-054); a failed download is retried by
// every run.
func waitFleetVulnerabilityData(t *testing.T, cves ...string) {
	t.Helper()
	begin := time.Now()
	var triggered time.Time
	for {
		missing := fleetVulnerabilityDataMissing(t, cves)
		if len(missing) == 0 {
			if waited := time.Since(begin); waited > time.Second {
				t.Logf("Fleet's vulnerability data loaded after %s", waited.Round(time.Second))
			}
			return
		}
		if time.Since(begin) > fleetDataTimeout {
			t.Fatalf("Fleet has no %v after %s; errors of its vulnerability job: %s", missing, fleetDataTimeout,
				fleetVulnerabilityErrors(t, begin))
		}
		if time.Since(triggered) >= fleetRetrigger {
			if err := triggerFleetVulnerabilities(t); err != nil {
				t.Log(err)
			}
			triggered = time.Now()
		}
		time.Sleep(15 * time.Second)
	}
}

// fleetVulnerabilityDataMissing lists the files of Fleet's vulnerability data that findings of the CVEs need and Fleet
// has not downloaded yet: the CPE dictionary and the NVD feeds of the CVEs' years. Fleet matches the gates' deb
// packages through them; its OSV path needs the OS versions that Fleet aggregates only hourly, which a
// fresh stack (CI) has not done yet when the gate runs.
func fleetVulnerabilityDataMissing(t *testing.T, cves []string) []string {
	t.Helper()
	files := []string{"cpe.sqlite"}
	for _, cve := range cves {
		files = append(files, "nvdcve-1.1-"+strings.Split(cve, "-")[1]+".json.gz")
	}
	script := "for f in " + strings.Join(files, " ") + "; do test -s \"$FLEET_VULNERABILITIES_DATABASES_PATH/$f\" || echo \"$f\"; done"
	out, err := stack.Compose(testContext(t, time.Minute), nil, "exec", "-T", "fleet", "sh", "-c", script)
	if err != nil {
		t.Fatalf("fleet vulnerability data: %v", err)
	}
	return strings.Fields(out)
}

// fleetVulnerabilityErrors returns the last errors of Fleet's vulnerability job since a time, such as GitHub's rate
// limit on the download of its data; `make logs` keeps too few lines of Fleet to show them after the whole suite.
func fleetVulnerabilityErrors(t *testing.T, since time.Time) string {
	t.Helper()
	out, err := stack.Compose(testContext(t, time.Minute), nil, "logs", "--no-color", "--no-log-prefix",
		"--since", since.UTC().Format(time.RFC3339), "fleet")
	if err != nil {
		return fmt.Sprintf("fleet logs: %v", err)
	}
	var errs []string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, `"cron":"vulnerabilities"`) && strings.Contains(line, `"level":"error"`) {
			errs = append(errs, line[:min(len(line), 400)])
		}
	}
	if len(errs) == 0 {
		return "none"
	}
	return strings.Join(errs[max(0, len(errs)-3):], "\n")
}

// storeInventory writes packages and findings of a device as paddock-worker's inventory sync stores them, as
// paddock_owner: the isolation and list contract gates need inventory rows without waiting for Fleet's rounds (gate
// F3 runs the real path through Fleet). Findings are cve, package, version and CVSS score, empty for none (as Fleet
// free reports them).
func storeInventory(t *testing.T, device string, packages [][2]string, findings [][4]string) {
	t.Helper()
	dsn, err := stack.PaddockOwnerDSN()
	if err != nil {
		t.Fatal(err)
	}
	ctx := testContext(t, time.Minute)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	for _, p := range packages {
		if _, err := conn.Exec(ctx, `INSERT INTO installed_software (device_id, organization_id, name, version, source)
			SELECT id, organization_id, $2, $3, 'deb_packages' FROM device WHERE id = $1`, device, p[0], p[1]); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range findings {
		if _, err := conn.Exec(ctx, `INSERT INTO vulnerability_finding (device_id, organization_id, cve, software_name,
			software_version, cvss_score, severity)
			SELECT id, organization_id, $2, $3, $4, NULLIF($5, '')::numeric, CASE WHEN $5 = '' THEN NULL
			  WHEN $5::numeric >= 9 THEN 'critical' WHEN $5::numeric >= 7 THEN 'high' WHEN $5::numeric >= 4 THEN 'medium'
			  ELSE 'low' END
			FROM device WHERE id = $1`, device, f[0], f[1], f[2], f[3]); err != nil {
			t.Fatal(err)
		}
	}
}

// uniqueCVE is a random CVE ID no feed knows (year 2099).
func uniqueCVE() string { return fmt.Sprintf("CVE-2099-%012d", rand.Int64N(1_000_000_000_000)) }
