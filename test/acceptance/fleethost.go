package acceptance

import (
	"context"
	"fmt"
	"math/rand/v2"
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

// triggerFleetVulnerabilities runs Fleet's vulnerability job now instead of at its next period, as the development
// administrator through fleetctl in Fleet's network namespace.
func triggerFleetVulnerabilities(t *testing.T) {
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
		t.Fatalf("fleetctl trigger: %v: %s", err, out)
	}
	t.Logf("fleetctl trigger: %s", strings.TrimSpace(out))
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
