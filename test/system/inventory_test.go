package system

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/portal"
)

// TestInventoryGates runs the device gates of plan M5a on the VMs in parallel, each from a fresh base-installed: F1
// (fleetd installed from Paddock's package store, enrolled into Fleet). The fleetd package of this run (make
// fleetd-deb) is published once, as a release without rollout, for both VMs.
func TestInventoryGates(t *testing.T) {
	forEachVM(t, func(t *testing.T, s *Stack, vm *VM) {
		vm.Gate(t, "inventory")
		fleetd := vm.Together(t, "inventory", "fleetd release", func() string { return s.PublishFleetd() })
		vm.Fresh()
		d := Install(t, s, vm, debDir(s))
		t.Run("F1 fleetd enrolled", func(t *testing.T) { gateF1(t, d, fleetd) })
	})
}

// PublishFleetd publishes bin/fleetd/fleet-osquery_<version>_amd64.deb in a new release without rollout, which no
// device updates to, and returns the fleetd version.
func (s *Stack) PublishFleetd() string {
	s.t.Helper()
	debs, err := filepath.Glob(filepath.Join(s.root, "bin", "fleetd", "fleet-osquery_*_amd64.deb"))
	if err != nil || len(debs) != 1 {
		s.t.Fatalf("want one fleetd package in bin/fleetd (make fleetd-deb), got %v", debs)
	}
	v := version(8, "fleetd")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, agentRelease(s.root), "--version", v, "--artifact", "amd64="+s.BuildAgent(v, nil),
		"--deb", debs[0], "--publish")
	cmd.Dir = s.root
	if out, err := cmd.CombinedOutput(); err != nil {
		s.t.Fatalf("agentrelease %s: %v\n%s", v, err, out)
	}
	return strings.TrimSuffix(strings.TrimPrefix(filepath.Base(debs[0]), "fleet-osquery_"), "_amd64.deb")
}

// gateF1: the bundle carries the inventory section; the agent installs fleetd from the package store (not from
// Fleet's update server) and gives it the enroll secret; orbit.service runs, and Fleet knows the host by the device's
// hardware UUID.
func gateF1(t *testing.T, d *Device, fleetd string) {
	Until(t, d.Name+": fleetd installed", 10*time.Minute, 10*time.Second, d.Checkin, func() bool {
		return d.Must("dpkg-query -W -f '${Version}' fleet-osquery 2>/dev/null || true") == fleetd
	})
	if out := d.Must("systemctl is-active orbit.service; systemctl is-enabled orbit.service"); out != "active\nenabled" {
		t.Errorf("orbit.service: %q", out)
	}
	if out := d.Must("sudo stat -c '%a %U' /opt/orbit/secret.txt /etc/paddock/orbit.env"); out != "600 root\n600 root" {
		t.Errorf("fleetd files: %q", out)
	}
	if env := d.Must("sudo cat /etc/paddock/orbit.env"); !strings.Contains(env, "ORBIT_DISABLE_UPDATES=true") ||
		!strings.Contains(env, "ORBIT_ENABLE_SCRIPTS=false") || !strings.Contains(env, "ORBIT_FLEET_URL=https://fleet.paddock.localhost:8443") {
		t.Errorf("orbit.env:\n%s", env)
	}
	uuid := d.Must("sudo cat /sys/class/dmi/id/product_uuid")
	var host fleetHost
	Until(t, d.Name+": host enrolled in Fleet", 5*time.Minute, 10*time.Second, nil, func() bool {
		var ok bool
		host, ok = fleetHostByUUID(t, uuid)
		return ok && host.OsqueryVersion != ""
	})
	t.Logf("%s: Fleet host %d (%s, osquery %s, orbit %s)", d.Name, host.ID, host.Hostname, host.OsqueryVersion, host.OrbitVersion)
}

// fleetHost is a host as Fleet's API returns it.
type fleetHost struct {
	ID             int    `json:"id"`
	UUID           string `json:"uuid"`
	Hostname       string `json:"hostname"`
	OsqueryVersion string `json:"osquery_version"`
	OrbitVersion   string `json:"orbit_version"`
}

// fleetHostByUUID looks a host up through Fleet's API on the development host (127.0.0.1:8412).
func fleetHostByUUID(t *testing.T, uuid string) (fleetHost, bool) {
	t.Helper()
	dir, err := portal.SecretsDir()
	if err != nil {
		t.Fatal(err)
	}
	token, err := os.ReadFile(filepath.Join(dir, "fleet_api_token"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:8412/api/latest/fleet/hosts?query="+url.QueryEscape(uuid), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Logf("fleet hosts: %v", err)
		return fleetHost{}, false
	}
	defer func() { _ = resp.Body.Close() }()
	var page struct {
		Hosts []fleetHost `json:"hosts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil || resp.StatusCode != http.StatusOK {
		t.Logf("fleet hosts: HTTP %d %v", resp.StatusCode, err)
		return fleetHost{}, false
	}
	for _, h := range page.Hosts {
		if strings.EqualFold(h.UUID, uuid) {
			return h, true
		}
	}
	return fleetHost{}, false
}
