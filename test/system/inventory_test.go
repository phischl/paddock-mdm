package system

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/portal"
)

// TestInventoryGates runs the device gates of plan M5a on the VMs in parallel, each from a fresh base-installed: F1
// (fleetd installed from Paddock's package store, enrolled into Fleet, mapped to the device), F4 (an old package
// version shows its CVEs) and F2 (mutual watch of agent and fleetd). The fleetd package of this run (make
// fleetd-deb) is published once, as a release without rollout, for both VMs.
func TestInventoryGates(t *testing.T) {
	forEachVM(t, func(t *testing.T, s *Stack, vm *VM) {
		vm.Gate(t, "inventory")
		fleetd := vm.Together(t, "inventory", "fleetd release", func() string { return s.PublishFleetd() })
		vm.Fresh()
		d := Install(t, s, vm, debDir(s))
		if !t.Run("F1 fleetd enrolled", func(t *testing.T) { gateF1(t, d, fleetd) }) {
			t.FailNow()
		}
		t.Run("F4 old package version", func(t *testing.T) { gateF4(t, d) })
		t.Run("F2 mutual watch", func(t *testing.T) { gateF2(t, d) })
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
	// dpkg-query names the version as soon as the package is unpacked; installed means configured, too.
	Until(t, d.Name+": fleetd installed and running", 10*time.Minute, 10*time.Second, d.Checkin, func() bool {
		return d.Must("dpkg-query -W -f '${Status} ${Version}' fleet-osquery 2>/dev/null || true") == "install ok installed "+fleetd &&
			d.Must("systemctl is-active orbit.service || true") == "active"
	})
	if out := d.Must("systemctl is-enabled orbit.service || true"); out != "enabled" {
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

	// Earlier runs left active devices with this VM's hardware UUID; the host maps only to a unique device.
	retireTwins(t, d, uuid)
	start := time.Now()
	query := fmt.Sprintf("SELECT external_id FROM device_inventory_ref WHERE device_id = '%s'", d.ID)
	Until(t, d.Name+": host mapped to the device", 3*time.Minute, 5*time.Second, nil, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		out, err := paddockSQL(ctx, query)
		return err == nil && out == fmt.Sprint(host.ID)
	})
	t.Logf("%s: mapped to device %s after %s", d.Name, d.ID, time.Since(start).Round(time.Second))
}

// retireTwins retires every other active or quarantined device of the organization with the hardware UUID.
func retireTwins(t *testing.T, d *Device, hardwareUUID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, err := paddockSQL(ctx, fmt.Sprintf(`SELECT id FROM device WHERE lower(hardware_uuid) = lower('%s')
		AND state IN ('active','quarantined') AND id <> '%[2]s'
		AND organization_id = (SELECT organization_id FROM device WHERE id = '%[2]s')`, hardwareUUID, d.ID))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range strings.Fields(out) {
		d.s.Call(http.MethodPost, "/api/v1/devices/"+id+"/retire", nil, http.StatusOK)
	}
}

// gateF4: an intentionally old package version shows its CVEs (plan M5a step 4, AC1). The device downgrades wget to
// the oldest version apt offers (the release pocket); after fleetd's next software report (refetched through Fleet's
// API) and Fleet's next vulnerability round, Paddock lists the old version among the device's packages and the CVEs
// Fleet matched to it among its vulnerabilities, within 10 minutes.
func gateF4(t *testing.T, d *Device) {
	const pkg = "wget"
	installed := d.Must("dpkg-query -W -f '${Version}' " + pkg)
	old := d.Must("apt-cache madison " + pkg + " | tail -n 1 | cut -d '|' -f 2 | tr -d ' '")
	if old == "" || old == installed {
		t.Fatalf("%s: no version of %s older than %s in apt", d.Name, pkg, installed)
	}
	d.Must(fmt.Sprintf("sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q --allow-downgrades -o DPkg::Lock::Timeout=300 %s=%s", pkg, old))
	start := time.Now()
	host, ok := fleetHostByUUID(t, d.Must("sudo cat /sys/class/dmi/id/product_uuid"))
	if !ok {
		t.Fatalf("%s: no Fleet host", d.Name)
	}
	resp, err := fleetAPI(t, http.MethodPost, fmt.Sprintf("/api/latest/fleet/hosts/%d/refetch", host.ID), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: refetch of Fleet host %d: HTTP %d", d.Name, host.ID, resp.StatusCode)
	}

	type page struct {
		Items []map[string]any `json:"items"`
	}
	list := func(path string) page {
		var p page
		if err := json.Unmarshal(d.s.Call(http.MethodGet, path, nil, http.StatusOK).Body, &p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	var cves []string
	Until(t, d.Name+": CVEs of "+pkg+" "+old+" in Paddock", 10*time.Minute, 15*time.Second, nil, func() bool {
		cves = nil
		for _, f := range list("/api/v1/devices/" + d.ID + "/vulnerabilities?page_size=100&q=" + pkg).Items {
			if f["software_name"] == pkg && f["software_version"] == old {
				cves = append(cves, fmt.Sprint(f["cve"]))
			}
		}
		return len(cves) > 0
	})
	t.Logf("%s: %s %s (downgraded from %s) shows %v after %s", d.Name, pkg, old, installed, cves, time.Since(start).Round(time.Second))
	var versions []string
	for _, s := range list("/api/v1/devices/" + d.ID + "/software?page_size=100&q=" + pkg).Items {
		if s["name"] == pkg {
			versions = append(versions, fmt.Sprint(s["version"]))
		}
	}
	if !slices.Equal(versions, []string{old}) {
		t.Errorf("%s: software lists %s %v, want only %s", d.Name, pkg, versions, old)
	}
}

// gateF2 is the mutual watch: a stopped fleetd is reported by the agent (tamper.service_stopped) and started again;
// a stopped agent is reported through fleetd's policy once the device has not checked in for 15 minutes
// (device.tamper_agent_not_running).
func gateF2(t *testing.T, d *Device) {
	d.Must("sudo systemctl stop orbit.service")
	d.WaitEvent(t, "device.tamper_service_stopped", 3*time.Minute, func(p map[string]any) bool { return p["unit"] == "orbit.service" })
	Until(t, d.Name+": orbit.service running again", time.Minute, 5*time.Second, nil, func() bool {
		return d.Must("systemctl is-active orbit.service || true") == "active"
	})

	stopped := time.Now()
	d.Must("sudo systemctl stop paddock-supervisor && ! pgrep -x paddockd")
	t.Cleanup(func() { d.Must("sudo systemctl start paddock-supervisor") })
	d.WaitEvent(t, "device.tamper_agent_not_running", 25*time.Minute, nil)
	t.Logf("%s: agent stop reported after %s", d.Name, time.Since(stopped).Round(time.Second))
}

// fleetHost is a host as Fleet's API returns it.
type fleetHost struct {
	ID             int    `json:"id"`
	UUID           string `json:"uuid"`
	Hostname       string `json:"hostname"`
	OsqueryVersion string `json:"osquery_version"`
	OrbitVersion   string `json:"orbit_version"`
}

// fleetAPI sends a request to Fleet's API on the development host (127.0.0.1:8412) as Paddock's API-only user; the
// caller closes the response.
func fleetAPI(t *testing.T, method, path string, body io.Reader) (*http.Response, error) {
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
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, method, "http://127.0.0.1:8412"+path, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	return http.DefaultClient.Do(req)
}

// fleetHostByUUID looks a host up through Fleet's API.
func fleetHostByUUID(t *testing.T, uuid string) (fleetHost, bool) {
	t.Helper()
	resp, err := fleetAPI(t, http.MethodGet, "/api/latest/fleet/hosts?query="+url.QueryEscape(uuid), nil)
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
