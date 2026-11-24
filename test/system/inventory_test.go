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

	"github.com/phischl/paddock-mdm/test/acceptance/devicesim"
	"github.com/phischl/paddock-mdm/test/acceptance/portal"
)

// TestInventoryGates runs the device gates of plan M5a on the VMs in parallel, each from a fresh base-installed: F1
// (fleetd installed from Paddock's package store, enrolled into Fleet, mapped to the device), F4 (an old package
// version shows its CVEs), F2 (mutual watch of agent and fleetd), F5 (the agent binary policy, plan M5a amendment
// 2026-11-16, A6), F6 (an impostor checks in while the genuine agent is stopped, amendment 2026-11-16 b) and F8 (the
// device's inventory host binding, amendment 2026-11-17 e). Over all
// gates exactly two device.tamper_agent_not_running are recorded per VM, F2's and F6's: the restarts of orbit and the
// supervisor in F1, F4 and F5 raise none. The fleetd package of this run (make fleetd-deb) is published once, as a release without rollout,
// for both VMs; Install publishes the installed paddockd the same way, so the genuine agent passes F5's policy.
func TestInventoryGates(t *testing.T) {
	forEachVM(t, func(t *testing.T, s *Stack, vm *VM) {
		vm.Gate(t, "inventory")
		fleetd := vm.Together(t, "inventory", "fleetd release", func() string { return s.PublishFleetd(t) })
		vm.Fresh()
		d := Install(t, s, vm, debDir(s))
		if !t.Run("F1 fleetd enrolled", func(t *testing.T) { d.Bind(t); gateF1(t, d, fleetd) }) {
			t.FailNow()
		}
		t.Run("F4 old package version", func(t *testing.T) { d.Bind(t); gateF4(t, d) })
		f2 := t.Run("F2 mutual watch", func(t *testing.T) { d.Bind(t); gateF2(t, d) })
		t.Run("F5 agent binary policy", func(t *testing.T) { d.Bind(t); gateF5(t, d) })
		f6 := t.Run("F6 agent absent while checking in", func(t *testing.T) { d.Bind(t); gateF6(t, d) })
		t.Run("F8 inventory host binding", func(t *testing.T) { d.Bind(t); gateF8(t, d) })
		// A failed F2 or F6 already fails the gate; their missing event would only repeat it as a count error.
		if !f2 || !f6 {
			return
		}
		if n := len(s.Events(t, agentNotRunningCode, d.ID)); n != 2 {
			t.Errorf("%s: %d %s events over the inventory gates, want exactly 2 (F2 and F6)", d.Name, n, agentNotRunningCode)
		}
	})
}

// PublishFleetd publishes bin/fleetd/fleet-osquery_<version>_amd64.deb in a new release without rollout, which no
// device updates to, and returns the fleetd version.
func (s *Stack) PublishFleetd(t *testing.T) string {
	t.Helper()
	debs, err := filepath.Glob(filepath.Join(s.root, "bin", "fleetd", "fleet-osquery_*_amd64.deb"))
	if err != nil || len(debs) != 1 {
		t.Fatalf("want one fleetd package in bin/fleetd (make fleetd-deb), got %v", debs)
	}
	v := version(8, "fleetd")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, agentRelease(s.root), "--version", v, "--artifact", "amd64="+s.BuildAgent(t, v, nil),
		"--deb", debs[0], "--publish")
	cmd.Dir = s.root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("agentrelease %s: %v\n%s", v, err, out)
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
		!strings.Contains(env, "ORBIT_ENABLE_SCRIPTS=false") || !strings.Contains(env, "ORBIT_FLEET_URL=https://fleet.paddock.localhost:"+portal.HTTPSPort()) {
		t.Errorf("orbit.env:\n%s", env)
	}
	uuid := d.MustRoot("cat /sys/class/dmi/id/product_uuid")
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
		d.s.Call(t, http.MethodPost, "/api/v1/devices/"+id+"/retire", nil, http.StatusOK)
	}
}

// gateF4: an intentionally old package version shows its CVEs (plan M5a step 4, AC1). The device downgrades wget to
// the oldest version apt offers (the release pocket); after fleetd's next software report (refetched through Fleet's
// API) and a vulnerability round the gate triggers, Paddock lists the old version among the device's packages and the
// CVEs Fleet matched to it among its vulnerabilities, within 10 minutes.
func gateF4(t *testing.T, d *Device) {
	const pkg = "wget"
	installed := d.Must("dpkg-query -W -f '${Version}' " + pkg)
	old := d.Must("apt-cache madison " + pkg + " | tail -n 1 | cut -d '|' -f 2 | tr -d ' '")
	if old == "" || old == installed {
		t.Fatalf("%s: no version of %s older than %s in apt", d.Name, pkg, installed)
	}
	d.Must(fmt.Sprintf("sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q --allow-downgrades -o DPkg::Lock::Timeout=300 %s=%s", pkg, old))
	start := time.Now()
	host, ok := fleetHostByUUID(t, d.MustRoot("cat /sys/class/dmi/id/product_uuid"))
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
		if err := json.Unmarshal(d.s.Call(t, http.MethodGet, path, nil, http.StatusOK).Body, &p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// The development stack runs Fleet's vulnerability job only hourly, because every run downloads the CPE database
	// again (ADR 0009 amendment 2026-10-12 (b)). A run matches only the software Fleet had stored when it started, so
	// the gate triggers again every 2 minutes; Fleet refuses a trigger while a run is pending.
	var triggered time.Time
	trigger := func() {
		if time.Since(triggered) < 2*time.Minute {
			return
		}
		triggered = time.Now()
		resp, err := fleetAPI(t, http.MethodPost, "/api/latest/fleet/trigger?name=vulnerabilities", nil)
		if err != nil {
			t.Logf("%s: Fleet vulnerability trigger: %v", d.Name, err)
			return
		}
		_ = resp.Body.Close()
		t.Logf("%s: Fleet vulnerability trigger: HTTP %d", d.Name, resp.StatusCode)
	}
	var cves []string
	Until(t, d.Name+": CVEs of "+pkg+" "+old+" in Paddock", 10*time.Minute, 15*time.Second, trigger, func() bool {
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
	// F4's apt downgrade restarts orbit; a stop issued while that restart job is queued fails with "Job canceled"
	// (PDK-041).
	Until(t, d.Name+": orbit.service settled", 2*time.Minute, 2*time.Second, nil, func() bool {
		return d.Must("{ systemctl is-active orbit.service; systemctl list-jobs --no-legend orbit.service; } || true") == "active"
	})
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

// agentBinaryCode is the audit code of the agent binary policy paddock_agent_binary_known.
const agentBinaryCode = "device.tamper_agent_binary_changed"

// osqueryRows runs query in osquery's shell on the guest (osqueryd -S, the osqueryi of fleet-osquery) and returns
// the number of rows. The real osquery decides the policy: it depends on the constraint pushdown of path into the
// hash table, so it is not simulated.
func osqueryRows(t *testing.T, d *Device, query string) int {
	t.Helper()
	out := d.MustRootIn([]byte(query), `q=$(cat) && /opt/orbit/bin/osqueryd/linux/stable/osqueryd -S --json "$q"`)
	var rows []map[string]any
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("%s: osquery answered %q: %v", d.Name, out, err)
	}
	return len(rows)
}

// agentBinaryQuery returns the agent binary policy as the worker applied it to Fleet (inventory.AgentBinaryPolicy
// from the stack's published hashes) once it lists hash.
func agentBinaryQuery(t *testing.T, d *Device, hash string) string {
	t.Helper()
	var query string
	Until(t, d.Name+": Fleet's agent binary policy lists the installed paddockd", 5*time.Minute, 10*time.Second, nil, func() bool {
		resp, err := fleetAPI(t, http.MethodGet, "/api/v1/fleet/global/policies", nil)
		if err != nil {
			t.Logf("fleet policies: %v", err)
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		var page struct {
			Policies []struct {
				Name  string `json:"name"`
				Query string `json:"query"`
			} `json:"policies"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil || resp.StatusCode != http.StatusOK {
			t.Logf("fleet policies: HTTP %d %v", resp.StatusCode, err)
			return false
		}
		for _, p := range page.Policies {
			if p.Name == "paddock_agent_binary_known" && strings.Contains(p.Query, "'"+hash+"'") {
				query = p.Query
				return true
			}
		}
		return false
	})
	return query
}

// gateF5 is the agent binary policy (plan M5a amendment 2026-11-16, A6): the genuine agent, which Install published,
// raised no device.tamper_agent_binary_changed during the earlier gates. osquery on the guest answers the policy with
// one row for the genuine binary, one with paddockd stopped and one for SELECT 1; (no release), and none for a
// modified binary in the active slot. That modified binary is reported exactly once within 25 minutes; once the
// genuine binary is back the policy passes again and no second event follows.
func gateF5(t *testing.T, d *Device) {
	if n := len(d.s.Events(t, agentBinaryCode, d.ID)); n != 0 {
		t.Fatalf("%s: %d %s events for the genuine agent during the inventory gates, want 0", d.Name, n, agentBinaryCode)
	}
	slot := "/opt/paddock/agent/current/paddockd"
	genuine := strings.Fields(d.Must("sudo sha256sum " + slot))[0]
	query := agentBinaryQuery(t, d, genuine)
	if n := osqueryRows(t, d, query); n != 1 {
		t.Fatalf("%s: genuine binary: %d rows, want 1", d.Name, n)
	}
	if n := osqueryRows(t, d, "SELECT 1;"); n != 1 {
		t.Fatalf("%s: SELECT 1;: %d rows, want 1", d.Name, n)
	}
	d.Must("sudo systemctl stop paddock-supervisor && ! pgrep -x paddockd")
	n := osqueryRows(t, d, query)
	d.Must("sudo systemctl start paddock-supervisor")
	if n != 1 {
		t.Fatalf("%s: paddockd stopped: %d rows, want 1", d.Name, n)
	}

	// A rename over the slot binary keeps the running process on the old inode; the restart runs the modified one.
	restored := false
	restore := func() {
		d.MustRoot("cp /root/paddockd.genuine " + slot + ".new && chmod --reference=" + slot + " " + slot + ".new && mv " + slot + ".new " +
			slot + " && systemctl restart paddock-supervisor")
		restored = true
	}
	t.Cleanup(func() {
		if !restored {
			restore()
		}
	})
	d.MustRoot("cp " + slot + " /root/paddockd.genuine && cp " + slot + " " + slot + ".new && printf x >> " + slot + ".new" +
		" && chmod --reference=" + slot + " " + slot + ".new && mv " + slot + ".new " + slot)
	// The policy hashes /proc/<pid>/exe: the running image is still genuine although its file was replaced (plan M5a
	// amendment 2026-11-16, review round 1, F5 step 1).
	if n := osqueryRows(t, d, query); n != 1 {
		t.Fatalf("%s: genuine image of a replaced file: %d rows, want 1", d.Name, n)
	}
	d.MustRoot("systemctl restart paddock-supervisor")
	replaced := time.Now()
	Until(t, d.Name+": the modified paddockd runs", 2*time.Minute, 5*time.Second, nil, func() bool {
		return d.Must("pgrep -x paddockd >/dev/null && sudo sha256sum "+slot+" | cut -d ' ' -f 1") != genuine
	})
	if n := osqueryRows(t, d, query); n != 0 {
		t.Fatalf("%s: modified binary: %d rows, want 0", d.Name, n)
	}
	d.WaitEvent(t, agentBinaryCode, 25*time.Minute, nil)
	t.Logf("%s: modified agent binary reported after %s", d.Name, time.Since(replaced).Round(time.Second))

	restore()
	Until(t, d.Name+": the genuine paddockd runs", 2*time.Minute, 5*time.Second, nil, func() bool {
		return d.Must("pgrep -x paddockd >/dev/null && sudo sha256sum "+slot+" | cut -d ' ' -f 1") == genuine
	})
	if n := osqueryRows(t, d, query); n != 1 {
		t.Fatalf("%s: restored binary: %d rows, want 1", d.Name, n)
	}
	passing := fmt.Sprintf(`SELECT passing FROM inventory_policy_result WHERE device_id = '%s' AND policy_key = 'paddock_agent_binary_known'`, d.ID)
	Until(t, d.Name+": the agent binary policy passes again", 25*time.Minute, 15*time.Second, d.Checkin, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		out, err := paddockSQL(ctx, passing)
		return err == nil && out == "t"
	})
	if n := len(d.s.Events(t, agentBinaryCode, d.ID)); n != 1 {
		t.Errorf("%s: %d %s events, want exactly 1", d.Name, n, agentBinaryCode)
	}
	gateF5Evasions(t, d, query)
}

// gateF5Evasions checks that the policy judges an agent started from another place, through a bind mount, or under
// another name (plan M5a amendment 2026-11-16, review round 1, A8 and F5 steps 2 and 3). Orbit is stopped meanwhile,
// so no evaluation reaches Fleet and the event count stays 1; the policy runs in osquery's shell. The stop is a
// runtime mask: the agent's mutual watch starts a merely stopped orbit again.
func gateF5Evasions(t *testing.T, d *Device, query string) {
	const current, dropIn = "/opt/paddock/agent/current", "/run/systemd/system/paddock-supervisor.service.d/99-f5.conf"
	link := d.MustRoot("readlink " + current)
	active := d.MustRoot("readlink -f " + current)
	sleep := d.MustRoot("readlink -f /usr/bin/sleep")
	reset := "rm -f " + dropIn + " && systemctl daemon-reload && ln -sfn " + link + " " + current + " && systemctl restart paddock-supervisor"
	const startOrbit = "systemctl unmask --runtime orbit.service && systemctl start orbit.service"
	done := false
	t.Cleanup(func() {
		if !done {
			d.MustRoot(reset + " && " + startOrbit)
		}
	})
	d.MustRoot("systemctl mask --runtime orbit.service && systemctl stop orbit.service && mkdir -p /var/lib/paddock-f5 /var/lib/paddock-f5s" +
		" && cp /root/paddockd.genuine /var/lib/paddock-f5/paddockd && printf x >> /var/lib/paddock-f5/paddockd" +
		" && chmod 755 /var/lib/paddock-f5/paddockd && printf '#!/bin/sh\\nexec sleep infinity\\n' > /var/lib/paddock-f5s/paddockd" +
		" && chmod 755 /var/lib/paddock-f5s/paddockd")
	for _, c := range []struct{ name, setup, exe string }{
		{"redirected current", "ln -sfn /var/lib/paddock-f5 " + current + " && systemctl restart paddock-supervisor", "/var/lib/paddock-f5/paddockd"},
		// The path a bind-mounted executable shows depends on the reader's mount namespace, so any child counts.
		{"bind mount", "mkdir -p $(dirname " + dropIn + ") && printf '[Service]\\nBindReadOnlyPaths=/var/lib/paddock-f5/paddockd:" + active +
			"/paddockd\\n' > " + dropIn + " && systemctl daemon-reload && systemctl restart paddock-supervisor", ""},
		{"renamed child", "ln -sfn /var/lib/paddock-f5s " + current + " && systemctl restart paddock-supervisor", sleep},
	} {
		d.MustRoot(c.setup)
		supervisorChild(t, d, c.exe, "")
		if n := osqueryRows(t, d, query); n != 0 {
			t.Errorf("%s: %s: %d rows, want 0", d.Name, c.name, n)
		}
		d.MustRoot(reset)
		supervisorChild(t, d, active+"/paddockd", "")
		if n := osqueryRows(t, d, query); n != 1 {
			t.Fatalf("%s: restored after %s: %d rows, want 1", d.Name, c.name, n)
		}
	}
	gateF5ReplacedSupervisor(t, d, query, active, sleep, reset)
	started := time.Now().UTC()
	d.MustRoot(startOrbit)
	done = true
	evaluated := fmt.Sprintf(`SELECT count(*) FROM inventory_policy_result r JOIN device_inventory_ref i USING (device_id)
		WHERE r.device_id = '%s' AND r.policy_key = 'paddock_agent_binary_known' AND r.passing AND i.policy_updated_at > '%s'`,
		d.ID, started.Format(time.RFC3339Nano))
	Until(t, d.Name+": a passing agent binary policy evaluated after orbit started", 25*time.Minute, 15*time.Second, d.Checkin, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		out, err := paddockSQL(ctx, evaluated)
		return err == nil && out == "1"
	})
	if n := len(d.s.Events(t, agentBinaryCode, d.ID)); n != 1 {
		t.Errorf("%s: %d %s events after the evasion checks, want still 1", d.Name, n, agentBinaryCode)
	}
}

// gateF5ReplacedSupervisor runs while orbit is masked (plan M5a addendum 2026-11-16, review round 2, A12): with the
// supervisor's file renamed over itself, its genuine child passes (the window of a regular supervisor upgrade) and a
// child that is neither paddockd nor below the slots fails. reset restores current and restarts the supervisor.
func gateF5ReplacedSupervisor(t *testing.T, d *Device, query, active, sleep, reset string) {
	const supervisor, current = "/usr/sbin/paddock-supervisor", "/opt/paddock/agent/current"
	d.MustRoot("cp " + supervisor + " " + supervisor + ".new && mv " + supervisor + ".new " + supervisor)
	t.Cleanup(func() { d.MustRoot("systemctl restart paddock-supervisor") })
	pid := supervisorChild(t, d, active+"/paddockd", "")
	d.MustRoot("kill " + pid)
	supervisorChild(t, d, active+"/paddockd", pid)
	if n := osqueryRows(t, d, query); n != 1 {
		t.Fatalf("%s: genuine child of a renamed-over supervisor: %d rows, want 1", d.Name, n)
	}
	pid = supervisorChild(t, d, active+"/paddockd", "")
	d.MustRoot("ln -sfn /var/lib/paddock-f5s " + current + " && kill " + pid)
	supervisorChild(t, d, sleep, "")
	if n := osqueryRows(t, d, query); n != 0 {
		t.Errorf("%s: foreign child of a renamed-over supervisor: %d rows, want 0", d.Name, n)
	}
	d.MustRoot(reset)
	supervisorChild(t, d, active+"/paddockd", "")
	if n := osqueryRows(t, d, query); n != 1 {
		t.Fatalf("%s: restored after the renamed-over supervisor: %d rows, want 1", d.Name, n)
	}
}

// supervisorChild waits until paddock-supervisor runs a child other than notPID that executed exe ("" any program but
// the supervisor itself) and returns the child's PID. A Go program forks from any of its threads, so the children of
// every task count; a supervisor whose file was renamed over runs from "… (deleted)".
func supervisorChild(t *testing.T, d *Device, exe, notPID string) string {
	t.Helper()
	var pid string
	Until(t, fmt.Sprintf("%s: paddock-supervisor runs %q", d.Name, exe), 2*time.Minute, 2*time.Second, nil, func() bool {
		children := d.MustRoot(`m=$(systemctl show -p MainPID --value paddock-supervisor); [ "$m" != 0 ] || exit 0` +
			`; for c in $(cat /proc/$m/task/*/children); do printf '%s\t%s\n' "$c" "$(readlink /proc/$c/exe || true)"; done`)
		for _, line := range strings.Split(children, "\n") {
			c, path, _ := strings.Cut(line, "\t")
			if c == "" || c == notPID || path == "" || strings.HasPrefix(path, "/usr/sbin/paddock-supervisor") {
				continue
			}
			if exe == "" || path == exe {
				pid = c
				return true
			}
		}
		return false
	})
	return pid
}

// fleetHost is a host as Fleet's API returns it.
type fleetHost struct {
	ID             int        `json:"id"`
	UUID           string     `json:"uuid"`
	Hostname       string     `json:"hostname"`
	OsqueryVersion string     `json:"osquery_version"`
	OrbitVersion   string     `json:"orbit_version"`
	SeenTime       *time.Time `json:"seen_time"`
}

// fleetAPI sends a request to Fleet's API on the development host (portal.FleetAdminURL) as Paddock's API-only user; the
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
	req, err := http.NewRequestWithContext(ctx, method, portal.FleetAdminURL()+path, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	return http.DefaultClient.Do(req)
}

// fleetHostByUUID looks a host up through Fleet's API: the most recently seen of the hosts with the hardware UUID, since
// earlier runs and the re-enrollment of F8 leave previous hosts behind.
func fleetHostByUUID(t *testing.T, uuid string) (fleetHost, bool) {
	hosts := fleetHostsByUUID(t, uuid)
	if len(hosts) == 0 {
		return fleetHost{}, false
	}
	best := hosts[0]
	for _, h := range hosts[1:] {
		if h.SeenTime != nil && (best.SeenTime == nil || h.SeenTime.After(*best.SeenTime)) {
			best = h
		}
	}
	return best, true
}

// fleetHostsByUUID lists every host with the hardware UUID through Fleet's API.
func fleetHostsByUUID(t *testing.T, uuid string) []fleetHost {
	t.Helper()
	resp, err := fleetAPI(t, http.MethodGet, "/api/latest/fleet/hosts?query="+url.QueryEscape(uuid), nil)
	if err != nil {
		t.Logf("fleet hosts: %v", err)
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	var page struct {
		Hosts []fleetHost `json:"hosts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil || resp.StatusCode != http.StatusOK {
		t.Logf("fleet hosts: HTTP %d %v", resp.StatusCode, err)
		return nil
	}
	var out []fleetHost
	for _, h := range page.Hosts {
		if strings.EqualFold(h.UUID, uuid) {
			out = append(out, h)
		}
	}
	return out
}

// agentNotRunningCode is the audit code of the mutual watch's policy paddock_agent_running.
const agentNotRunningCode = "device.tamper_agent_not_running"

// gateF6 is the mutual watch against an impostor (plan M5a amendment 2026-11-16 b, section 8): the genuine agent is
// stopped and a copy of it runs under another name and unit, so it checks in with the device's credentials while
// paddock_agent_running fails and paddock_agent_binary_known does not judge it. The org admin sees exactly one
// device.tamper_agent_not_running with last_contact_at later than failing_since, and no agent binary event.
func gateF6(t *testing.T, d *Device) {
	const dir, unit = "/var/lib/paddock-f6", "pdk-f6-impostor"
	query := func(sql string) string {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		out, err := paddockSQL(ctx, sql)
		if err != nil {
			t.Logf("%s: %v", d.Name, err)
		}
		return out
	}
	passing := fmt.Sprintf(`SELECT passing FROM inventory_policy_result WHERE device_id = '%s' AND policy_key = 'paddock_agent_running'`, d.ID)
	Until(t, d.Name+": paddock_agent_running passes", 25*time.Minute, 15*time.Second, d.Checkin, func() bool { return query(passing) == "t" })
	n0, binary0 := len(d.s.Events(t, agentNotRunningCode, d.ID)), len(d.s.Events(t, agentBinaryCode, d.ID))

	restored := false
	restore := func() {
		d.MustRoot("{ systemctl stop " + unit + " || true; } && rm -rf " + dir + " && systemctl start paddock-supervisor")
		restored = true
	}
	t.Cleanup(func() {
		if !restored {
			restore()
		}
	})
	d.MustRoot("mkdir -p " + dir + " && cp /opt/paddock/agent/current/paddockd " + dir + "/" + unit +
		" && systemctl stop paddock-supervisor && ! pgrep -x paddockd")
	// Taken after the stop: a check-in by the genuine agent cannot count as the impostor's.
	started := time.Now().UTC()
	d.MustRoot("systemd-run --unit=" + unit + " --property=RuntimeDirectory=paddock " + dir + "/" + unit + " run")
	contact := fmt.Sprintf(`SELECT count(*) FROM device_status WHERE device_id = '%s' AND last_contact_at > '%s'`, d.ID, started.Format(time.RFC3339Nano))
	Until(t, d.Name+": the impostor checks in", 5*time.Minute, 15*time.Second, func() {
		d.Must("sudo pkill -HUP -x " + unit + " || true")
	}, func() bool { return query(contact) == "1" })
	if d.Must("pgrep -x paddockd || true") != "" {
		t.Fatalf("%s: a process named paddockd runs next to the impostor", d.Name)
	}

	stamp := func(p map[string]any, key string) (time.Time, bool) {
		v, _ := p[key].(string)
		at, err := time.Parse(time.RFC3339Nano, v)
		return at, err == nil
	}
	d.WaitEvent(t, agentNotRunningCode, 30*time.Minute, func(p map[string]any) bool {
		since, ok := stamp(p, "failing_since")
		last, okLast := stamp(p, "last_contact_at")
		return ok && okLast && last.After(since)
	})
	t.Logf("%s: impostor reported after %s", d.Name, time.Since(started).Round(time.Second))

	evaluated := fmt.Sprintf(`SELECT coalesce(policy_updated_at::text, '') FROM device_inventory_ref WHERE device_id = '%s'`, d.ID)
	last, further := query(evaluated), 0
	Until(t, d.Name+": two further evaluations stored", 30*time.Minute, 15*time.Second, nil, func() bool {
		if at := query(evaluated); at != "" && at != last {
			last, further = at, further+1
		}
		return further >= 2
	})
	if n := len(d.s.Events(t, agentNotRunningCode, d.ID)); n != n0+1 {
		t.Errorf("%s: %d %s events, want %d", d.Name, n, agentNotRunningCode, n0+1)
	}
	if n := len(d.s.Events(t, agentBinaryCode, d.ID)); n != binary0 {
		t.Errorf("%s: %d %s events during F6, want still %d", d.Name, n, agentBinaryCode, binary0)
	}

	restore()
	Until(t, d.Name+": paddock_agent_running passes again", 25*time.Minute, 15*time.Second, d.Checkin, func() bool { return query(passing) == "t" })
}

// fleetHostClaimedCode is the audit code of a claim on a device's inventory host (ADR 0057).
const fleetHostClaimedCode = "device.tamper_fleet_host_claimed"

// gateF8 is the inventory host binding on the device (plan M5a amendment 2026-11-17 e, section 8):
//  1. orbit.env names the instance identifier, and fleetd's device token is readable and well formed;
//  2. the device is bound to its most recently seen Fleet host and stores it;
//  3. upgrade path: an orbit.env of an earlier agent makes the agent reset fleetd's enrollment once, announced before
//     the new host is bound; the new host is bound, the previous one falls silent, and nothing is reported;
//  4. another host enrolled with the VM's hardware UUID and a failing agent binary policy is reported once as a second
//     host, and its data never reaches the device.
func gateF8(t *testing.T, d *Device) {
	query := func(sql string) string {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		out, err := paddockSQL(ctx, sql)
		if err != nil {
			t.Logf("%s: %v", d.Name, err)
		}
		return out
	}
	binding := func() string {
		return query(fmt.Sprintf("SELECT host_id FROM device_fleet_binding WHERE device_id = '%s'", d.ID))
	}
	stored := func() string {
		return query(fmt.Sprintf("SELECT external_id FROM device_inventory_ref WHERE device_id = '%s'", d.ID))
	}
	hw := strings.ToLower(d.MustRoot("cat /sys/class/dmi/id/product_uuid"))
	claims0, files0 := len(d.s.Events(t, fleetHostClaimedCode, d.ID)), len(d.s.Events(t, "device.tamper_protected_file_changed", d.ID))
	binary0 := len(d.s.Events(t, agentBinaryCode, d.ID))

	if env := d.Must("sudo cat /etc/paddock/orbit.env"); !strings.Contains(env, "\nORBIT_HOST_IDENTIFIER=instance\n") {
		t.Errorf("orbit.env:\n%s", env)
	}
	if out := d.Must("stat -c '%a' /opt/orbit/identifier"); out != "644" {
		t.Errorf("/opt/orbit/identifier mode %q", out)
	}
	if token := d.Must("cat /opt/orbit/identifier"); !fleetTokenFormat(token) {
		t.Errorf("device token of %d characters does not match the format", len(token))
	}

	var current fleetHost
	Until(t, d.Name+": bound to its most recently seen Fleet host", 10*time.Minute, 15*time.Second, d.Checkin, func() bool {
		h, ok := fleetHostByUUID(t, hw)
		current = h
		return ok && binding() == fmt.Sprint(h.ID) && stored() == fmt.Sprint(h.ID)
	})

	d.MustRoot("systemctl stop paddock-supervisor && sed -i '/^ORBIT_HOST_IDENTIFIER=/d' /etc/paddock/orbit.env && systemctl start paddock-supervisor")
	var next fleetHost
	Until(t, d.Name+": re-enrolled under a new Fleet host and bound to it", 15*time.Minute, 15*time.Second, d.Checkin, func() bool {
		h, ok := fleetHostByUUID(t, hw)
		next = h
		return ok && h.ID > current.ID && binding() == fmt.Sprint(h.ID)
	})
	if got := query(fmt.Sprintf(`SELECT reset_announced_at IS NOT NULL AND reset_announced_at <= bound_at FROM device_fleet_binding
		WHERE device_id = '%s'`, d.ID)); got != "t" {
		t.Errorf("the enrollment reset was not announced before the new host was bound (%q)", got)
	}
	synced := query(fmt.Sprintf("SELECT synced_at FROM device_inventory_ref WHERE device_id = '%s'", d.ID))
	Until(t, d.Name+": the new host's inventory synced", 10*time.Minute, 15*time.Second, d.Checkin, func() bool {
		return stored() == fmt.Sprint(next.ID) &&
			query(fmt.Sprintf("SELECT synced_at FROM device_inventory_ref WHERE device_id = '%s'", d.ID)) != synced
	})
	for _, h := range fleetHostsByUUID(t, hw) {
		if h.ID == current.ID && h.SeenTime != nil && next.SeenTime != nil && !h.SeenTime.Before(*next.SeenTime) {
			t.Errorf("the previous host %d is still seen (%s)", h.ID, h.SeenTime)
		}
	}
	if n := len(d.s.Events(t, fleetHostClaimedCode, d.ID)) - claims0; n != 0 {
		t.Errorf("%d %s events for the device's own re-enrollment", n, fleetHostClaimedCode)
	}
	if n := len(d.s.Events(t, "device.tamper_protected_file_changed", d.ID)) - files0; n != 0 {
		t.Errorf("%d device.tamper_protected_file_changed events for the agent's own orbit.env", n)
	}

	dir, err := portal.SecretsDir()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := os.ReadFile(filepath.Join(dir, "fleet_enroll_secret"))
	if err != nil {
		t.Fatal(err)
	}
	identifier := fmt.Sprintf("pdk-f8-%s-%d", d.Name, time.Now().UnixNano())
	other, err := devicesim.EnrollFleetAs(context.Background(), http.DefaultClient, strings.TrimRight(portal.FleetAdminURL(), "/"),
		strings.TrimSpace(string(secret)), identifier, hw, identifier, nil)
	if err != nil {
		t.Fatal(err)
	}
	other.AgentBinarySHA256 = strings.Repeat("0", 64)
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			_, _ = other.Answer(ctx)
			select {
			case <-ctx.Done():
				return
			case <-time.After(30 * time.Second):
			}
		}
	}()
	t.Cleanup(func() {
		stop()
		<-done
		for _, h := range fleetHostsByUUID(t, hw) {
			if h.Hostname == identifier {
				if resp, err := fleetAPI(t, http.MethodDelete, fmt.Sprintf("/api/latest/fleet/hosts/%d", h.ID), nil); err == nil {
					_ = resp.Body.Close()
				}
			}
		}
	})
	var claim []portal.AuditEvent
	Until(t, d.Name+": the second host is reported", 30*time.Minute, 30*time.Second, d.Checkin, func() bool {
		claim = d.s.Events(t, fleetHostClaimedCode, d.ID)[claims0:]
		if stored() != fmt.Sprint(next.ID) {
			t.Errorf("the device stores host %s, not its bound host %d", stored(), next.ID)
		}
		return len(claim) > 0
	})
	p := claim[0].Params
	if len(claim) != 1 || p["kind"] != "second_host" || p["binding"] != "device" || p["bound_host"] != fmt.Sprint(next.ID) {
		t.Errorf("claims %+v, want one second_host/device/%d", claim, next.ID)
	}
	if n := len(d.s.Events(t, agentBinaryCode, d.ID)) - binary0; n != 0 {
		t.Errorf("%d %s events from the second host", n, agentBinaryCode)
	}
}

// fleetTokenFormat reports whether s is a lower-case UUID, the format of fleetd's device token.
func fleetTokenFormat(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return false
			}
		case (c < '0' || c > '9') && (c < 'a' || c > 'f'):
			return false
		}
	}
	return true
}
