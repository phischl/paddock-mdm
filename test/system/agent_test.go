package system

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"aead.dev/minisign"

	"github.com/phischl/paddock-mdm/pkg/releasesig"
)

// vms are the VMs of this run: PADDOCK_SYSTEM_VMS, comma-separated or "all" (make system-test VM=…).
func vms(t *testing.T) []string {
	t.Helper()
	v := os.Getenv("PADDOCK_SYSTEM_VMS")
	switch v {
	case "":
		t.Skip("PADDOCK_SYSTEM_VMS is not set; run `make system-test VM=<vm|all>`")
	case "all":
		return []string{"paddock-u2404", "paddock-u2604"}
	}
	return strings.Split(v, ",")
}

// forEachVM runs body for every VM of the run (PADDOCK_SYSTEM_VMS) as parallel subtests named after the VM; each
// gets its own Stack session and a VM of the shared group.
func forEachVM(t *testing.T, body func(t *testing.T, s *Stack, vm *VM)) {
	names := vms(t)
	g := newVMGroup()
	for _, name := range names {
		g.active[name] = true
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			t.Cleanup(func() { g.leave(name) })
			s := newStack(t)
			vm := newVM(t, s.root, name)
			vm.group = g
			body(t, s, vm)
		})
	}
}

// debDir holds the packages under test (make deb).
func debDir(s *Stack) string {
	if d := os.Getenv("PADDOCK_SYSTEM_DEBS"); d != "" {
		return d
	}
	return filepath.Join(s.root, "bin", "deb")
}

// TestAgentGates runs gates S1–S4 of plan M2b §8 on the VMs in parallel, each from a fresh base-installed. The stack
// outage of S3 and the releases of S4 are shared: they happen once, when every VM reached them.
func TestAgentGates(t *testing.T) {
	forEachVM(t, func(t *testing.T, s *Stack, vm *VM) {
		vm.Fresh()
		d := Install(t, s, vm, debDir(s))
		if !t.Run("S1 enrollment and bundle", func(t *testing.T) { gateS1(t, d) }) {
			t.FailNow()
		}
		t.Run("S2 configuration idempotency", func(t *testing.T) { gateS2(t, d) })
		t.Run("S3 agent outage", func(t *testing.T) { gateS3(t, d) })
		t.Run("S4 agent update", func(t *testing.T) { gateS4(t, d) })
	})
}

// fileFacts returns "<mode> <owner>:<group> <sha256>" of a guest file.
func fileFacts(d *Device, path string) string {
	return d.Must("sudo stat -c '%a %U:%G' " + path + " && sudo sha256sum " + path + " | cut -c1-64")
}

// gateS1: install, enroll, device active, managed file + unit + time applied, bundle.applied audited.
func gateS1(t *testing.T, d *Device) {
	var dev struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(d.s.Call(http.MethodGet, "/api/v1/devices/"+d.ID, nil, http.StatusOK).Body, &dev); err != nil || dev.State != "active" {
		t.Fatalf("device state %q, %v", dev.State, err)
	}
	// Only this run's resources and the time resource must apply without error; other definitions of the
	// development organization may fail on the VM, but the acceptance gates leave no units behind that real devices
	// would report as unknown (plan M2.1 decision 3).
	applied := d.WaitEvent(t, "device.bundle_applied", 5*time.Minute, func(p map[string]any) bool {
		version, _ := p["bundle_version"].(float64)
		return version >= d.Bundle && len(d.ownErrors(p)) == 0
	})
	errs := applied["errors"].([]any)
	t.Logf("bundle.applied: changed %v, %d errors of other definitions of the organization", applied["changed"], len(errs))
	for _, e := range errs {
		if m, _ := e.(map[string]any); strings.HasPrefix(fmt.Sprint(m["message"]), "unknown unit ") {
			t.Errorf("the device reports a unit of the organization as unknown: %v", m)
		}
	}
	for path := range d.Files {
		if strings.HasPrefix(path, "/etc/paddock-systest/") {
			if got := d.Must("sudo stat -c '%a %U:%G' " + path); got != "640 root:adm" {
				t.Errorf("%s: %s, want 640 root:adm", path, got)
			}
		}
	}
	if got := d.Must("systemctl is-enabled " + d.Unit + "; systemctl is-active " + d.Unit); got != "enabled\nactive" {
		t.Errorf("managed unit: %q", got)
	}
	// One NTP client runs (chrony on 26.04, systemd-timesyncd on 24.04) and timedated reports NTP on.
	ntp := d.Must("timedatectl show --property=NTP --value; systemctl is-active chrony.service systemd-timesyncd.service || true")
	if lines := strings.Split(ntp, "\n"); lines[0] != "yes" || !slices.Contains(lines[1:], "active") {
		t.Errorf("time synchronization: %q", ntp)
	}
	if health := d.Health(); !strings.Contains(health, `"status":"ok"`) {
		t.Errorf("health %s", health)
	}
}

// gateS2: a second run changes nothing; local drift is corrected within the drift interval and reported; a
// removed file resource deletes the unmodified file and leaves a modified one, reported.
func gateS2(t *testing.T, d *Device) {
	var plan struct {
		Changes int `json:"changes"`
	}
	if err := json.Unmarshal([]byte(d.Must("sudo paddockd plan")), &plan); err != nil || plan.Changes != 0 {
		t.Fatalf("second run plans %d changes (%v)", plan.Changes, err)
	}
	a, b := d.managedPath("a"), d.managedPath("b")
	want := fileFacts(d, a)
	d.Must("echo local edit | sudo tee -a " + a + " >/dev/null && sudo chmod 0666 " + a)
	Until(t, "drift corrected", 2*time.Minute, 5*time.Second, nil, func() bool { return fileFacts(d, a) == want })
	d.WaitEvent(t, "device.config_drift_corrected", 3*time.Minute, func(p map[string]any) bool {
		ids, _ := p["resource_ids"].([]any)
		return slices.Contains(ids, any("file:"+a))
	})

	// Remove both file resources; b is changed locally while the agent is stopped, so that the drift loop cannot
	// restore it before the new bundle arrives (the agent checks in at start, before its first drift pass).
	versionBefore := d.State()["applied_bundle_version"].(float64)
	for _, p := range []string{a, b} {
		d.s.Call(http.MethodDelete, "/api/v1/managed-files/"+d.Files[p], nil, http.StatusNoContent)
		delete(d.Files, p)
	}
	Until(t, "new bundle compiled", time.Minute, 2*time.Second, nil, func() bool {
		var dev struct {
			BundleVersion float64 `json:"bundle_version"`
		}
		_ = json.Unmarshal(d.s.Call(http.MethodGet, "/api/v1/devices/"+d.ID, nil, http.StatusOK).Body, &dev)
		return dev.BundleVersion > versionBefore
	})
	d.Must("sudo systemctl stop paddock-supervisor && echo local | sudo tee -a " + b + " >/dev/null && sudo systemctl start paddock-supervisor")
	d.WaitEvent(t, "device.bundle_applied", 3*time.Minute, func(p map[string]any) bool {
		errs, _ := p["errors"].([]any)
		for _, e := range errs {
			if m, _ := e.(map[string]any); m["id"] == "file:"+b && m["message"] == "left_modified_file" {
				return true
			}
		}
		return false
	})
	if out := d.Must("test -e " + a + " && echo present || echo absent; test -e " + b + " && echo present || echo absent"); out != "absent\npresent" {
		t.Fatalf("after the removal: a, b = %q; want the unmodified file deleted and the modified one kept", out)
	}
}

// spooled returns the spooled events of the agent.
func spooled(d *Device) []map[string]any {
	events, err := trySpooled(d)
	if err != nil {
		d.t.Fatal(err)
	}
	return events
}

// trySpooled reads the spool; the error is an SSH failure (e.g. while the guest's network comes back up).
func trySpooled(d *Device) ([]map[string]any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	raw, err := d.SSH(ctx, nil, "sudo cat /var/lib/paddock/spool/events.jsonl 2>/dev/null || true")
	if err != nil {
		return nil, fmt.Errorf("%s: read spool: %w: %s", d.Name, err, raw)
	}
	var out []map[string]any
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		var ev map[string]any
		if json.Unmarshal(sc.Bytes(), &ev) == nil {
			out = append(out, ev)
		}
	}
	return out, nil
}

// gateS3: with the stack down for 10 minutes the device works normally (agent and supervisor running, SSH, managed
// files, drift correction, no lock); after `make up` and a link down/up it checks in at once and the spooled events
// arrive exactly once. VMs in parallel share one outage.
func gateS3(t *testing.T, d *Device) {
	d.Gate(t, "S3")
	unit := "/etc/systemd/system/" + d.Unit
	want := fileFacts(d, unit)
	d.Together(t, "S3", "stack down", func() string { d.s.Make("down"); return "" })
	t.Cleanup(func() {
		if t.Failed() {
			d.s.Make("up") // never leave the stack down
		}
	})
	start := time.Now()
	d.Must("echo offline edit | sudo tee -a " + unit + " >/dev/null")
	for time.Since(start) < 10*time.Minute {
		out := d.Must("systemctl is-active paddock-supervisor; pgrep -fc '^/opt/paddock/agent/current/paddockd run'; sudo passwd -S paddock | cut -d' ' -f2; sudo -n true && echo sudo-ok")
		if out != "active\n1\nP\nsudo-ok" {
			t.Fatalf("device not usable while the server is down: %q", out)
		}
		time.Sleep(time.Minute)
	}
	if got := fileFacts(d, unit); got != want {
		t.Fatalf("managed file not enforced offline: %s, want %s", got, want)
	}
	pending := spooled(d)
	var drift []float64
	for _, ev := range pending {
		if ev["type"] == "config.drift_corrected" {
			drift = append(drift, ev["event_seq"].(float64))
		}
	}
	if len(drift) == 0 {
		t.Fatalf("no config.drift_corrected spooled while offline: %v", pending)
	}
	if health := d.Health(); !strings.Contains(health, `"status":"degraded"`) {
		t.Errorf("health while offline: %s", health)
	}

	d.Together(t, "S3", "stack up", func() string { d.s.Make("up"); return "" })
	d.s.Login()
	upAt := time.Now()
	d.SetLink(false)
	time.Sleep(10 * time.Second)
	d.SetLink(true)
	Until(t, "check-in after the outage", 6*time.Minute, 5*time.Second, nil, func() bool {
		events, err := trySpooled(d)
		if err != nil {
			t.Log(err) // the guest's network is coming back after the link toggle
			return false
		}
		return len(events) == 0
	})
	t.Logf("spool delivered %s after make up", time.Since(upAt).Round(time.Second))
	seen := map[float64]int{}
	Until(t, "spooled drift events audited", 2*time.Minute, 5*time.Second, nil, func() bool {
		seen = map[float64]int{}
		for _, e := range d.s.Events("device.config_drift_corrected", d.ID) {
			seen[e.Params["event_seq"].(float64)]++
		}
		for _, seq := range drift {
			if seen[seq] == 0 {
				return false
			}
		}
		return true
	})
	for _, seq := range drift {
		if seen[seq] != 1 {
			t.Errorf("event %v recorded %d times, want exactly once", seq, seen[seq])
		}
	}
}

// release marks t as gate and releases a new version once every VM running in parallel arrived at it: a rollout
// reaches every device.
func release(t *testing.T, d *Device, gate string, minor int, label string, tags []string) string {
	t.Helper()
	d.Gate(t, gate)
	return d.Together(t, gate, "release", func() string {
		v := version(minor, label)
		d.s.Release(v, tags)
		return v
	})
}

// stage puts a release into the device's staging directory exactly as the agent stages a download, and signals the
// supervisor.
func (d *Device) stage(t *testing.T, v string, bin, sig []byte) {
	t.Helper()
	dir := "/var/lib/paddock/staging/" + v
	d.Must("sudo install -d -m 0700 " + dir)
	d.MustIn(bin, "sudo tee "+dir+"/paddockd >/dev/null && sudo chmod 0700 "+dir+"/paddockd")
	d.MustIn(sig, "sudo tee "+dir+"/paddockd.minisig >/dev/null")
	d.MustIn([]byte(fmt.Sprintf(`{"version":%q}`, v)), "sudo tee /var/lib/paddock/staging/request.json >/dev/null")
	d.Must("sudo kill -USR1 $(pidof paddock-supervisor)")
}

// releaseKey is the development release key (make dev-release-key, password-less).
func releaseKey(t *testing.T, s *Stack) minisign.PrivateKey {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(s.root, "deploy", "compose", ".secrets", "release", "minisign.key"))
	if err != nil {
		t.Fatal(err)
	}
	if minisign.IsEncrypted(data) {
		k, err := minisign.DecryptKey("", data)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	var k minisign.PrivateKey
	if err := k.UnmarshalText(data); err != nil {
		t.Fatal(err)
	}
	return k
}

// gateS4: a good release is installed and reported; a release that crashes in probation is rolled back; one that
// fails its self-test is never switched to; a signed older release (plan M4b.1 AC4) and a binary with a bad signature
// are refused. VMs in parallel share the
// releases.
func gateS4(t *testing.T, d *Device) {
	t.Run("good release", func(t *testing.T) {
		v := release(t, d, "S4 good", 2, "good", nil)
		d.WaitEvent(t, "device.agent_updated", 12*time.Minute, func(p map[string]any) bool { return p["version"] == v })
		if got := d.AgentVersion(); got != v {
			t.Fatalf("agent version %s, want %s", got, v)
		}
		t.Logf("updated to %s in slot %s", v, d.Slot())
	})
	good, slot := d.AgentVersion(), d.Slot()

	t.Run("probation failure", func(t *testing.T) {
		v := release(t, d, "S4 probation", 3, "probation", []string{"paddock_testbroken_probation"})
		p := d.WaitEvent(t, "device.agent_rolled_back", 12*time.Minute, func(p map[string]any) bool { return p["version"] == v })
		if p["from_version"] != good || d.AgentVersion() != good || d.Slot() != slot {
			t.Fatalf("after the rollback: %v, version %s slot %s; want %s in %s", p, d.AgentVersion(), d.Slot(), good, slot)
		}
	})

	t.Run("self-test failure", func(t *testing.T) {
		v := release(t, d, "S4 selftest", 4, "selftest", []string{"paddock_testbroken_selftest"})
		d.WaitEvent(t, "device.agent_update_failed", 10*time.Minute, func(p map[string]any) bool {
			return p["version"] == v && p["outcome"] == "self_test_failed"
		})
		if d.AgentVersion() != good || d.Slot() != slot {
			t.Fatalf("switched to a release that failed its self-test: %s in %s", d.AgentVersion(), d.Slot())
		}
	})

	t.Run("downgrade", func(t *testing.T) {
		// AC4 of plan M4b.1: a correctly signed release older than the active one is refused, staged on the device
		// directly as the agent would stage it (the server offers only newer releases).
		v := version(1, "downgrade")
		data, err := os.ReadFile(d.s.BuildAgent(v, nil))
		if err != nil {
			t.Fatal(err)
		}
		d.stage(t, v, data, minisign.SignWithComments(releaseKey(t, d.s), data, releasesig.Comment(v, "amd64"), ""))
		d.WaitEvent(t, "device.agent_update_failed", 6*time.Minute, func(p map[string]any) bool {
			return p["version"] == v && p["outcome"] == "downgrade_refused"
		})
		if d.AgentVersion() != good || d.Slot() != slot {
			t.Fatalf("installed the older release: %s in %s", d.AgentVersion(), d.Slot())
		}
	})

	t.Run("bad signature", func(t *testing.T) {
		// The server refuses binaries that do not verify, so the forged release is staged on the device directly,
		// exactly as the agent would stage a downloaded one, signed with a key the supervisor does not trust.
		v := version(5, "forged")
		bin := d.s.BuildAgent(v, nil)
		_, forger, err := minisign.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(bin)
		if err != nil {
			t.Fatal(err)
		}
		d.stage(t, v, data, minisign.Sign(forger, data))
		d.WaitEvent(t, "device.agent_update_failed", 6*time.Minute, func(p map[string]any) bool {
			return p["version"] == v && p["outcome"] == "signature_invalid"
		})
		if d.AgentVersion() != good || d.Slot() != slot || d.Must("sudo ls /var/lib/paddock/staging") != "" {
			t.Fatalf("after the refused release: %s in %s, staging %q", d.AgentVersion(), d.Slot(), d.Must("sudo ls /var/lib/paddock/staging"))
		}
	})
}
