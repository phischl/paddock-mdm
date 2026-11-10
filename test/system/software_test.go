package system

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/portal"
)

// driftInterval is the agent's drift interval on the gate's devices (Device.SetDriftInterval).
const driftInterval = 30 * time.Second

// softwareGate is the per-VM state the software gates share: the repository, the source and the catalog entry of
// gateApp with its assignment to the device's group.
type softwareGate struct {
	keep                     *testing.T // the VM's test: the assignments live until it ends
	repo                     gateRepo
	source, slug             string
	entry, assignment        string
	anchorEntry              string   // gateAnchor's entry, assigned required from SW3 on
	installed, removed, fail []string // event IDs seen so far, by code
}

// TestSoftwareGates runs the device gates of plan M13a §9 on the VMs in parallel, each from a fresh base-installed
// with its own signed local repository, source and catalog entry (every server object carries the run's suffix):
// SW1 required install, SW2 reinstall after a local removal, SW3 forbid, SW4 hold, SW5 no removal while the server
// is unreachable, SW6 dpkg lock, SW7 source key change, SW8 tamper, and of plan M13c §9 SW10 maintenance window. The
// gates build on each other in this order. SW9 (an uploaded package through the Paddock repository) waits for PDK-812
// and PDK-813, SW11 (the request flow from the real app) for PDK-811.
func TestSoftwareGates(t *testing.T) {
	forEachVM(t, func(t *testing.T, s *Stack, vm *VM) {
		vm.Gate(t, "software")
		vm.Fresh()
		d := Install(t, s, vm, debDir(s))
		g := &softwareGate{keep: t, repo: d.setupGateRepo()}
		g.source, g.slug = d.softwareSource(g.repo)
		// Both entries belong to the VM's test, not to a subtest: a subtest's cleanup would delete them when it ends.
		g.entry = d.catalogEntry(g.source, gateApp)
		g.anchorEntry = d.catalogEntry(g.source, gateAnchor)
		for _, gate := range []struct {
			name string
			fn   func(*testing.T, *Device, *softwareGate)
		}{
			{"SW1 required install", gateSW1}, {"SW2 local removal", gateSW2}, {"SW3 forbid", gateSW3},
			{"SW4 hold", gateSW4}, {"SW5 server unreachable", gateSW5}, {"SW6 dpkg lock", gateSW6},
			{"SW7 source key change", gateSW7}, {"SW8 tamper", gateSW8}, {"SW10 maintenance window", gateSW10},
		} {
			if !t.Run(gate.name, func(t *testing.T) { d.Bind(t); gate.fn(t, d, g) }) {
				t.FailNow()
			}
		}
	})
}

// softwareState waits until the agent's health reports state and reason for pkg; tick runs before each poll (nil
// for none).
func softwareState(t *testing.T, d *Device, pkg, state, reason string, timeout time.Duration, tick func()) {
	t.Helper()
	var last softwareItem
	Until(t, fmt.Sprintf("%s: health %s %s/%s", d.Name, pkg, state, reason), timeout, 5*time.Second, tick, func() bool {
		it, ok, err := healthSoftwareItem(d.Health(), pkg)
		if err != nil {
			t.Fatal(err)
		}
		last = it
		return ok && it.State == state && it.Reason == reason
	})
	t.Logf("%s: health item %+v", d.Name, last)
}

// waitVersion waits until pkg is installed at version ("" = not installed); a check-in is triggered when checkin.
func waitVersion(t *testing.T, d *Device, pkg, version string, timeout time.Duration, checkin bool) {
	t.Helper()
	var tick func()
	if checkin {
		tick = d.Checkin
	}
	Until(t, fmt.Sprintf("%s: %s at %q", d.Name, pkg, version), timeout, 10*time.Second, tick, func() bool {
		return d.installedVersion(pkg) == version
	})
}

// managedSoftware is an item of GET /devices/{id}/managed-software.
type managedSoftware struct {
	CatalogEntryID string `json:"catalog_entry_id"`
	State          string `json:"state"`
	Version        string `json:"version"`
}

// intentIs matches the params of a software event of gateApp with intent.
func intentIs(intent string) func(map[string]any) bool {
	return func(p map[string]any) bool { return p["package"] == gateApp && p["intent"] == intent }
}

// gateSW1: a required pinned assignment installs the package at 1.0 within one check-in, with the source file as
// the agent renders it, the keyring of the source's key, the 1001 pin of the updates section, the event and the
// status on the device's managed software.
func gateSW1(t *testing.T, d *Device, g *softwareGate) {
	g.installed = d.eventIDs("device.software_installed")
	g.assignment = d.assign(g.keep, g.entry, "required", "1.0")
	waitVersion(t, d, gateApp, "1.0", 6*time.Minute, true)

	source := gateSourcePath(g.slug)
	if got := d.Must("sudo sha256sum " + source + " | cut -c1-64"); got != sha256Hex(gateSourceFile(g.slug)) {
		t.Errorf("%s differs from the rendering:\n%s\nwant:\n%s", source, d.Must("sudo cat "+source), gateSourceFile(g.slug))
	}
	for _, f := range []string{source, gateKeyringPath(g.slug)} {
		if got := d.Must("sudo stat -c '%a %U:%G' " + f); got != "644 root:root" {
			t.Errorf("%s: %s, want 644 root:root", f, got)
		}
	}
	if fp := d.keyringFingerprint(gateKeyringPath(g.slug)); fp != g.repo.Fingerprint {
		t.Errorf("keyring fingerprint %q, want %s", fp, g.repo.Fingerprint)
	}
	policy := d.Must("LC_ALL=C apt-cache policy " + gateApp)
	if !regexp.MustCompile(`(?m)^\s*(\*\*\* )?1\.0 1001$`).MatchString(policy) ||
		!regexp.MustCompile(`(?m)^\s*1\.1 500$`).MatchString(policy) {
		t.Errorf("apt-cache policy without the pin 1001 for 1.0 next to 1.1:\n%s", policy)
	}
	ev := d.waitNewEvent(t, "device.software_installed", g.installed, 5*time.Minute, intentIs("required"))
	if ev["version"] != "1.0" || ev["reason"] != "first_install" || ev["catalog_entry_id"] != g.entry {
		t.Errorf("device.software_installed %v", ev)
	}
	Until(t, d.Name+": managed software installed 1.0", 5*time.Minute, 10*time.Second, d.Checkin, func() bool {
		var page struct {
			Items []managedSoftware `json:"items"`
		}
		res := d.s.Call(t, http.MethodGet, "/api/v1/devices/"+d.ID+"/managed-software", nil, http.StatusOK)
		if err := json.Unmarshal(res.Body, &page); err != nil {
			t.Fatal(err)
		}
		return slices.ContainsFunc(page.Items, func(i managedSoftware) bool {
			return i.CatalogEntryID == g.entry && i.State == "installed" && i.Version == "1.0"
		})
	})
}

// gateSW2: a required package the local administrator removes is back within the drift interval (≤ 6 min), with
// device.software_reinstalled{reason: locally_removed}; nothing stopped the removal.
func gateSW2(t *testing.T, d *Device, g *softwareGate) {
	seen := d.eventIDs("device.software_reinstalled")
	d.Must("sudo DEBIAN_FRONTEND=noninteractive apt-get remove -y -q -o DPkg::Lock::Timeout=120 " + gateApp + " >/dev/null")
	if v := d.installedVersion(gateApp); v != "" {
		t.Fatalf("%s still installed at %s after apt-get remove", gateApp, v)
	}
	waitVersion(t, d, gateApp, "1.0", 6*time.Minute, false)
	ev := d.waitNewEvent(t, "device.software_reinstalled", seen, 5*time.Minute, intentIs("required"))
	if ev["reason"] != "locally_removed" || ev["version"] != "1.0" {
		t.Errorf("device.software_reinstalled %v", ev)
	}
}

// gateSW3: forbid removes the package with device.software_removed{intent: forbid} and pins it to -1, so apt-get
// install fails; a dpkg -i of it is undone within the drift interval with a second event.
func gateSW3(t *testing.T, d *Device, g *softwareGate) {
	d.assign(g.keep, g.anchorEntry, "required", "")
	waitVersion(t, d, gateAnchor, "1.0", 6*time.Minute, true)
	g.removed = d.eventIDs("device.software_removed")
	d.reassign(g.assignment, "forbid", "")
	waitVersion(t, d, gateApp, "", 6*time.Minute, true)
	ev := d.waitNewEvent(t, "device.software_removed", g.removed, 5*time.Minute, intentIs("forbid"))
	if ev["version"] != "1.0" {
		t.Errorf("device.software_removed %v", ev)
	}
	g.removed = d.eventIDs("device.software_removed")
	if pins := d.Must("sudo cat " + gateForbidFile); !strings.Contains(pins, gateForbidPin(gateApp)) {
		t.Errorf("%s lacks the forbid pin:\n%s", gateForbidFile, pins)
	}
	if source := gateSourcePath(g.slug); d.Must("sudo test -e "+source+" && echo present || echo absent") != "present" {
		t.Fatalf("%s is gone while %s is required: the refusal below would not prove the pin", source, gateAnchor)
	}
	if policy := d.Must("LC_ALL=C apt-cache policy " + gateApp); !regexp.MustCompile(`(?m)^\s*1\.1 -1$`).MatchString(policy) {
		t.Errorf("apt-cache policy does not pin the available 1.1 to -1:\n%s", policy)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	out, err := d.SSH(ctx, nil, "sudo env LC_ALL=C DEBIAN_FRONTEND=noninteractive apt-get install -y -q -o DPkg::Lock::Timeout=120 "+gateApp+" 2>&1")
	if err == nil || !strings.Contains(out, "has no installation candidate") {
		t.Errorf("apt-get install of a forbidden package (%v), want a refusal for no installation candidate:\n%s", err, out)
	}
	if v := d.installedVersion(gateApp); v != "" {
		t.Fatalf("forbidden %s installed at %s", gateApp, v)
	}

	d.dpkgInstall(t, gateDeb)
	if v := d.installedVersion(gateApp); v != "1.0" {
		t.Fatalf("dpkg -i: %s at %q", gateApp, v)
	}
	waitVersion(t, d, gateApp, "", 6*time.Minute, false)
	d.waitNewEvent(t, "device.software_removed", g.removed, 5*time.Minute, intentIs("forbid"))
	g.removed = d.eventIDs("device.software_removed")
}

// gateSW4: a hold keeps the installed 1.0 through the regular update run, which names it held back; the catalog
// itself never upgrades a required latest package, the next regular run does. gateAnchor, required since SW3, keeps
// the source in the bundle while gateApp is held (see gateAnchor).
func gateSW4(t *testing.T, d *Device, g *softwareGate) {
	g.installed = d.eventIDs("device.software_installed")
	d.reassign(g.assignment, "required", "1.0")
	waitVersion(t, d, gateApp, "1.0", 6*time.Minute, true)
	d.waitNewEvent(t, "device.software_installed", g.installed, 5*time.Minute, intentIs("required"))

	d.reassign(g.assignment, "hold", "")
	Until(t, d.Name+": "+gateApp+" held", 5*time.Minute, 10*time.Second, d.Checkin, func() bool {
		return slices.Contains(strings.Fields(d.Must("apt-mark showhold")), gateApp)
	})
	if source := gateSourcePath(g.slug); d.Must("sudo test -e "+source+" && echo present || echo absent") != "present" {
		t.Fatalf("%s is gone while %s is required", source, gateAnchor)
	}
	run := regularRun(t, d)
	held, _ := run["held_back"].([]any)
	if !slices.Contains(held, any(gateApp)) {
		t.Errorf("updates.run held_back %v does not name %s: %v", held, gateApp, run)
	}
	if v := d.installedVersion(gateApp); v != "1.0" {
		t.Errorf("held %s at %s after the regular run, want 1.0", gateApp, v)
	}

	d.reassign(g.assignment, "required", "")
	Until(t, d.Name+": hold released and 1.1 visible", 5*time.Minute, 10*time.Second, d.Checkin, func() bool {
		return !slices.Contains(strings.Fields(d.Must("apt-mark showhold")), gateApp) &&
			strings.Contains(d.Must("LC_ALL=C apt-cache policy "+gateApp+" | grep Candidate: || true"), "1.1")
	})
	d.Checkin()
	time.Sleep(2*driftInterval + 10*time.Second)
	if v := d.installedVersion(gateApp); v != "1.0" {
		t.Fatalf("required latest: the catalog moved %s to %s; only the update runs may", gateApp, v)
	}
	run = regularRun(t, d)
	if v := d.installedVersion(gateApp); v != "1.1" {
		t.Errorf("%s at %s after the second regular run, want 1.1: %v", gateApp, v, run)
	}
}

// regularRun starts the regular update run (paddock-updates.service) and returns the params of its device.updates_run.
func regularRun(t *testing.T, d *Device) map[string]any {
	t.Helper()
	seen := d.eventIDs("device.updates_run")
	d.Must("sudo systemctl start --no-block paddock-updates.service")
	run := d.waitNewEvent(t, "device.updates_run", seen, 60*time.Minute, func(p map[string]any) bool { return p["kind"] == "regular" })
	t.Logf("%s: regular run %v", d.Name, run)
	if run["result"] != "ok" {
		t.Errorf("regular run %v", run)
	}
	return run
}

// gateSW5: while the device has had no check-in for 15 minutes, a forbidden package a local administrator installs
// stays through two drift intervals as pending/deferred_offline; it is removed within one check-in once the server is
// reachable again.
func gateSW5(t *testing.T, d *Device, g *softwareGate) {
	d.reassign(g.assignment, "forbid", "")
	waitVersion(t, d, gateApp, "", 6*time.Minute, true)
	d.waitNewEvent(t, "device.software_removed", g.removed, 5*time.Minute, intentIs("forbid"))
	g.removed = d.eventIDs("device.software_removed")

	failed := d.Must("stat -c %Y /run/paddock/last-checkin-failed 2>/dev/null || echo 0")
	blockStack(d, true)
	t.Cleanup(func() { blockStack(d, false) })
	Until(t, d.Name+": a check-in fails", 3*time.Minute, 10*time.Second, d.Checkin, func() bool {
		return d.Must("stat -c %Y /run/paddock/last-checkin-failed 2>/dev/null || echo 0") != failed
	})
	d.Must("sudo touch -d '-20 min' /run/paddock/last-checkin")
	d.dpkgInstall(t, gateDeb)
	softwareState(t, d, gateApp, "pending", "deferred_offline", 3*time.Minute, nil)
	time.Sleep(2*driftInterval + 10*time.Second)
	if v := d.installedVersion(gateApp); v != "1.0" {
		t.Fatalf("%s removed while the server was unreachable (%q)", gateApp, v)
	}
	softwareState(t, d, gateApp, "pending", "deferred_offline", time.Minute, nil)

	blockStack(d, false)
	waitVersion(t, d, gateApp, "", 6*time.Minute, true)
	d.waitNewEvent(t, "device.software_removed", g.removed, 5*time.Minute, intentIs("forbid"))
	g.removed = d.eventIDs("device.software_removed")
}

// gateSW6: another process holding the dpkg lock leaves the install pending/dpkg_locked without a failure event; the
// install completes after the lock ends.
func gateSW6(t *testing.T, d *Device, g *softwareGate) {
	g.installed, g.fail = d.eventIDs("device.software_installed"), d.eventIDs("device.software_apply_failed")
	d.Must("sudo systemd-run --quiet --unit gate-lock python3 " + gateRepoDir + "/lock.py")
	t.Cleanup(func() { _, _ = d.SSH(context.Background(), nil, "sudo systemctl stop gate-lock") })
	var lastOut, lastPID string
	func() {
		defer func() {
			if t.Failed() {
				t.Logf("%s: last dpkg output (gate-lock MainPID %q):\n%s", d.Name, lastPID, lastOut)
			}
		}()
		Until(t, d.Name+": dpkg lock held by gate-lock", time.Minute, 2*time.Second, nil, func() bool {
			if d.Must("systemctl is-active gate-lock || true") != "active" {
				return false
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			out, err := d.SSH(ctx, nil, "sudo env LC_ALL=C dpkg --configure -a 2>&1")
			lastOut, lastPID = out, d.Must("systemctl show -p MainPID --value gate-lock")
			return err != nil && lastPID != "0" && lockHolder(out) == lastPID
		})
	}()

	d.reassign(g.assignment, "required", "1.0")
	softwareState(t, d, gateApp, "pending", "dpkg_locked", 6*time.Minute, d.Checkin)
	d.Checkin()
	time.Sleep(70 * time.Second)
	if failed := d.newEvents("device.software_apply_failed", g.fail, nil); len(failed) > 0 {
		t.Errorf("a dpkg lock recorded device.software_apply_failed: %+v", failed)
	}

	d.Must("sudo systemctl stop gate-lock")
	waitVersion(t, d, gateApp, "1.0", 6*time.Minute, false)
	d.waitNewEvent(t, "device.software_installed", g.installed, 5*time.Minute, intentIs("required"))
	if failed := d.newEvents("device.software_apply_failed", g.fail, nil); len(failed) > 0 {
		t.Errorf("a dpkg lock recorded device.software_apply_failed: %+v", failed)
	}
}

// gateSW7: after the repository's key changes, apt refuses the repository's signature; the source's new key needs a
// step-up (403 and a denied event without), the success records both fingerprints, and within one check-in the
// device's keyring has the new key, the repository verifies again and required pinned 1.1 installs.
func gateSW7(t *testing.T, d *Device, g *softwareGate) {
	old := g.repo.Fingerprint
	g.repo = d.rotateGateRepo()
	if out, err := d.scopedUpdateUnlocked(t, g.slug); !signatureRefused(out) {
		t.Fatalf("apt-get update after the key rotation (%v) does not refuse the signature:\n%s", err, out)
	}

	path := "/api/v1/software-sources/" + g.source
	change := map[string]any{"signing_key": g.repo.Key, "fingerprint": g.repo.Fingerprint}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	fresh, err := portal.Login(ctx, portal.Alice)
	if err != nil {
		t.Fatalf("login alice: %v", err)
	}
	defer func() {
		if res, err := fresh.Do(context.Background(), http.MethodPost, "/api/auth/logout", nil); err != nil || res.Status != http.StatusOK {
			t.Logf("logout of the session without step-up: %v HTTP %d", err, res.Status)
		}
	}()
	res, err := fresh.Do(ctx, http.MethodPatch, path, change)
	if err != nil || res.Status != http.StatusForbidden || res.ProblemCode() != "step_up_required" {
		t.Fatalf("PATCH %s without step-up: %v HTTP %d %s", path, err, res.Status, res.Body)
	}
	if ev := d.s.requestEvent(t, "software_source.updated", res.RequestID); ev.Outcome != "denied" {
		t.Errorf("software_source.updated without step-up: %+v", ev)
	}

	d.s.StepUp(t)
	res = d.s.Call(t, http.MethodPatch, path, change, http.StatusOK)
	ev := d.s.requestEvent(t, "software_source.updated", res.RequestID)
	if ev.Outcome != "success" || ev.Params["fingerprint"] != g.repo.Fingerprint || ev.Params["old_fingerprint"] != old {
		t.Errorf("software_source.updated %s %v, want fingerprint %s and old_fingerprint %s", ev.Outcome, ev.Params, g.repo.Fingerprint, old)
	}

	Until(t, d.Name+": keyring with the new key", 6*time.Minute, 10*time.Second, d.Checkin, func() bool {
		return d.keyringFingerprint(gateKeyringPath(g.slug)) == g.repo.Fingerprint
	})
	d.reassign(g.assignment, "required", "1.1")
	waitVersion(t, d, gateApp, "1.1", 6*time.Minute, true)
	if out, err := d.scopedUpdateUnlocked(t, g.slug); err != nil || signatureRefused(out) || aptError(out) {
		t.Errorf("apt-get update with the new keyring (%v):\n%s", err, out)
	}
}

// gateSW8: an edited managed source file and a rogue paddock-*.sources are corrected within the drift interval, each
// with device.tamper_protected_file_changed naming the file.
func gateSW8(t *testing.T, d *Device, g *softwareGate) {
	source, rogue := gateSourcePath(g.slug), "/etc/apt/sources.list.d/paddock-rogue.sources"
	seen := d.eventIDs("device.tamper_protected_file_changed")
	d.Must("echo '# x' | sudo tee -a " + source + " >/dev/null && sudo cp " + source + " " + rogue)
	Until(t, d.Name+": source restored and rogue file removed", 3*time.Minute, 5*time.Second, nil, func() bool {
		return d.Must("sudo sha256sum "+source+" | cut -c1-64") == sha256Hex(gateSourceFile(g.slug)) &&
			d.Must("sudo test -e "+rogue+" && echo present || echo absent") == "absent"
	})
	for _, f := range []string{source, rogue} {
		d.waitNewEvent(t, "device.tamper_protected_file_changed", seen, 5*time.Minute, func(p map[string]any) bool { return p["file"] == f })
	}
}

// windowAt is a maintenance window of every day in UTC that opens at minute start of the day (wrapped into 0..1439).
func windowAt(start, duration int) map[string]any {
	return map[string]any{"days": []int{1, 2, 3, 4, 5, 6, 7}, "start_minute": ((start % 1440) + 1440) % 1440,
		"duration_minutes": duration, "timezone": "UTC"}
}

// minuteOfDay is the UTC minute of the day of now.
func minuteOfDay(now time.Time) int { u := now.UTC(); return u.Hour()*60 + u.Minute() }

// gateSW10 (plan M13c decision 6, C2): outside the window of its group the device defers the removal of a forbidden
// package and the install of a required one as pending/outside_window through several drift passes; a window that
// opens lets the next pass remove the package; an urgent assignment, set with a reason and a step-up, installs outside
// the window. The window is put before each assignment change, so every bundle with the change carries the window.
// The VM's clock is synchronized; the closed window opens six hours from now, the open one began ten minutes ago.
func gateSW10(t *testing.T, d *Device, g *softwareGate) {
	window := "/api/v1/device-groups/" + d.Group + "/maintenance-window"
	closed := func() map[string]any { return windowAt(minuteOfDay(time.Now())+360, 30) }
	d.s.Call(t, http.MethodPut, window, closed(), http.StatusOK)
	d.s.DeleteOnCleanup(t, window)

	g.removed = d.eventIDs("device.software_removed")
	d.reassign(g.assignment, "forbid", "")
	softwareState(t, d, gateApp, "pending", "outside_window", 6*time.Minute, d.Checkin)
	time.Sleep(2*driftInterval + 10*time.Second)
	if v := d.installedVersion(gateApp); v != "1.1" {
		t.Fatalf("forbidden %s removed outside the window (%q)", gateApp, v)
	}
	softwareState(t, d, gateApp, "pending", "outside_window", time.Minute, nil)

	d.s.Call(t, http.MethodPut, window, windowAt(minuteOfDay(time.Now())-10, 120), http.StatusOK)
	waitVersion(t, d, gateApp, "", 6*time.Minute, true)
	d.waitNewEvent(t, "device.software_removed", g.removed, 5*time.Minute, intentIs("forbid"))
	g.removed = d.eventIDs("device.software_removed")

	d.s.Call(t, http.MethodPut, window, closed(), http.StatusOK)
	g.installed = d.eventIDs("device.software_installed")
	d.reassign(g.assignment, "required", "1.1")
	softwareState(t, d, gateApp, "pending", "outside_window", 6*time.Minute, d.Checkin)
	time.Sleep(2*driftInterval + 10*time.Second)
	if v := d.installedVersion(gateApp); v != "" {
		t.Fatalf("required %s installed outside the window at %s", gateApp, v)
	}

	d.s.StepUp(t)
	urgent := assignmentBody("required", "1.1")
	urgent["urgent"], urgent["reason"] = true, "system test SW10 "+d.run
	d.s.Call(t, http.MethodPatch, "/api/v1/software-assignments/"+g.assignment, urgent, http.StatusOK)
	waitVersion(t, d, gateApp, "1.1", 6*time.Minute, true)
	d.waitNewEvent(t, "device.software_installed", g.installed, 5*time.Minute, intentIs("required"))
}
