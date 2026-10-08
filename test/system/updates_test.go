package system

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestUpdatesGates runs the device gates of plan M5b on the VMs in parallel, each from a fresh base-installed: U1
// (holds become apt-mark holds, pins and the unattended-upgrades blacklist, and go again), U2 (install now) and U3
// (the regular update run on a schedule a few minutes ahead, and a security run). The organization's update schedule
// is shared: U3 moves it once for both VMs and puts it back when the gate ends.
func TestUpdatesGates(t *testing.T) {
	forEachVM(t, func(t *testing.T, s *Stack, vm *VM) {
		vm.Gate(t, "updates")
		vm.Fresh()
		// Fresh masks the distribution's apt timers for every gate (aptUnits); these gates are about them. The agent
		// never unmasks a timer itself: a masked timer is the device owner's decision and reported as an error.
		vm.Must("sudo systemctl unmask apt-daily.timer apt-daily-upgrade.timer")
		d := Install(t, s, vm, debDir(s))
		if !t.Run("U1 holds", func(t *testing.T) { gateU1(t, d) }) {
			t.FailNow()
		}
		t.Run("U2 install now", func(t *testing.T) { gateU2(t, d) })
		t.Run("U3 scheduled runs", func(t *testing.T) { gateU3(t, d) })
	})
}

// hold creates a package hold for the device's group and returns its ID.
func (d *Device) hold(pkg, version string) string {
	d.t.Helper()
	body := map[string]any{"package": pkg, "device_group_id": d.Group, "reason": "system test " + d.run}
	if version != "" {
		body["version"] = version
	}
	id := d.s.ID(d.s.Call(http.MethodPost, "/api/v1/package-holds", body, http.StatusCreated))
	d.s.DeleteOnCleanup("/api/v1/package-holds/" + id)
	return id
}

// gateU1: a versionless hold is an apt-mark hold, a versioned one a pin with priority 1001; both are blacklisted for
// unattended-upgrades, which allows the security pocket only. Removing the holds reverts all of it.
func gateU1(t *testing.T, d *Device) {
	const free, pinned = "rsync", "nano"
	version := d.Must("dpkg-query -W -f '${Version}' " + pinned)
	holds := []string{d.hold(free, ""), d.hold(pinned, version)}
	pin := fmt.Sprintf("Package: %s\nPin: version %s\nPin-Priority: 1001", pinned, version)
	Until(t, d.Name+": holds applied", 5*time.Minute, 10*time.Second, d.Checkin, func() bool {
		return strings.Contains(d.Must("apt-mark showhold"), free) &&
			strings.Contains(d.Must("cat /etc/apt/preferences.d/50paddock 2>/dev/null || true"), pin)
	})
	if held := d.Must("apt-mark showhold"); strings.Contains(held, pinned) {
		t.Errorf("versioned hold is an apt-mark hold too: %q", held)
	}
	config := d.Must("apt-config dump | grep -E '^Unattended-Upgrade::(Allowed-Origins|Origins-Pattern|Package-Blacklist)' || true")
	for _, want := range []string{`"^rsync$"`, `"^nano$"`, `-security"`} {
		if !strings.Contains(config, want) {
			t.Errorf("unattended-upgrades configuration lacks %s:\n%s", want, config)
		}
	}
	// List items are "<list>:: \"value\";"; the list heads carry an empty value.
	for _, line := range strings.Split(config, "\n") {
		if strings.HasPrefix(line, "Unattended-Upgrade::Origins-Pattern::") ||
			(strings.HasPrefix(line, "Unattended-Upgrade::Allowed-Origins::") && !strings.Contains(line, "-security")) {
			t.Errorf("unattended-upgrades allows more than the security pocket: %s", line)
		}
	}
	if out := d.Must("systemctl cat apt-daily-upgrade.timer | grep -E '^(OnCalendar|RandomizedDelaySec)='"); !strings.Contains(out, "OnCalendar=*-*-* ") {
		t.Errorf("apt-daily-upgrade.timer: %q", out)
	}
	if out := d.Must("systemctl is-enabled paddock-updates.timer; systemctl is-active paddock-updates.timer"); out != "enabled\nactive" {
		t.Errorf("paddock-updates.timer: %q", out)
	}

	for _, id := range holds {
		d.s.Call(http.MethodDelete, "/api/v1/package-holds/"+id, nil, http.StatusNoContent)
	}
	Until(t, d.Name+": holds released", 5*time.Minute, 10*time.Second, d.Checkin, func() bool {
		return !strings.Contains(d.Must("apt-mark showhold"), free) &&
			d.Must("test -e /etc/apt/preferences.d/50paddock && echo present || echo absent") == "absent"
	})
	if config := d.Must("apt-config dump | grep -E '^Unattended-Upgrade::Package-Blacklist' || true"); strings.Contains(config, "rsync") || strings.Contains(config, "nano") {
		t.Errorf("blacklist after release:\n%s", config)
	}
}

// gateU2: a package that is not installed is installed within one check-in of install now (plan M5b AC3).
func gateU2(t *testing.T, d *Device) {
	const pkg = "hello"
	if out := d.Must("dpkg-query -W -f '${Status}' " + pkg + " 2>/dev/null || true"); out == "install ok installed" {
		t.Fatalf("%s: %s is installed before the gate", d.Name, pkg)
	}
	command := d.s.ID(d.s.Call(http.MethodPost, "/api/v1/devices/"+d.ID+"/install-now", map[string]any{"packages": []string{pkg}}, http.StatusAccepted))
	start := time.Now()
	Until(t, d.Name+": "+pkg+" installed", 10*time.Minute, 10*time.Second, d.Checkin, func() bool {
		return d.Must("dpkg-query -W -f '${Status}' "+pkg+" 2>/dev/null || true") == "install ok installed"
	})
	t.Logf("%s: %s installed %s after the request", d.Name, pkg, time.Since(start).Round(time.Second))
	Until(t, d.Name+": install_now result", 5*time.Minute, 10*time.Second, d.Checkin, func() bool {
		var page struct {
			Items []struct {
				ID     string         `json:"id"`
				Status string         `json:"status"`
				Result map[string]any `json:"result"`
			} `json:"items"`
		}
		res := d.s.Call(http.MethodGet, "/api/v1/devices/"+d.ID+"/commands?type=install_now", nil, http.StatusOK)
		if err := json.Unmarshal(res.Body, &page); err != nil {
			t.Fatal(err)
		}
		for _, c := range page.Items {
			if c.ID == command && c.Status != "pending" && c.Status != "delivered" {
				if c.Status != "succeeded" {
					t.Fatalf("install_now %s: %+v", c.Status, c.Result)
				}
				return true
			}
		}
		return false
	})
}

// downgradable returns installed packages of candidates for which apt offers an older version, with that version.
func (d *Device) downgradable(candidates ...string) [][2]string {
	d.t.Helper()
	script := "for p in " + strings.Join(candidates, " ") + "; do i=$(dpkg-query -W -f '${Version}' $p 2>/dev/null) || continue; " +
		"o=$(apt-cache madison $p | tail -n 1 | cut -d '|' -f 2 | tr -d ' '); " +
		"[ -n \"$o\" ] && [ \"$o\" != \"$i\" ] && echo \"$p $o\"; done; true"
	var out [][2]string
	for _, line := range strings.Split(d.Must(script), "\n") {
		if f := strings.Fields(line); len(f) == 2 {
			out = append(out, [2]string{f[0], f[1]})
		}
	}
	return out
}

// gateU3: with the regular schedule a few minutes ahead (no random delay), paddock-updates.service runs and reports
// updates.run with its counts; an older package version the test installed is upgraded, a held one is not, and the
// reboot marker the test leaves is reported. A security run (apt-daily-upgrade.service) is reported as well.
func gateU3(t *testing.T, d *Device) {
	old := d.downgradable("wget", "rsync", "less", "nano", "curl", "bzip2", "gzip")
	if len(old) < 2 {
		t.Fatalf("%s: need two packages with an older version in apt, found %v", d.Name, old)
	}
	upgrade, held := old[0], old[1]

	// The schedule a few minutes ahead and no random delay, once for both VMs. Without the delay, the restarted
	// apt-daily-upgrade.timer catches up on the missed security run (Persistent=true) right away instead of up to an
	// hour later, when it would upgrade the downgraded packages again before the regular run.
	at := d.Together(t, "updates", "regular schedule", func() string {
		previous := d.s.Call(http.MethodGet, "/api/v1/settings/updates", nil, http.StatusOK)
		var settings map[string]any
		if err := json.Unmarshal(previous.Body, &settings); err != nil {
			t.Fatal(err)
		}
		delete(settings, "updated_at")
		t.Cleanup(func() { d.s.Call(http.MethodPut, "/api/v1/settings/updates", settings, http.StatusOK) })
		next := map[string]any{}
		for k, v := range settings {
			next[k] = v
		}
		at := d.Must("date -d '+15 min' +%H:%M")
		next["regular_schedule"], next["regular_updates_enabled"], next["max_random_delay_min"] = at, true, 0
		d.s.Call(http.MethodPut, "/api/v1/settings/updates", next, http.StatusOK)
		return at
	})
	Until(t, d.Name+": timer at "+at, 4*time.Minute, 10*time.Second, d.Checkin, func() bool {
		return strings.Contains(d.Must("systemctl cat paddock-updates.timer | grep '^OnCalendar=' || true"), "OnCalendar="+at) &&
			strings.Contains(d.Must("systemctl cat apt-daily-upgrade.timer | grep '^RandomizedDelaySec=' || true"), "RandomizedDelaySec=0m")
	})
	Until(t, d.Name+": apt idle", 10*time.Minute, 15*time.Second, nil, func() bool {
		return d.Must("systemctl is-active apt-daily.service apt-daily-upgrade.service | grep -cx 'active\\|activating' || true") == "0" &&
			d.Must("pgrep -c -x 'unattended-upgr|apt-get|apt|dpkg' || true") == "0"
	})

	// The hold comes first, so the package is never unheld while apt may run.
	d.hold(held[0], "")
	Until(t, d.Name+": "+held[0]+" held", 5*time.Minute, 10*time.Second, d.Checkin, func() bool {
		return strings.Contains(d.Must("apt-mark showhold"), held[0])
	})
	for _, p := range old[:2] {
		d.Must(fmt.Sprintf("sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q --allow-downgrades --allow-change-held-packages "+
			"-o DPkg::Lock::Timeout=300 %s=%s", p[0], p[1]))
	}
	// Installing a held package with --allow-change-held-packages releases the hold; the agent's drift pass sets it again.
	Until(t, d.Name+": "+held[0]+" held again", 5*time.Minute, 10*time.Second, nil, func() bool {
		return strings.Contains(d.Must("apt-mark showhold"), held[0])
	})
	d.Must("sudo touch /var/run/reboot-required")
	if v := d.Must("dpkg-query -W -f '${Version}' " + upgrade[0]); v != upgrade[1] {
		t.Fatalf("%s: %s is at %s before the regular run, want %s", d.Name, upgrade[0], v, upgrade[1])
	}
	start := time.Now()
	run := d.WaitEvent(t, "device.updates_run", 75*time.Minute, func(p map[string]any) bool { return p["kind"] == "regular" })
	t.Logf("%s: regular run after %s: %v", d.Name, time.Since(start).Round(time.Second), run)
	if run["result"] != "ok" || run["reboot_required"] != true {
		t.Errorf("updates.run %v", run)
	}
	if n, _ := run["upgraded"].(float64); n < 1 {
		t.Errorf("updates.run upgraded %v", run["upgraded"])
	}
	if v := d.Must("dpkg-query -W -f '${Version}' " + upgrade[0]); v == upgrade[1] {
		t.Errorf("%s still at %s after the regular run", upgrade[0], v)
	}
	if v := d.Must("dpkg-query -W -f '${Version}' " + held[0]); v != held[1] {
		t.Errorf("held %s changed from %s to %s", held[0], held[1], v)
	}
	if out := d.Must("journalctl -u paddock-updates.service --no-pager -o cat | grep -c 'regular updates finished' || true"); out == "0" {
		t.Errorf("paddock-updates.service did not run paddockd updates run")
	}
	Until(t, d.Name+": updates of the device", 3*time.Minute, 10*time.Second, d.Checkin, func() bool {
		var u struct {
			LastRegularRun *struct {
				Params map[string]any `json:"params"`
			} `json:"last_regular_run"`
			RebootRequired bool `json:"reboot_required"`
		}
		res := d.s.Call(http.MethodGet, "/api/v1/devices/"+d.ID+"/updates", nil, http.StatusOK)
		return json.Unmarshal(res.Body, &u) == nil && u.LastRegularRun != nil && u.RebootRequired
	})

	// A security run the gate starts is reported once it ends; an earlier one (the unmasked timers catch up on the
	// missed run) does not count.
	triggered := time.Now().Add(-time.Minute)
	d.Must("sudo systemctl start --no-block apt-daily-upgrade.service")
	security := d.WaitEvent(t, "device.updates_run", 45*time.Minute, func(p map[string]any) bool {
		started, err := time.Parse(time.RFC3339Nano, fmt.Sprint(p["started_at"]))
		return p["kind"] == "security" && err == nil && started.After(triggered)
	})
	t.Logf("%s: security run: %v", d.Name, security)
	if security["result"] != "ok" {
		t.Errorf("security run %v", security)
	}
}
