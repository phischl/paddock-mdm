package system

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

// supervisorVersion is the version of the running paddock-supervisor binary.
func (d *Device) supervisorVersion() string { return d.Must("/usr/sbin/paddock-supervisor version") }

// supervisorRelease releases this tree as a new version with its supervisor package, once for all VMs of the gate, and
// waits until the device runs the release's agent.
func supervisorRelease(t *testing.T, d *Device, gate, label string, tags []string) string {
	t.Helper()
	d.Gate(t, gate)
	v := d.Together(t, gate, "release", func() string {
		v := version(8, label)
		d.s.ReleaseSupervisor(t, v, tags)
		d.AfterAll(t, func(t *testing.T) { retractRelease(t, v) })
		return v
	})
	d.WaitEvent(t, "device.agent_updated", 12*time.Minute, func(p map[string]any) bool { return p["version"] == v })
	return v
}

// TestSupervisorUpdate is gate S-UP2a of plan M8d (AC7): after the device's agent runs the release, the agent installs
// the release's paddock-supervisor package through the transient unit, the new supervisor runs and its agent checks
// in, and the device reports device.supervisor_updated with the outcome updated.
func TestSupervisorUpdate(t *testing.T) {
	forEachVM(t, func(t *testing.T, s *Stack, vm *VM) {
		vm.Fresh()
		d := Install(t, s, vm, debDir(s))
		d.WaitEvent(t, "device.bundle_applied", 5*time.Minute, nil)
		before := d.supervisorVersion()
		v := supervisorRelease(t, d, "S-UP2a", "sup", nil)
		p := d.WaitEvent(t, "device.supervisor_updated", 15*time.Minute, func(p map[string]any) bool { return p["version"] == v })
		if p["outcome"] != "updated" || p["from_version"] != strings.Replace(before, "-", "~", 1) {
			t.Fatalf("device.supervisor_updated %v, want updated from %s", p, before)
		}
		if got := d.supervisorVersion(); got != v {
			t.Fatalf("paddock-supervisor version %s, want %s", got, v)
		}
		if state := d.Must("systemctl is-active paddock-supervisor.service || true"); state != "active" {
			t.Fatalf("paddock-supervisor.service %s", state)
		}
		// The agent checked in after dpkg installed the package.
		installed := d.Must(`date -d "$(grep ' status installed paddock-supervisor:' /var/log/dpkg.log | tail -1 | cut -d' ' -f1-2)" +%s`)
		checkin := d.Must("stat -c %Y /run/paddock/last-checkin")
		if a, b := atoi(t, checkin), atoi(t, installed); a <= b {
			t.Fatalf("last check-in %d not after the installation %d", a, b)
		}
		Until(t, "transient unit gone", 2*time.Minute, 5*time.Second, nil, func() bool {
			return d.Must("systemctl list-units --all --no-legend paddock-supervisor-upgrade.service") == ""
		})
	})
}

// TestSupervisorRollback is gate S-UP2b of plan M8d (AC7): a supervisor package whose supervisor exits 20 s after
// every start (paddock_testbroken_supervisor) is rolled back within 12 minutes; the previous supervisor runs again,
// its agent checks in, and the same version is not installed again.
func TestSupervisorRollback(t *testing.T) {
	forEachVM(t, func(t *testing.T, s *Stack, vm *VM) {
		vm.Fresh()
		d := Install(t, s, vm, debDir(s))
		d.WaitEvent(t, "device.bundle_applied", 5*time.Minute, nil)
		before := d.supervisorVersion()
		v := supervisorRelease(t, d, "S-UP2b", "supbroken", []string{"paddock_testbroken_supervisor"})
		p := d.WaitEvent(t, "device.supervisor_update_failed", 25*time.Minute, func(p map[string]any) bool { return p["version"] == v })
		if p["outcome"] != "rolled_back" {
			t.Fatalf("device.supervisor_update_failed %v, want rolled_back", p)
		}
		if got := d.supervisorVersion(); got != before {
			t.Fatalf("paddock-supervisor version %s after the rollback, want %s", got, before)
		}
		mark := atoi(t, d.Must("stat -c %Y /run/paddock/last-checkin"))
		Until(t, "check-in after the rollback", 5*time.Minute, 10*time.Second, d.Checkin, func() bool {
			return atoi(t, d.Must("stat -c %Y /run/paddock/last-checkin")) > mark
		})
		if failed := d.State()["failed_supervisor_version"]; failed != v {
			t.Fatalf("failed_supervisor_version %v, want %s", failed, v)
		}
		for range 2 {
			d.Checkin()
			time.Sleep(30 * time.Second)
		}
		if n := len(d.s.Events(t, "device.supervisor_update_failed", d.ID)) + len(d.s.Events(t, "device.supervisor_updated", d.ID)); n != 1 {
			t.Fatalf("%d supervisor events, want 1 (the failed version was installed again)", n)
		}
		if got := d.supervisorVersion(); got != before {
			t.Fatalf("paddock-supervisor version %s, want %s", got, before)
		}
	})
}

func atoi(t *testing.T, s string) int64 {
	t.Helper()
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		t.Fatalf("not a number: %q", s)
	}
	return n
}
