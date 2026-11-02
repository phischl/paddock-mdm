package system

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// watchDemo is the third-party unit gate N12 watches; the gate writes it on the VM and removes it again.
const watchDemo = "watchdemo.service"

// TestWatchGate runs gate N12 of plan M9 on the VMs in parallel, each from a fresh base install: the organization's
// presence policy watches a unit, a stop is reported once with its state and the agent leaves the unit stopped, a
// second stop after a manual start is a second report, and a removed unit is reported as missing.
func TestWatchGate(t *testing.T) {
	forEachVM(t, func(t *testing.T, s *Stack, vm *VM) {
		vm.Gate(t, "watch")
		vm.Fresh()
		d := Install(t, s, vm, debDir(s))
		t.Run("N12 presence policy", func(t *testing.T) { d.Bind(t); gateN12(t, s, d) })
	})
}

// watchReports counts the device's tamper.service_stopped events of watchdemo.service with state.
func watchReports(t *testing.T, d *Device, state string) int {
	t.Helper()
	n := 0
	for _, e := range d.s.Events(t, "device.tamper_service_stopped", d.ID) {
		if e.Params["unit"] == watchDemo && e.Params["state"] == state {
			n++
		}
	}
	return n
}

// waitWatchReports waits until the device reported watchdemo.service with state want times; the drift pass runs
// every 30 s on the VMs, the 6 minutes are the gate's bound.
func waitWatchReports(t *testing.T, d *Device, state string, want int) {
	t.Helper()
	last := time.Time{}
	Until(t, fmt.Sprintf("%s: %d report(s) of %s %s", d.Name, want, watchDemo, state), 6*time.Minute, 5*time.Second, func() {
		if time.Since(last) > 65*time.Second {
			d.Checkin()
			last = time.Now()
		}
	}, func() bool { return watchReports(t, d, state) >= want })
	if n := watchReports(t, d, state); n != want {
		t.Fatalf("%s: %d reports of %s %s, want %d", d.Name, n, watchDemo, state, want)
	}
}

// gateN12 is gate N12 of plan M9 (decision 40).
func gateN12(t *testing.T, s *Stack, d *Device) {
	unit := "[Unit]\nDescription=Paddock gate N12 (watched third-party service)\n[Service]\nExecStart=/bin/sleep infinity\n"
	d.MustIn([]byte(unit), "sudo tee /etc/systemd/system/"+watchDemo+" >/dev/null && sudo systemctl daemon-reload && sudo systemctl start "+watchDemo)
	t.Cleanup(func() {
		d.Must("sudo systemctl stop " + watchDemo + " 2>/dev/null; sudo rm -f /etc/systemd/system/" + watchDemo + " && sudo systemctl daemon-reload")
	})
	// The presence policy belongs to the organization: set once for all VMs, cleared after every VM's gate.
	d.Together(t, "watch", "policy", func() string {
		s.StepUp(t)
		s.Call(t, http.MethodPut, "/api/v1/settings/watched-units", map[string]any{"units": []string{watchDemo}}, http.StatusOK)
		d.AfterAll(t, func(t *testing.T) {
			s.StepUp(t)
			s.Call(t, http.MethodPut, "/api/v1/settings/watched-units", map[string]any{"units": []string{}}, http.StatusOK)
		})
		return ""
	})
	if n := watchReports(t, d, "inactive"); n != 0 {
		t.Fatalf("%s: %d reports while the unit runs", d.Name, n)
	}

	d.Must("sudo systemctl stop " + watchDemo)
	waitWatchReports(t, d, "inactive", 1)
	// The agent reports and never starts the unit (agent design contract 8).
	for end := time.Now().Add(2 * time.Minute); time.Now().Before(end); time.Sleep(10 * time.Second) {
		if state := d.Must("systemctl is-active " + watchDemo + " || true"); state != "inactive" {
			t.Fatalf("%s: %s is %q after the report", d.Name, watchDemo, state)
		}
	}
	if n := watchReports(t, d, "inactive"); n != 1 {
		t.Fatalf("%s: %d reports of one stop", d.Name, n)
	}

	running := func() {
		// The VM's clock, not the host's, dates its journal.
		since := d.Must("date +%s")
		d.Must("sudo systemctl start " + watchDemo)
		Until(t, d.Name+": the agent saw "+watchDemo+" running again", 3*time.Minute, 5*time.Second, nil, func() bool {
			log := d.Must(fmt.Sprintf("sudo journalctl -u paddock-supervisor --since @%s --no-pager -o cat | grep 'watched unit running again' || true", since))
			return strings.Contains(log, watchDemo)
		})
	}
	running()
	d.Must("sudo systemctl stop " + watchDemo)
	waitWatchReports(t, d, "inactive", 2)

	// A removed unit file is an unknown unit: missing.
	running()
	d.Must("sudo rm /etc/systemd/system/" + watchDemo + " && sudo systemctl daemon-reload && sudo systemctl stop " + watchDemo)
	waitWatchReports(t, d, "missing", 1)
}
