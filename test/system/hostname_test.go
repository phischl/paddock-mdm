package system

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestHostnameGate runs gate S-HN1 of plan M8h on each VM, from a fresh base install: a name set in the portal
// becomes the static and transient hostname without a reboot (systemd leaves the pretty hostname empty, ADR 0041
// amendment 2026-10-18), /etc/hosts and Avahi follow and sudo keeps resolving the host; a local rename is corrected as
// drift and the device then converges; a cleared name is left alone; the inventory mapping survives; the VM ends with
// its original hostname.
func TestHostnameGate(t *testing.T) {
	forEachVM(t, func(t *testing.T, s *Stack, vm *VM) {
		vm.Fresh()
		d := Install(t, s, vm, debDir(s))
		t.Run("S-HN1 device name", func(t *testing.T) {
			vm.Bind(t)
			vm.group.Exclusive(t, "device name") // the gate renames the device the other gates address
			gateHN1(t, d)
		})
	})
}

type deviceNameState struct {
	Hostname     string  `json:"hostname"`
	Name         *string `json:"name"`
	NameState    string  `json:"name_state"`
	HardwareUUID *string `json:"hardware_uuid"`
	Applied      *int64  `json:"applied_bundle_version"`
	Bundle       int64   `json:"bundle_version"`
}

func (d *Device) nameState(t *testing.T) deviceNameState {
	t.Helper()
	var st deviceNameState
	if err := json.Unmarshal(d.s.Call(http.MethodGet, "/api/v1/devices/"+d.ID, nil, http.StatusOK).Body, &st); err != nil {
		t.Fatal(err)
	}
	return st
}

func (d *Device) setName(name any) {
	d.s.Call(http.MethodPut, "/api/v1/devices/"+d.ID+"/name", map[string]any{"name": name}, http.StatusOK)
}

// hostnames are the static, transient and pretty hostname of the device.
func (d *Device) hostnames() [3]string {
	return [3]string{d.Must("hostnamectl --static"), d.Must("hostname"), d.Must("hostnamectl --pretty")}
}

// namedAs reports whether hostnames carry name: static and transient are the name; the pretty name is empty, which
// hostnamectl leaves for a valid host name, or the name.
func namedAs(names [3]string, name string) bool {
	return names[0] == name && names[1] == name && (names[2] == "" || names[2] == name)
}

// hostnameDriftPasses counts the agent's journal lines since the unix time since that report a drift correction, or
// a failed one, of the hostname resource.
func hostnameDriftPasses(d *Device, since int64) string {
	return d.Must("sudo journalctl -u paddock-supervisor --since @" + strconv.FormatInt(since, 10) +
		" --no-pager -o cat | grep -E 'drift correct(ed|ion failed)' | grep -c hostname || true")
}

// checkinTick triggers a check-in at most once per 65 s (the agent's limit).
func (d *Device) checkinTick() func() {
	last := time.Time{}
	return func() {
		if time.Since(last) > 65*time.Second {
			d.Checkin()
			last = time.Now()
		}
	}
}

func hasHostsLine(hosts, name string) bool {
	for line := range strings.Lines(hosts) {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "127.0.1.1" && f[1] == name {
			return true
		}
	}
	return false
}

func gateHN1(t *testing.T, d *Device) {
	original := d.hostnames()
	d.Must("sudo cp -p /etc/hosts /var/tmp/hosts.s-hn1")
	before := d.nameState(t)
	// (e) The VM ends with its original names and /etc/hosts; the managed name is cleared first so that the agent
	// does not rename it back.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if res, err := d.s.alice.Do(ctx, http.MethodPut, "/api/v1/devices/"+d.ID+"/name", map[string]any{"name": nil}); err != nil ||
			(res.Status != http.StatusOK && res.Status != http.StatusNotFound) {
			t.Errorf("cleanup: clearing the name: %v %+v", err, res)
		}
		d.Must("sudo hostnamectl hostname '" + original[0] + "' && sudo hostnamectl hostname --pretty '" + original[2] + "'" +
			" && sudo cp -p /var/tmp/hosts.s-hn1 /etc/hosts && sudo rm -f /var/tmp/hosts.s-hn1")
		if got := d.hostnames(); got != original {
			t.Errorf("%s: hostnames after the gate %v, want %v", d.Name, got, original)
		}
	})
	name := "s-hn1-" + d.Name + "-" + d.run
	tick := d.checkinTick()

	// (a) The name is applied at a check-in without a reboot.
	bootID := d.Must("cat /proc/sys/kernel/random/boot_id")
	startedAt, err := strconv.ParseInt(d.Must("date +%s"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	d.setName(name)
	time.Sleep(5 * time.Second) // the compiler publishes the bundle
	Until(t, d.Name+": hostnames "+name, 10*time.Minute, 5*time.Second, tick, func() bool { return namedAs(d.hostnames(), name) })
	version := float64(d.nameState(t).Bundle)
	d.WaitEvent(t, "device.bundle_applied", 5*time.Minute, func(p map[string]any) bool {
		if v, _ := p["bundle_version"].(float64); v < version {
			return false
		}
		errs, _ := p["errors"].([]any)
		for _, e := range errs {
			if m, _ := e.(map[string]any); m["id"] == "hostname" {
				t.Errorf("%s: bundle.applied error for hostname: %v", d.Name, m)
			}
		}
		return true
	})
	if hosts := d.Must("cat /etc/hosts"); !hasHostsLine(hosts, name) {
		t.Errorf("%s: /etc/hosts without 127.0.1.1 %s:\n%s", d.Name, name, hosts)
	}
	if out, _ := d.SSH(context.Background(), nil, "sudo -n true 2>&1"); strings.Contains(out, "unable to resolve host") {
		t.Errorf("%s: sudo warns: %s", d.Name, out)
	}
	if d.Must("systemctl is-active avahi-daemon.service || true") == "active" {
		at := strings.TrimPrefix(d.Must("systemctl show -p ActiveEnterTimestamp --value --timestamp=unix avahi-daemon.service"), "@")
		if sec, err := strconv.ParseInt(at, 10, 64); err != nil || sec < startedAt {
			t.Errorf("%s: avahi-daemon not restarted after the rename: ActiveEnterTimestamp %q, rename at %d", d.Name, at, startedAt)
		}
	}
	if got := d.Must("cat /proc/sys/kernel/random/boot_id"); got != bootID {
		t.Errorf("%s: the device rebooted", d.Name)
	}
	Until(t, d.Name+": name_state applied", 5*time.Minute, 5*time.Second, tick, func() bool {
		st := d.nameState(t)
		return st.NameState == "applied" && st.Hostname == name
	})

	// (d) The inventory mapping survives the rename.
	if st := d.nameState(t); st.HardwareUUID == nil || before.HardwareUUID == nil || *st.HardwareUUID != *before.HardwareUUID {
		t.Errorf("%s: hardware_uuid %v, before %v", d.Name, st.HardwareUUID, before.HardwareUUID)
	}
	d.s.Call(http.MethodGet, "/api/v1/devices/"+d.ID+"/software", nil, http.StatusOK)

	// (b) A local rename is drift: corrected within the drift interval and reported.
	d.Must("sudo hostnamectl hostname other-" + d.run)
	d.WaitEvent(t, "device.config_drift_corrected", 5*time.Minute, func(p map[string]any) bool {
		ids, _ := p["resource_ids"].([]any)
		return slices.Contains(ids, any("hostname"))
	})
	Until(t, d.Name+": name restored after the local rename", 2*time.Minute, 5*time.Second, nil, func() bool { return namedAs(d.hostnames(), name) })
	hn1Converged(t, d, name)

	// (c) A cleared name is not managed: the device keeps it and a local rename stays.
	d.setName(nil)
	time.Sleep(5 * time.Second)
	cleared := d.nameState(t).Bundle
	Until(t, d.Name+": bundle without the hostname section applied", 5*time.Minute, 5*time.Second, tick, func() bool {
		st := d.nameState(t)
		return st.Applied != nil && *st.Applied >= cleared
	})
	if got := d.hostnames(); !namedAs(got, name) {
		t.Errorf("%s: hostnames after clearing %v, want %s", d.Name, got, name)
	}
	local := "local-" + d.run
	d.Must("sudo hostnamectl hostname " + local)
	time.Sleep(90 * time.Second) // three drift intervals of the development build (30 s)
	if got := d.Must("hostnamectl --static"); got != local {
		t.Errorf("%s: a local rename of an unmanaged name was changed to %q", d.Name, got)
	}
}

// hn1Converged checks that the device converges after a correction (review 1 finding 1): two consecutive drift passes
// change nothing, report no config.drift_corrected for the hostname and leave avahi-daemon running as it was.
func hn1Converged(t *testing.T, d *Device, name string) {
	t.Helper()
	time.Sleep(15 * time.Second) // the correcting pass's event reaches the audit log
	corrected := len(hostnameDriftEvents(d))
	avahi := d.Must("systemctl show -p ActiveEnterTimestamp --value --timestamp=unix avahi-daemon.service")
	since, err := strconv.ParseInt(d.Must("date +%s"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(70 * time.Second) // two drift passes of the development build (30 s)
	if n := hostnameDriftPasses(d, since); n != "0" {
		t.Errorf("%s: %s drift passes corrected the hostname again after it converged", d.Name, n)
	}
	var plan struct {
		Resources []struct {
			ID      string   `json:"id"`
			Changes []string `json:"changes"`
		} `json:"resources"`
	}
	if err := json.Unmarshal([]byte(d.Must("sudo paddockd plan")), &plan); err != nil {
		t.Fatal(err)
	}
	for _, r := range plan.Resources {
		if r.ID == "hostname" && len(r.Changes) > 0 {
			t.Errorf("%s: the converged hostname plans %v", d.Name, r.Changes)
		}
	}
	if got := d.hostnames(); !namedAs(got, name) {
		t.Errorf("%s: hostnames after two drift passes %v, want %s", d.Name, got, name)
	}
	if got := d.Must("systemctl show -p ActiveEnterTimestamp --value --timestamp=unix avahi-daemon.service"); got != avahi {
		t.Errorf("%s: avahi-daemon restarted after the device converged: %s, before %s", d.Name, got, avahi)
	}
	d.Checkin()
	time.Sleep(15 * time.Second) // a config.drift_corrected spooled by the two passes reaches the audit log
	if n := len(hostnameDriftEvents(d)); n != corrected {
		t.Errorf("%s: %d config.drift_corrected events for the hostname after it converged", d.Name, n-corrected)
	}
}

// hostnameDriftEvents are the device's config.drift_corrected audit events that name the hostname resource.
func hostnameDriftEvents(d *Device) []map[string]any {
	var out []map[string]any
	for _, e := range d.s.Events("device.config_drift_corrected", d.ID) {
		if ids, _ := e.Params["resource_ids"].([]any); slices.Contains(ids, any("hostname")) {
			out = append(out, e.Params)
		}
	}
	return out
}
