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
// becomes the static, transient and pretty hostname without a reboot, /etc/hosts and Avahi follow and sudo keeps
// resolving the host; a local rename is corrected as drift; a cleared name is left alone; the inventory mapping
// survives; the VM ends with its original hostname.
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
	want := [3]string{name, name, name}
	Until(t, d.Name+": hostnames "+name, 10*time.Minute, 5*time.Second, tick, func() bool { return d.hostnames() == want })
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
	Until(t, d.Name+": name restored after the local rename", 2*time.Minute, 5*time.Second, nil, func() bool { return d.hostnames() == want })

	// (c) A cleared name is not managed: the device keeps it and a local rename stays.
	d.setName(nil)
	time.Sleep(5 * time.Second)
	cleared := d.nameState(t).Bundle
	Until(t, d.Name+": bundle without the hostname section applied", 5*time.Minute, 5*time.Second, tick, func() bool {
		st := d.nameState(t)
		return st.Applied != nil && *st.Applied >= cleared
	})
	if got := d.hostnames(); got != want {
		t.Errorf("%s: hostnames after clearing %v, want %v", d.Name, got, want)
	}
	local := "local-" + d.run
	d.Must("sudo hostnamectl hostname " + local)
	time.Sleep(90 * time.Second) // three drift intervals of the development build (30 s)
	if got := d.Must("hostnamectl --static"); got != local {
		t.Errorf("%s: a local rename of an unmanaged name was changed to %q", d.Name, got)
	}
}
