package system

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestOSReleaseGate (PDK-695): the agent reports the VM's os-release with its check-ins, so the device record follows
// a distribution upgrade. The upgrade is simulated by replacing /etc/os-release (the symlink to /usr/lib/os-release)
// with a file of another VERSION_ID: one device.os_release_changed with the old and new values and the new stored
// value follow; restoring the symlink changes the record back, once. Enrollment stored the original values, so the
// gate cannot pass without the check-in report.
func TestOSReleaseGate(t *testing.T) {
	forEachVM(t, func(t *testing.T, s *Stack, vm *VM) {
		vm.Fresh()
		d := Install(t, s, vm, debDir(s))
		t.Run("S-OSR1 os-release follows the device", func(t *testing.T) {
			vm.Bind(t)
			orig := strings.Fields(d.Must(". /usr/lib/os-release; echo \"$ID $VERSION_ID\""))
			if len(orig) != 2 {
				t.Fatalf("os-release of the VM: %q", orig)
			}
			const upgraded = "99.04"
			restore := func() { d.Must("sudo ln -sfn ../usr/lib/os-release /etc/os-release") }
			t.Cleanup(restore)
			d.Must("sudo sed 's/^VERSION_ID=.*/VERSION_ID=\"" + upgraded + "\"/' /usr/lib/os-release | sudo tee /etc/os-release.new >/dev/null" +
				" && sudo mv -f /etc/os-release.new /etc/os-release")

			ev := d.WaitEvent(t, "device.os_release_changed", 5*time.Minute, func(p map[string]any) bool { return p["new_version_id"] == upgraded })
			if ev["old_id"] != orig[0] || ev["old_version_id"] != orig[1] || ev["new_id"] != orig[0] || len(ev) != 4 {
				t.Fatalf("device.os_release_changed %v, want %v -> %s", ev, orig, upgraded)
			}
			if id, v := osRelease(t, d); id != orig[0] || v != upgraded {
				t.Fatalf("stored os_release %s %s, want %s %s", id, v, orig[0], upgraded)
			}

			restore()
			d.WaitEvent(t, "device.os_release_changed", 5*time.Minute, func(p map[string]any) bool { return p["new_version_id"] == orig[1] })
			if id, v := osRelease(t, d); id != orig[0] || v != orig[1] {
				t.Fatalf("stored os_release %s %s after the restore, want %v", id, v, orig)
			}
			if n := len(s.Events(t, "device.os_release_changed", d.ID)); n != 2 {
				t.Fatalf("%d device.os_release_changed, want 2 (upgrade and restore)", n)
			}
		})
	})
}

func osRelease(t *testing.T, d *Device) (id, version string) {
	t.Helper()
	var st struct {
		OSRelease map[string]string `json:"os_release"`
	}
	if err := json.Unmarshal(d.s.Call(t, http.MethodGet, "/api/v1/devices/"+d.ID, nil, http.StatusOK).Body, &st); err != nil {
		t.Fatal(err)
	}
	return st.OSRelease["id"], st.OSRelease["version_id"]
}
