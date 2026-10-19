package system

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// uninstallWorld is an enrolled device with its managed local administrator and Himmelblau installed, the state an
// uninstall starts from.
type uninstallWorld struct {
	*laWorld
}

func newUninstallWorld(t *testing.T, s *Stack, vm *VM) *uninstallWorld {
	t.Helper()
	vm.Fresh()
	d := Install(t, s, vm, debDir(s))
	d.WaitEvent(t, "device.bundle_applied", 5*time.Minute, nil)
	w := &uninstallWorld{laWorld: newLAWorld(t, d)}
	d.WaitEvent(t, "device.login_applied", 15*time.Minute, nil)
	return w
}

// absent fails when a path exists on the VM.
func (w *uninstallWorld) absent(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if out := w.Must("sudo test -e " + p + " && echo present || echo absent"); out != "absent" {
			t.Fatalf("%s is still there", p)
		}
	}
}

// present fails when a path does not exist on the VM.
func (w *uninstallWorld) present(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if out := w.Must("sudo test -e " + p + " && echo present || echo absent"); out != "present" {
			t.Fatalf("%s was removed", p)
		}
	}
}

// packagesGone fails while a Paddock or fleetd package is installed.
func (w *uninstallWorld) packagesGone(t *testing.T) {
	t.Helper()
	if out := w.Must("dpkg-query -W -f '${Package} ${db:Status-Abbrev}\\n' 'paddock-*' fleet-osquery 2>/dev/null | grep ' ii' || true"); out != "" {
		t.Fatalf("packages left: %s", out)
	}
}

// vmAdmin is the test VMs' install administrator (PADDOCK_USER of test/vms) and acme's break-glass account; it keeps
// passwordless sudo through /etc/sudoers.d/90-paddock, which names the user, not a group. The VMs have no vagrant
// account: Himmelblau's NSS module answers for that name with a synthetic entry.
const vmAdmin = "paddock"

// inSudo reports whether an account is a member of the sudo group.
func (w *uninstallWorld) inSudo(user string) bool {
	return strings.Contains(" "+w.Must("id -nG "+user)+" ", " sudo ")
}

// TestUninstallLeave is gate S-UN1 of plan M8d (AC8): mode leave removes Paddock and keeps the managed file, the
// managed local administrator, the install administrator's (break-glass account's) sudo, Himmelblau and its configuration; the device reports
// once, is retired by it and still boots.
func TestUninstallLeave(t *testing.T) {
	forEachVM(t, func(t *testing.T, s *Stack, vm *VM) {
		w := newUninstallWorld(t, s, vm)
		managed := w.managedPath("a")
		w.RequestUninstall("leave", nil, http.StatusOK)
		p := w.WaitRetired(t, 10*time.Minute)
		if p["outcome"] != "completed" || p["local_admin"] != "kept" || p["tpm"] != "not_requested" {
			t.Fatalf("device.uninstalled %v", p)
		}
		w.packagesGone(t)
		w.absent(t, "/etc/paddock", "/var/lib/paddock", "/opt/paddock", "/opt/orbit")
		if out := w.Must("sudo find /etc/sudoers.d -name 'paddock-u-*'"); out != "" {
			t.Fatalf("sudoers files left: %s", out)
		}
		if out := w.Must("systemctl list-unit-files paddock-supervisor.service --no-legend || true"); out != "" {
			t.Fatalf("paddock-supervisor.service still known: %s", out)
		}
		w.present(t, managed, "/etc/himmelblau/himmelblau.conf", "/root/paddock-uninstall/result.json")
		w.Must("getent passwd " + localAdmin)
		if !w.inSudo(vmAdmin) {
			t.Fatal(vmAdmin + " lost sudo")
		}
		if out := w.Must("dpkg-query -W -f '${db:Status-Abbrev}' himmelblau"); !strings.HasPrefix(out, "ii") {
			t.Fatalf("himmelblau package %q", out)
		}
		w.Must("sudo visudo -c")
		vm.RebootWithPassphrase(t)
	})
}

// TestUninstallReset is gate S-UN2 of plan M8d (AC9): mode reset with clear_tpm on the passphrase-only base VM also
// removes Himmelblau, the unchanged managed file and the managed local administrator; a modified managed file, the
// home directories, the install administrator's sudo and the LUKS passphrase stay, and the TPM is cleared or its clear requested.
func TestUninstallReset(t *testing.T) {
	forEachVM(t, func(t *testing.T, s *Stack, vm *VM) {
		w := newUninstallWorld(t, s, vm)
		unchanged, modified := w.managedPath("a"), w.managedPath("b")
		homes := w.Must("ls -1 /home | sort")
		// Managed files stay enforced until the removal starts, so b is modified while the agent is stopped and the
		// agent comes back with a drift interval the removal never reaches. After its start the agent corrects files
		// only in a drift pass (first one a drift interval after its run loop started) or by applying a newer bundle
		// (handleBundle, first in Cycle); its first Cycle checks in at once and, without a newer bundle, accepts the
		// command (handleCommands), reports it (postResults) and starts the removal (launchUninstall), whose first
		// step stops the agent. A request compiles no bundle, so the compiled version is applied first and checked
		// unchanged.
		Until(t, "the compiled bundle applied", 5*time.Minute, 5*time.Second, w.Checkin, func() bool {
			applied, _ := w.State()["applied_bundle_version"].(float64)
			return applied == w.bundleVersion()
		})
		compiled := w.bundleVersion()
		w.Must("sudo systemctl stop paddock-supervisor && echo 'changed at the device' | sudo tee -a " + modified + " >/dev/null" +
			" && echo 'drift_interval_s: 86400' | sudo tee -a /etc/paddock/agent.yml >/dev/null")
		w.RequestUninstall("reset", map[string]any{"clear_tpm": true}, http.StatusOK)
		if v := w.bundleVersion(); v != compiled {
			t.Fatalf("bundle %v compiled after %v while the agent was stopped: it would restore %s before the removal", v, compiled, modified)
		}
		w.Must("sudo systemctl start paddock-supervisor")
		p := w.WaitRetired(t, 15*time.Minute)
		if p["outcome"] != "completed" || p["local_admin"] != "removed" || (p["tpm"] != "cleared" && p["tpm"] != "requested_at_next_boot") {
			t.Fatalf("device.uninstalled %v", p)
		}
		if p["tpm"] == "cleared" {
			if out := w.Must("sudo tpm2_getcap properties-variable"); !strings.Contains(out, "lockoutAuthSet:            0") &&
				!strings.Contains(out, "lockoutAuthSet: 0") {
				t.Fatalf("TPM after the clear:\n%s", out)
			}
		}
		w.packagesGone(t)
		if out := w.Must("dpkg-query -W -f '${Package} ${db:Status-Abbrev}\\n' 'himmelblau*' 'pam-himmelblau' 'nss-himmelblau' 2>/dev/null | grep ' ii' || true"); out != "" {
			t.Fatalf("Himmelblau packages left: %s", out)
		}
		w.absent(t, "/etc/himmelblau", unchanged)
		w.present(t, modified)
		if out := w.Must("getent passwd " + localAdmin + " || true"); out != "" {
			t.Fatalf("%s still exists: %s", localAdmin, out)
		}
		if got := w.Must("ls -1 /home | sort"); got != homes {
			t.Fatalf("home directories %q, before %q", got, homes)
		}
		if !w.inSudo(vmAdmin) {
			t.Fatal(vmAdmin + " lost sudo")
		}
		vm.RebootWithPassphrase(t)
		if !vm.Opens(t, credential(t, vm, "PADDOCK_LUKS_PASSPHRASE")) {
			t.Fatal("the LUKS passphrase no longer opens the disk")
		}
	})
}

// TestUninstallLastAdmin is gate S-UN3 of plan M8d (AC9): without another local administrator the managed one is
// kept, stays in sudo, and its escrowed password, revealed for the retired device, logs in over SSH. The install
// administrator leaves the sudo group for the gate (90-paddock keeps the harness's sudo); the sudo reconciler only ever
// removes members of privileged groups, so it does not put the account back before the removal.
func TestUninstallLastAdmin(t *testing.T) {
	forEachVM(t, func(t *testing.T, s *Stack, vm *VM) {
		w := newUninstallWorld(t, s, vm)
		password := active(t, w.reveal(t)).Password
		w.Must("sudo gpasswd -d " + vmAdmin + " sudo >/dev/null")
		t.Cleanup(func() {
			// t.Context() is already cancelled when cleanups run.
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if out, err := vm.SSH(ctx, nil, "sudo gpasswd -a "+vmAdmin+" sudo >/dev/null"); err != nil {
				t.Logf("%s: re-adding %s to sudo: %v %s", vm.Name, vmAdmin, err, out)
			}
		})
		w.RequestUninstall("reset", nil, http.StatusOK)
		p := w.WaitRetired(t, 15*time.Minute)
		if p["local_admin"] != "kept_last_admin" {
			t.Fatalf("device.uninstalled %v", p)
		}
		w.Must("getent passwd " + localAdmin)
		if !w.inSudo(localAdmin) {
			t.Fatalf("%s is not in sudo", localAdmin)
		}
		if revealed := active(t, w.reveal(t)).Password; revealed != password {
			t.Fatal("the retired device's escrowed password changed")
		}
		if out := w.sshLogin(t, password); !strings.Contains(out, localAdmin) {
			t.Fatalf("SSH login: %s", out)
		}
	})
}

// TestUninstallTpmInUse is gate S-UN4 of plan M8d (AC9): on a device whose disk unlocks with TPM2+PIN the request
// with clear_tpm is refused with tpm_in_use_by_disk; without it the removal reports tpm not_requested and the PIN
// still unlocks the disk.
func TestUninstallTpmInUse(t *testing.T) {
	forEachVM(t, func(t *testing.T, s *Stack, vm *VM) {
		vm.Fresh()
		d := Install(t, s, vm, debDir(s))
		disk := &diskWorld{Device: d, pin: randomDigits(t, 8)}
		gateDiskFlow(t, disk)
		res := d.RequestUninstall("reset", map[string]any{"clear_tpm": true}, http.StatusConflict)
		if !strings.Contains(string(res.Body), "tpm_in_use_by_disk") {
			t.Fatalf("clear_tpm on a TPM disk: %s", res.Body)
		}
		d.RequestUninstall("leave", nil, http.StatusOK)
		if p := d.WaitRetired(t, 10*time.Minute); p["tpm"] != "not_requested" {
			t.Fatalf("device.uninstalled %v", p)
		}
		vm.RebootWithPIN(t, disk.pin)
	})
}
