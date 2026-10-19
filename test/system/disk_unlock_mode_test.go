package system

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// setUnlockMode sets acme's disk unlock mode and keeps every other login setting.
func setUnlockMode(t *testing.T, s *Stack, mode string) {
	t.Helper()
	var set map[string]any
	if err := json.Unmarshal(s.Call(http.MethodGet, "/api/v1/settings/login", nil, http.StatusOK).Body, &set); err != nil {
		t.Fatal(err)
	}
	delete(set, "updated_at")
	set["disk_unlock_mode"] = mode
	s.Call(http.MethodPut, "/api/v1/settings/login", set, http.StatusOK)
}

// revealRecoveryKey reveals the device's recovery key as alice after a step-up.
func (d *Device) revealRecoveryKey(t *testing.T) string {
	t.Helper()
	d.s.StepUp()
	var revealed struct {
		RecoveryKey string `json:"recovery_key"`
	}
	if err := json.Unmarshal(d.s.Call(http.MethodPost, "/api/v1/devices/"+d.ID+"/disk/recovery-key",
		map[string]any{"confirm_hostname": d.Must("hostname")}, http.StatusOK).Body, &revealed); err != nil || revealed.RecoveryKey == "" {
		t.Fatalf("reveal: %v", err)
	}
	return revealed.RecoveryKey
}

// TestDiskUnlockModeTPMOnly is gate S-DU1 of plan M8d (AC10): with the organization on tpm_only an autoinstalled
// throwaway VM shows no PIN dialogue at the first boot, reaches compliant with [recovery, tpm2] and unlock_mode
// tpm_only, and the next boot unlocks without input; the install passphrase no longer opens the disk, the recovery
// key does. It runs only with PADDOCK_SYSTEM_VMS=paddock-ai-2604, like gate D-AI.
func TestDiskUnlockModeTPMOnly(t *testing.T) {
	if !slices.Contains(strings.Split(os.Getenv("PADDOCK_SYSTEM_VMS"), ","), aiVMName) {
		t.Skip("gate S-DU1 runs with PADDOCK_SYSTEM_VMS=" + aiVMName)
	}
	s := newStack(t)
	iso := os.Getenv("PADDOCK_SYSTEM_ISO_2604")
	if iso == "" {
		home, _ := os.UserHomeDir()
		iso = filepath.Join(home, "Downloads", "ubuntu-26.04.1-desktop-amd64.iso")
	}
	s.InstallRelease(t)
	setUnlockMode(t, s, "tpm_only")
	t.Cleanup(func() { setUnlockMode(t, s, "tpm_pin") })

	tok := s.Call(http.MethodPost, "/api/v1/enrollment-tokens", map[string]any{
		"name": "systest du1 " + unique(), "max_uses": 1, "auto_approve": true,
		"expires_at": time.Now().Add(3 * time.Hour).UTC().Format(time.RFC3339),
	}, http.StatusCreated)
	var created struct {
		Token struct {
			ID string `json:"id"`
		} `json:"token"`
		EnrollmentConfig json.RawMessage `json:"enrollment_config"`
	}
	if err := json.Unmarshal(tok.Body, &created); err != nil {
		t.Fatal(err)
	}
	s.RevokeOnCleanup(created.Token.ID)
	userData := s.Call(http.MethodPost, "/api/v1/autoinstall", map[string]any{
		"enrollment_config": created.EnrollmentConfig, "release": "26.04", "hostname": aiVMName,
		"locale": "en_US.UTF-8", "keyboard_layout": "us", "timezone": "Europe/Berlin",
	}, http.StatusOK).Body
	if !strings.Contains(string(userData), `unlock_mode\":\"tpm_only`) && !strings.Contains(string(userData), `"unlock_mode":"tpm_only"`) {
		t.Fatal("the user-data does not configure tpm_only")
	}
	passphrase := storagePassphrase(t, userData)
	vm := buildAIVM(t, s.root, iso, withTestAccess(t, userData, s.root, &VM{dir: filepath.Join(s.root, "test", "vms", "virtualbox")}))
	vm.StartWithPassphrase(t, passphrase)
	d := &Device{VM: vm, s: s}
	Until(t, aiVMName+": disk setup finished without input", 5*time.Minute, 3*time.Second, nil, func() bool {
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		out, _ := vm.SSH(ctx, nil, "systemctl is-active paddock-disk-setup.service; sudo test -e /var/lib/paddock/disk-setup-pending && echo pending")
		return !strings.HasPrefix(out, "activating") && !strings.Contains(out, "pending")
	})
	d.Shot(t, "disk-setup-tpm-only")
	if out := vm.Must("sudo journalctl -b -u paddock-disk-setup.service --no-pager"); !strings.Contains(out, "TPM unlock enrolled") {
		t.Fatalf("no TPM-only enrollment in the journal:\n%s", out)
	}
	Until(t, aiVMName+" enrolls itself", 10*time.Minute, 10*time.Second, nil, func() bool {
		var page struct {
			Items []struct {
				ID string `json:"id"`
			} `json:"items"`
		}
		_ = json.Unmarshal(s.Call(http.MethodGet, "/api/v1/devices?q="+aiVMName+"&state=active", nil, http.StatusOK).Body, &page)
		if len(page.Items) > 0 {
			d.ID = page.Items[0].ID
		}
		return d.ID != ""
	})
	info := d.WaitDisk(t, "compliant", 30*time.Minute, func(i diskInfo) bool { return i.state() == "compliant" })
	if info.UnlockMode != "tpm_only" || !slices.Equal(vm.Keyslots(t), []string{"recovery", "tpm2"}) {
		t.Fatalf("compliant disk %+v, keyslots %v", info, vm.Keyslots(t))
	}
	if vm.Opens(t, passphrase) {
		t.Fatal("the install passphrase still unlocks the disk")
	}
	if !vm.Opens(t, d.revealRecoveryKey(t)) {
		t.Fatal("the recovery key does not open the disk")
	}
	_, _ = vm.SSH(t.Context(), nil, "sudo systemctl reboot")
	vm.waitSSHDown(t)
	Until(t, aiVMName+" boots without input", 5*time.Minute, 5*time.Second, nil, vm.sshUp)
}

// TestDiskUnlockModeMismatch is gate S-DU2 of plan M8d (AC11): a D-24 device (tpm2+pin) whose group is set to
// tpm_only reports unlock_mode_mismatch within one drift pass and is listed as disk_not_compliant with that detail;
// the runbook's conversion with the recovery key is reported as a keyslot change and makes it compliant with
// [recovery, tpm2].
func TestDiskUnlockModeMismatch(t *testing.T) {
	forEachVM(t, func(t *testing.T, s *Stack, vm *VM) {
		vm.Fresh()
		d := Install(t, s, vm, debDir(s))
		gateDiskFlow(t, &diskWorld{Device: d, pin: randomDigits(t, 8)})
		s.Call(http.MethodPatch, "/api/v1/device-groups/"+d.Group, map[string]any{"disk_unlock_mode": "tpm_only"}, http.StatusOK)
		d.WaitDisk(t, "unlock_mode_mismatch", 10*time.Minute, func(i diskInfo) bool {
			return i.state() == "unlock_mode_mismatch" && i.UnlockMode == "tpm_only"
		})
		hostname := d.Must("hostname")
		Until(t, "attention lists the mismatch", 3*time.Minute, 10*time.Second, nil, func() bool {
			res := s.Call(http.MethodGet, "/api/v1/attention?kind=disk_not_compliant&q="+hostname, nil, http.StatusOK)
			return strings.Contains(string(res.Body), `"detail":"unlock_mode_mismatch"`)
		})
		key := d.revealRecoveryKey(t)
		d.MustIn([]byte(key), "umask 077 && sudo tee /run/paddock-recovery-key >/dev/null")
		d.Must("sudo systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto --tpm2-pcrs=7 --unlock-key-file=/run/paddock-recovery-key " +
			vm.LUKSDevice() + " && sudo shred -u /run/paddock-recovery-key")
		d.WaitEvent(t, "device.tamper_keyslot_changed", 10*time.Minute, nil)
		info := d.WaitDisk(t, "compliant after the conversion", 15*time.Minute, func(i diskInfo) bool { return i.state() == "compliant" })
		if !slices.Equal(info.Tokens, []string{"recovery", "tpm2"}) {
			t.Fatalf("keyslots after the conversion %v", info.Tokens)
		}
	})
}
