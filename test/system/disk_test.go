package system

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"
	"time"
)

// TestDiskGates runs the disk encryption gates of plan M4b §6 on each VM, from base-installed with the Paddock
// autoinstall simulated (PrepareDisk): the LUKS flow (gate D-24 on 24.04, the same flow on 26.04), D-ESC and D-TAMP
// on that device, then D-SKIP from a second fresh base-installed. The VMs run in parallel.
func TestDiskGates(t *testing.T) {
	forEachVM(t, func(t *testing.T, s *Stack, vm *VM) {
		t.Run("LUKS flow", func(t *testing.T) {
			vm.Fresh()
			d := Install(t, s, vm, debDir(s))
			w := &diskWorld{Device: d, pin: randomDigits(t, 8)}
			if !t.Run("D-24 TPM2+PIN and escrow", func(t *testing.T) { gateDiskFlow(t, w) }) {
				t.FailNow()
			}
			var key string
			if !t.Run("D-ESC escrow and recovery", func(t *testing.T) { key = gateDESC(t, w) }) {
				t.FailNow()
			}
			t.Run("D-TAMP keyslot tamper", func(t *testing.T) { gateDTAMP(t, w, key) })
		})
		t.Run("D-SKIP skip the PIN", func(t *testing.T) {
			vm.Fresh()
			gateDSKIP(t, Install(t, s, vm, debDir(s)))
		})
	})
}

type diskWorld struct {
	*Device
	pin string
}

// gateDiskFlow is gate D-24 (and the same flow on 26.04): with the autoinstall's state the first boot asks for the
// boot PIN, the reconciler reaches compliant (recovery key and header escrowed, install passphrase removed), and the
// next boot unlocks with the PIN.
func gateDiskFlow(t *testing.T, w *diskWorld) {
	w.PrepareDisk(t)
	w.RebootWithPassphrase(t)
	w.AnswerDiskSetup(t, w.pin)
	if kinds := w.Keyslots(t); !slices.Contains(kinds, "tpm2+pin") {
		t.Fatalf("keyslots after the disk setup: %v", kinds)
	}
	info := w.WaitDisk(t, "compliant", 15*time.Minute, func(i diskInfo) bool { return i.state() == "compliant" })
	if stored(info.RecoveryKeys) < 1 || stored(info.Headers) < 2 || !slices.Equal(info.Tokens, []string{"recovery", "tpm2+pin"}) {
		t.Fatalf("compliant disk %+v", info)
	}
	if kinds := w.Keyslots(t); !slices.Equal(kinds, []string{"recovery", "tpm2+pin"}) {
		t.Fatalf("keyslots %v, want recovery and tpm2+pin", kinds)
	}
	if out := w.Must("sudo test -e /var/lib/paddock/install-passphrase && echo present || echo gone"); out != "gone" {
		t.Fatal("the install passphrase file is still there")
	}
	if w.Opens(t, credential(t, w.VM, "PADDOCK_LUKS_PASSPHRASE")) {
		t.Fatal("the install passphrase still unlocks the disk")
	}
	w.RebootWithPIN(t, w.pin)
	if out := w.Must("systemctl is-active paddock-supervisor"); out != "active" {
		t.Fatalf("supervisor after the PIN boot: %s", out)
	}
}

// gateDESC is gate D-ESC: the escrowed recovery key and the newest header, revealed and downloaded after a step-up,
// restore the header onto a loop device copy that the recovery key opens; each reveal and download is audited once.
// It returns the recovery key.
func gateDESC(t *testing.T, w *diskWorld) string {
	hostname := w.Must("hostname")
	body := map[string]any{"confirm_hostname": hostname}
	w.s.StepUp()
	var revealed struct {
		Generation  int    `json:"generation"`
		RecoveryKey string `json:"recovery_key"`
	}
	if err := json.Unmarshal(w.s.Call(http.MethodPost, "/api/v1/devices/"+w.ID+"/disk/recovery-key", body, http.StatusOK).Body, &revealed); err != nil {
		t.Fatal(err)
	}
	header := w.s.Call(http.MethodPost, "/api/v1/devices/"+w.ID+"/disk/header", body, http.StatusOK).Body
	if !w.Opens(t, revealed.RecoveryKey) {
		t.Fatal("the escrowed recovery key does not open the disk")
	}
	w.MustIn(header, "sudo sh -c 'umask 077 && cat > /run/paddock-gate-header.img'")
	w.MustIn([]byte(revealed.RecoveryKey), `sudo sh -c 'set -e
f=/run/paddock-gate-copy.img
truncate -s 64M $f
loop=$(losetup --find --show $f)
trap "losetup -d $loop; rm -f $f /run/paddock-gate-header.img" EXIT
cryptsetup luksHeaderRestore -q $loop --header-backup-file /run/paddock-gate-header.img
cryptsetup open --test-passphrase --key-file=- $loop'`)
	for _, code := range []string{"disk.recovery_key_revealed", "disk.header_downloaded"} {
		Until(t, "one audit event "+code, time.Minute, 2*time.Second, nil, func() bool { return len(w.s.Events(code, w.ID)) == 1 })
	}
	return revealed.RecoveryKey
}

// gateDTAMP is gate D-TAMP: a passphrase keyslot added locally is reported as tamper.keyslot_changed, the header is
// escrowed again, and the portal's disk state shows the extra keyslot and the change.
func gateDTAMP(t *testing.T, w *diskWorld, recoveryKey string) {
	before := stored(w.Disk().Headers)
	w.MustIn([]byte(recoveryKey), `sudo sh -c 'set -e
umask 077
head -c 32 /dev/urandom > /run/paddock-gate-newkey
trap "rm -f /run/paddock-gate-newkey" EXIT
cryptsetup luksAddKey -q --key-file=- `+w.LUKSDevice()+` /run/paddock-gate-newkey'`)
	if kinds := w.Keyslots(t); !slices.Equal(kinds, []string{"password", "recovery", "tpm2+pin"}) {
		t.Fatalf("keyslots after adding a passphrase: %v", kinds)
	}
	ev := w.WaitEvent(t, "device.tamper_keyslot_changed", 5*time.Minute, nil)
	was, _ := json.Marshal(ev["before"])
	if after, _ := json.Marshal(ev["after"]); string(was) != `["recovery","tpm2+pin"]` || string(after) != `["password","recovery","tpm2+pin"]` {
		t.Fatalf("tamper event %v", ev)
	}
	info := w.WaitDisk(t, "header escrowed again", 10*time.Minute, func(i diskInfo) bool {
		return stored(i.Headers) > before && i.LastKeyslotChange != nil && slices.Contains(i.Tokens, "password")
	})
	if info.state() == "compliant" {
		t.Fatalf("a device with a foreign keyslot is reported compliant: %+v", info)
	}
	if len(w.s.Events("device.tamper_keyslot_changed", w.ID)) != 1 {
		t.Fatal("the keyslot change was reported more than once")
	}
}

// gateDSKIP is gate D-SKIP: entering no PIN twice lets the boot continue; the device escrows recovery key and header
// but keeps the passphrase keyslot and is reported tpm_pin_missing.
func gateDSKIP(t *testing.T, d *Device) {
	d.PrepareDisk(t)
	d.RebootWithPassphrase(t)
	d.AnswerDiskSetup(t, "")
	if out := d.Must("systemctl is-active display-manager.service"); out != "active" {
		t.Fatalf("display manager after a skipped PIN: %s", out)
	}
	info := d.WaitDisk(t, "tpm_pin_missing with escrows", 15*time.Minute, func(i diskInfo) bool {
		return i.state() == "tpm_pin_missing" && stored(i.RecoveryKeys) >= 1 && stored(i.Headers) >= 1
	})
	if !slices.Equal(info.Tokens, []string{"password", "recovery"}) || !slices.Equal(d.Keyslots(t), []string{"password", "recovery"}) {
		t.Fatalf("keyslots %v (reported %v), want password and recovery", d.Keyslots(t), info.Tokens)
	}
	if out := d.Must("sudo test -e /var/lib/paddock/install-passphrase && echo present || echo gone"); out != "present" {
		t.Fatal("the install passphrase file is gone although the passphrase keyslot is kept")
	}
	if !d.Opens(t, credential(t, d.VM, "PADDOCK_LUKS_PASSPHRASE")) {
		t.Fatal("the passphrase keyslot was removed")
	}
}
