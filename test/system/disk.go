package system

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// credential reads a value of the test VMs' credentials.env (test/vms/virtualbox/.secrets).
func credential(t *testing.T, vm *VM, key string) string {
	t.Helper()
	data, err := os.ReadFile(vm.dir + "/.secrets/credentials.env")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, key+"="); ok {
			return strings.Trim(v, `"'`)
		}
	}
	t.Fatalf("%s missing in credentials.env", key)
	return ""
}

// dracutConf is the dracut configuration of the Paddock autoinstall on 24.04 (server/internal/autoinstall
// templates, PoC M1 C7).
const dracutConf = `# Paddock: unlock LUKS with systemd-cryptsetup and TPM2+PIN (plan M4b)
hostonly="yes"
add_dracutmodules+=" systemd crypt tpm2-tss lvm "
`

// crypttabTPM2 is the sed expression of the autoinstall that adds tpm2-device=auto to the LUKS entries.
const crypttabTPM2 = `/^\s*#/! { /tpm2-device=/! s/^(\S+\s+\S+\s+\S+\s+)(\S*luks\S*)/\1\2,tpm2-device=auto/ }`

// PrepareDisk leaves the device as the Paddock autoinstall would (gate D-24's test preparation): the disk
// passphrase as install passphrase, the disk setup settings and its pending marker, tpm2-device=auto in crypttab,
// on 24.04 dracut instead of initramfs-tools, and a rebuilt initramfs.
func (d *Device) PrepareDisk(t *testing.T) {
	t.Helper()
	// The marker first: the agent is running already and must not take the passphrase for a finished disk setup.
	d.Must(`sudo sh -c 'echo "{\"boot_pin_min_length\":8}" > /etc/paddock/disk-setup.json && touch /var/lib/paddock/disk-setup-pending'`)
	d.MustIn([]byte(credential(t, d.VM, "PADDOCK_LUKS_PASSPHRASE")),
		"sudo sh -c 'umask 077 && mkdir -p /var/lib/paddock && cat > /var/lib/paddock/install-passphrase'")
	if d.Release() == "24.04" {
		d.Must("sudo DEBIAN_FRONTEND=noninteractive apt-get install -y dracut >/dev/null 2>&1")
		d.MustIn([]byte(dracutConf), "sudo tee /etc/dracut.conf.d/90-paddock-tpm2.conf >/dev/null")
	}
	d.Must("sudo sed -i -E '" + crypttabTPM2 + "' /etc/crypttab && grep -q tpm2-device=auto /etc/crypttab")
	d.Must("sudo dracut -f --regenerate-all >/dev/null 2>&1 && sudo lsinitrd -f etc/crypttab /boot/initrd.img-$(uname -r) | grep -q tpm2-device=auto")
}

// Release is the Ubuntu release of the guest, e.g. 24.04.
func (v *VM) Release() string { return v.Must(". /etc/os-release && echo $VERSION_ID") }

// waitSSHDown waits until the guest stops answering SSH (after a reboot request).
func (v *VM) waitSSHDown(t *testing.T) {
	t.Helper()
	Until(t, v.Name+" goes down", 3*time.Minute, 2*time.Second, nil, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, err := v.SSH(ctx, nil, "true")
		return err != nil
	})
}

func (v *VM) sshUp() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := v.SSH(ctx, nil, "true")
	return err == nil
}

// RebootWithPassphrase reboots and unlocks the disk with the test VMs' passphrase (lib.sh unlock_and_wait_ssh).
func (v *VM) RebootWithPassphrase(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	_, _ = v.SSH(ctx, nil, "sudo systemctl reboot")
	v.waitSSHDown(t)
	if out, err := v.lib(ctx, "ensure_secrets; unlock_and_wait_ssh "+v.Name+" "+v.port); err != nil {
		t.Fatalf("unlock %s with the passphrase: %v: %s", v.Name, err, out)
	}
}

// RebootWithPIN reboots and types the boot PIN at the TPM2+PIN prompt until SSH answers; it fails if the disk does
// not unlock.
func (v *VM) RebootWithPIN(t *testing.T, pin string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, _ = v.SSH(ctx, nil, "sudo systemctl reboot")
	v.waitSSHDown(t)
	v.unlockAtPrompt(t, []string{pin}, "pin")
}

// unlockAtPrompt types each entry in turn at the disk prompt (repeating the last) until SSH answers, at most 6
// entries; it returns how many it typed.
func (v *VM) unlockAtPrompt(t *testing.T, entries []string, what string) int {
	t.Helper()
	time.Sleep(30 * time.Second)
	for n := 1; n <= 6; n++ {
		v.Shot(t, what+"-prompt-"+strconv.Itoa(n))
		v.Type(entries[min(n, len(entries))-1])
		for range 18 {
			time.Sleep(5 * time.Second)
			if v.sshUp() {
				t.Logf("%s: disk unlocked with the %s after %d entries", v.Name, what, n)
				return n
			}
		}
	}
	t.Fatalf("%s: the disk did not unlock with the %s", v.Name, what)
	return 0
}

// AnswerDiskSetup waits for the boot PIN dialogue of paddock-disk-setup.service on tty1 and types pin twice ("" skips
// the PIN); it waits until the unit finished and removed its marker.
func (d *Device) AnswerDiskSetup(t *testing.T, pin string) {
	t.Helper()
	state := func() string {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		out, _ := d.SSH(ctx, nil, "systemctl is-active paddock-disk-setup.service; sudo test -e /var/lib/paddock/disk-setup-pending && echo pending")
		return out
	}
	Until(t, d.Name+": disk setup asks for the boot PIN", 5*time.Minute, 3*time.Second, nil, func() bool {
		return strings.HasPrefix(state(), "activating")
	})
	time.Sleep(3 * time.Second)
	d.Shot(t, "disk-setup")
	d.Type(pin)
	time.Sleep(2 * time.Second)
	d.Type(pin)
	Until(t, d.Name+": disk setup finished", 3*time.Minute, 3*time.Second, nil, func() bool {
		s := state()
		return !strings.HasPrefix(s, "activating") && !strings.Contains(s, "pending")
	})
}

// LUKSDevice is the LUKS partition of the guest.
func (v *VM) LUKSDevice() string { return v.Must("sudo blkid -t TYPE=crypto_LUKS -o device | head -1") }

// Keyslots are the keyslot kinds of the guest's LUKS volume, sorted, as the agent names them.
func (v *VM) Keyslots(t *testing.T) []string {
	t.Helper()
	var md struct {
		Keyslots map[string]json.RawMessage `json:"keyslots"`
		Tokens   map[string]struct {
			Type     string   `json:"type"`
			Keyslots []string `json:"keyslots"`
			PIN      bool     `json:"tpm2-pin"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal([]byte(v.Must("sudo cryptsetup luksDump --dump-json-metadata "+v.LUKSDevice())), &md); err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for slot := range md.Keyslots {
		kind := "password"
		for _, tok := range md.Tokens {
			switch {
			case !slices.Contains(tok.Keyslots, slot):
			case tok.Type == "systemd-tpm2" && tok.PIN:
				kind = "tpm2+pin"
			case tok.Type == "systemd-tpm2":
				kind = "tpm2"
			case tok.Type == "systemd-recovery":
				kind = "recovery"
			default:
				kind = strings.TrimPrefix(tok.Type, "systemd-")
			}
		}
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	return kinds
}

// Opens reports whether secret unlocks the guest's LUKS volume (cryptsetup --test-passphrase; the secret travels on
// stdin).
func (v *VM) Opens(t *testing.T, secret string) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, err := v.SSH(ctx, []byte(secret), "sudo cryptsetup open --test-passphrase --key-file=- "+v.LUKSDevice())
	return err == nil
}

// diskEscrow is a generation of GET /api/v1/devices/{id}/disk.
type diskEscrow struct {
	Generation int    `json:"generation"`
	Status     string `json:"status"`
}

// diskInfo is GET /api/v1/devices/{id}/disk.
type diskInfo struct {
	State             *string      `json:"state"`
	Tokens            []string     `json:"tokens"`
	RecoveryKeys      []diskEscrow `json:"recovery_keys"`
	Headers           []diskEscrow `json:"headers"`
	LastKeyslotChange *struct {
		Before []string `json:"before"`
		After  []string `json:"after"`
	} `json:"last_keyslot_change"`
}

func (i diskInfo) state() string {
	if i.State == nil {
		return ""
	}
	return *i.State
}

// stored counts the stored generations.
func stored(es []diskEscrow) int {
	n := 0
	for _, e := range es {
		if e.Status == "stored" {
			n++
		}
	}
	return n
}

// Disk reads the disk encryption of the device from the API.
func (d *Device) Disk() diskInfo {
	d.t.Helper()
	var i diskInfo
	if err := json.Unmarshal(d.s.Call(http.MethodGet, "/api/v1/devices/"+d.ID+"/disk", nil, http.StatusOK).Body, &i); err != nil {
		d.t.Fatal(err)
	}
	return i
}

// WaitDisk waits until cond holds for the disk encryption the API reports, checking in every 65 s.
func (d *Device) WaitDisk(t *testing.T, what string, timeout time.Duration, cond func(diskInfo) bool) diskInfo {
	t.Helper()
	var i diskInfo
	last := time.Time{}
	Until(t, d.Name+": "+what, timeout, 10*time.Second, func() {
		if time.Since(last) > 65*time.Second {
			d.Checkin()
			last = time.Now()
		}
	}, func() bool {
		i = d.Disk()
		return cond(i)
	})
	return i
}
