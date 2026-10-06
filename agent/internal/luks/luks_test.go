package luks_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/luks"
)

// fakeTools answers commands by their name and arguments and records every call.
type fakeTools struct {
	answers map[string]answer
	calls   []call
}

type answer struct {
	stdout, stderr string
	exit           int
}

type call struct {
	env  []string
	line string
}

func (f *fakeTools) Command(_ context.Context, env []string, name string, args ...string) (string, string, int, error) {
	line := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, call{env: env, line: line})
	a, ok := f.answers[line]
	if !ok {
		return "", "", -1, errors.New("unexpected command " + line)
	}
	return a.stdout, a.stderr, a.exit, nil
}

const lsblkRoot = `{"blockdevices":[{"name":"/dev/mapper/ubuntu--vg-ubuntu--lv","type":"lvm","fstype":"ext4","children":[
  {"name":"/dev/mapper/dm_crypt-0","type":"crypt","fstype":"LVM2_member","children":[
    {"name":"/dev/sda3","type":"part","fstype":"crypto_LUKS","children":[{"name":"/dev/sda","type":"disk","fstype":null}]}]}]}]}`

func TestRoot(t *testing.T) {
	f := &fakeTools{answers: map[string]answer{
		"findmnt --noheadings --output SOURCE --target /":                                               {stdout: "/dev/mapper/ubuntu--vg-ubuntu--lv\n"},
		"lsblk --inverse --json --paths --output NAME,TYPE,FSTYPE -- /dev/mapper/ubuntu--vg-ubuntu--lv": {stdout: lsblkRoot},
	}}
	v, err := luks.Root(context.Background(), f)
	if err != nil || v.Device != "/dev/sda3" || v.Mapping != "dm_crypt-0" {
		t.Fatalf("root %+v, %v", v, err)
	}

	plain := &fakeTools{answers: map[string]answer{
		"findmnt --noheadings --output SOURCE --target /":                       {stdout: "/dev/sda2[/@]\n"},
		"lsblk --inverse --json --paths --output NAME,TYPE,FSTYPE -- /dev/sda2": {stdout: `{"blockdevices":[{"name":"/dev/sda2","type":"part","fstype":"btrfs","children":[{"name":"/dev/sda","type":"disk"}]}]}`},
	}}
	if _, err := luks.Root(context.Background(), plain); !errors.Is(err, luks.ErrNotEncrypted) {
		t.Fatalf("unencrypted root: %v", err)
	}
}

func TestDumpKinds(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "tpm2-recovery-password.json"))
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeTools{answers: map[string]answer{"cryptsetup luksDump --dump-json-metadata -- /dev/sda3": {stdout: string(raw)}}}
	m, err := luks.Dump(context.Background(), f, "/dev/sda3")
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Kinds(); !slices.Equal(got, []string{"password", "recovery", "tpm2+pin"}) {
		t.Fatalf("kinds %v", got)
	}
	if !m.Has(luks.KindTPM2PIN) || !m.Has(luks.KindPassword) || m.Has(luks.KindTPM2) || string(m.Raw) != string(raw) {
		t.Fatal("Has or Raw wrong")
	}
	f.answers["cryptsetup luksDump --dump-json-metadata -- /dev/sda3"] = answer{stderr: "Device /dev/sda3 is not a valid LUKS device.", exit: 1}
	if _, err := luks.Dump(context.Background(), f, "/dev/sda3"); err == nil || !strings.Contains(err.Error(), "not a valid LUKS device") {
		t.Fatalf("dump error %v", err)
	}
}

func TestSlots(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "tpm2-recovery-password.json"))
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeTools{answers: map[string]answer{"cryptsetup luksDump --dump-json-metadata -- /dev/sda3": {stdout: string(raw)}}}
	m, err := luks.Dump(context.Background(), f, "/dev/sda3")
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{luks.KindPassword, luks.KindRecovery, luks.KindTPM2PIN} {
		slots := m.Slots(kind)
		if len(slots) != 1 || m.Kind(slots[0]) != kind {
			t.Fatalf("%s: slots %v", kind, slots)
		}
	}
	if m.Kind(31) != "" || len(m.Slots(luks.KindTPM2)) != 0 {
		t.Fatal("an unused keyslot has a kind")
	}
}

func TestKeySlot(t *testing.T) {
	const line = "cryptsetup open --test-passphrase --verbose --disable-external-tokens --key-file /k /dev/sda3"
	f := &fakeTools{answers: map[string]answer{line: {stdout: "No usable token is available.\nKey slot 3 unlocked.\nCommand successful.\n"}}}
	if slot, err := luks.KeySlot(context.Background(), f, "/dev/sda3", "/k"); err != nil || slot != 3 {
		t.Fatalf("slot %d, %v", slot, err)
	}
	f.answers[line] = answer{stdout: "Command successful.\n"}
	if _, err := luks.KeySlot(context.Background(), f, "/dev/sda3", "/k"); err == nil {
		t.Fatal("output without a keyslot accepted")
	}
	f.answers[line] = answer{stderr: "No key available with this passphrase.", exit: 2}
	if _, err := luks.KeySlot(context.Background(), f, "/dev/sda3", "/k"); err == nil || !strings.Contains(err.Error(), "No key available") {
		t.Fatalf("wrong key: %v", err)
	}
}

func TestVersion(t *testing.T) {
	f := &fakeTools{answers: map[string]answer{"cryptsetup luksDump -- /dev/sda3": {stdout: "LUKS header information for /dev/sda3\n\nVersion:       \t1\nCipher name:   \taes\n"}}}
	if v, err := luks.Version(context.Background(), f, "/dev/sda3"); err != nil || v != 1 {
		t.Fatalf("version %d, %v", v, err)
	}
}

const recoveryKey = "fhjdtbcl-cuhkvnbr-huhbbcbt-klhvrgcj-kvjrhfdv-fnvlechn-rvgrgtiu-cnfdjbnl"

func TestEnroll(t *testing.T) {
	f := &fakeTools{answers: map[string]answer{
		"systemd-cryptenroll --tpm2-device=auto --tpm2-with-pin=yes --tpm2-pcrs=7 --unlock-key-file=/k /dev/sda3": {},
		"systemd-cryptenroll --recovery-key --unlock-key-file=/k /dev/sda3":                                       {stdout: recoveryKey + "\n"},
		"systemd-cryptenroll --wipe-slot=2 --unlock-key-file=/k /dev/sda3":                                        {},
		"cryptsetup luksHeaderBackup /dev/sda3 --header-backup-file /run/h.img":                                   {},
	}}
	ctx := context.Background()
	if err := luks.EnrollTPM2PIN(ctx, f, "/dev/sda3", "/k", []byte("12345678")); err != nil {
		t.Fatal(err)
	}
	// The PIN is only in the environment, never on the command line.
	if c := f.calls[0]; !slices.Equal(c.env, []string{"NEWPIN=12345678"}) || strings.Contains(c.line, "12345678") {
		t.Fatalf("enroll call %+v", c)
	}
	key, err := luks.EnrollRecovery(ctx, f, "/dev/sda3", "/k")
	if err != nil || string(key) != recoveryKey {
		t.Fatalf("recovery key %q, %v", key, err)
	}
	// Keyslots are wiped by number only, never by type.
	if err := luks.WipeSlot(ctx, f, "/dev/sda3", "/k", 2); err != nil {
		t.Fatal(err)
	}
	if err := luks.WipeSlot(ctx, f, "/dev/sda3", "/k", -1); err == nil {
		t.Fatal("a negative keyslot was accepted")
	}
	if err := luks.HeaderBackup(ctx, f, "/dev/sda3", "/run/h.img"); err != nil {
		t.Fatal(err)
	}

	f.answers["systemd-cryptenroll --recovery-key --unlock-key-file=/k /dev/sda3"] = answer{stdout: "something else\n"}
	if _, err := luks.EnrollRecovery(ctx, f, "/dev/sda3", "/k"); err == nil {
		t.Fatal("output without a recovery key accepted")
	}
	// A failure reports stderr but never stdout, which may hold a recovery key.
	f.answers["systemd-cryptenroll --recovery-key --unlock-key-file=/k /dev/sda3"] = answer{stdout: recoveryKey, stderr: "No TPM", exit: 1}
	if _, err := luks.EnrollRecovery(ctx, f, "/dev/sda3", "/k"); err == nil || strings.Contains(err.Error(), recoveryKey) || !strings.Contains(err.Error(), "No TPM") {
		t.Fatalf("error %v", err)
	}
}

func TestTPM2Present(t *testing.T) {
	root := t.TempDir()
	if luks.TPM2Present(root) {
		t.Fatal("TPM without sysfs entry")
	}
	dir := filepath.Join(root, "sys/class/tpm/tpm0")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for v, want := range map[string]bool{"1\n": false, "2\n": true} {
		if err := os.WriteFile(filepath.Join(dir, "tpm_version_major"), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
		if luks.TPM2Present(root) != want {
			t.Fatalf("version %q: present %v", v, !want)
		}
	}
}
