package encrypt_test

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/encrypt"
)

// recorded is a tool output of a fixture.
type recorded struct {
	stdout string
	exit   int
}

// fakeSystem answers the commands of a recorded fixture and reads the fixture's files below root. It records every
// command; one the fixture does not know fails the test.
type fakeSystem struct {
	t        *testing.T
	root     string
	commands map[string]*recorded
	calls    []string
}

// loadFixture reads testdata/<name>.txt: "@ <base>" includes another fixture first, "$ <command line>" starts a
// command whose stdout follows ("? <n>" sets its exit code), "> <path>" a file below the root whose content follows
// (a path ending in / is a directory). Later entries replace earlier ones.
func loadFixture(t *testing.T, name string) *fakeSystem {
	t.Helper()
	f := &fakeSystem{t: t, root: t.TempDir(), commands: map[string]*recorded{}}
	files := map[string]*strings.Builder{}
	f.load(name, files)
	for path, content := range files {
		full := filepath.Join(f.root, path)
		if strings.HasSuffix(path, "/") {
			if err := os.MkdirAll(full, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f *fakeSystem) load(name string, files map[string]*strings.Builder) {
	raw, err := os.ReadFile(filepath.Join("testdata", name+".txt"))
	if err != nil {
		f.t.Fatal(err)
	}
	var out *strings.Builder
	var cmd *recorded
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "@ "):
			f.load(strings.TrimPrefix(line, "@ "), files)
		case strings.HasPrefix(line, "$ "):
			if cmd != nil {
				cmd.stdout = out.String()
			}
			cmd, out = &recorded{}, &strings.Builder{}
			f.commands[strings.TrimPrefix(line, "$ ")] = cmd
		case strings.HasPrefix(line, "? ") && cmd != nil:
			cmd.exit, _ = strconv.Atoi(strings.TrimPrefix(line, "? "))
		case strings.HasPrefix(line, "> "):
			if cmd != nil {
				cmd.stdout, cmd = out.String(), nil
			}
			out = &strings.Builder{}
			files[strings.TrimPrefix(line, "> ")] = out
		default:
			out.WriteString(line + "\n")
		}
	}
	if cmd != nil {
		cmd.stdout = out.String()
	}
}

func (f *fakeSystem) Command(_ context.Context, name string, args ...string) (string, string, int, error) {
	line := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, line)
	r, ok := f.commands[line]
	if !ok {
		f.t.Errorf("unrecorded command %s", line)
		return "", "", -1, errors.New("unrecorded command")
	}
	return r.stdout, "", r.exit, nil
}

func (f *fakeSystem) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) } //nolint:gosec // test root

func (f *fakeSystem) Stat(path string) (bool, error) {
	_, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func (f *fakeSystem) preflight() encrypt.Layout {
	f.t.Helper()
	return encrypt.Preflight(context.Background(), f, f.root, false)
}

func (f *fakeSystem) set(line, stdout string, exit int) {
	f.commands[line] = &recorded{stdout: stdout, exit: exit}
}

// tools are the commands a preflight may run (plan M8e decision 34).
var tools = []string{"findmnt", "lsblk", "blkid", "lvm", "dpkg-query", "apt-get"}

// checkCalls asserts that the preflight ran only the tools of decision 34 and apt-get only without dracut.
func (f *fakeSystem) checkCalls(dracut bool) {
	f.t.Helper()
	for _, c := range f.calls {
		name, _, _ := strings.Cut(c, " ")
		if !slices.Contains(tools, name) || (dracut && name == "apt-get") {
			f.t.Errorf("preflight ran %s", c)
		}
	}
}

func TestPreflightLVM(t *testing.T) {
	f := loadFixture(t, "lvm")
	got := f.preflight()
	want := encrypt.Layout{Eligible: true, Kind: encrypt.KindLVM, Reasons: nil,
		Partition: "/dev/disk/by-partuuid/8c2f8d4e-5b7a-4f1c-9e0d-2a6b3c4d5e6f", PartUUID: "8c2f8d4e-5b7a-4f1c-9e0d-2a6b3c4d5e6f",
		VG: "ubuntu-vg", LV: "ubuntu-lv", FSUUID: "3d5a2c71-8e4b-4f09-a1c6-7b2e9d0f4a85", Release: "24.04",
		Initramfs: encrypt.InitramfsTools, InitramfsRemoves: []string{"brltty", "initramfs-tools"},
		PartitionBytes: 40793800704, FSBytes: 20012101632, FSFreeBytes: 14873907200}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("lvm layout\n got %+v\nwant %+v", got, want)
	}
	f.checkCalls(false)
	if !slices.Contains(f.calls, "apt-get -s -o Debug::NoLocking=true install dracut") {
		t.Fatalf("no removal simulation without dracut: %v", f.calls)
	}
}

func TestPreflightPlain(t *testing.T) {
	f := loadFixture(t, "plain")
	got := f.preflight()
	if !got.Eligible || got.Kind != encrypt.KindPlain || got.Reasons != nil || got.VG != "" || got.Release != "26.04" ||
		got.Partition != "/dev/disk/by-partuuid/1f0e2d3c-4b5a-4968-8776-655443322110" || got.PartitionBytes != 509031055360 ||
		got.Initramfs != encrypt.InitramfsDracut || got.InitramfsRemoves != nil {
		t.Fatalf("plain layout %+v", got)
	}
	f.checkCalls(true)
}

// TestPreflightNotEligible: every negative fixture reports exactly the failing reasons of plan M8e decision 2, sorted.
func TestPreflightNotEligible(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		change  func(f *fakeSystem)
		reasons []string
		kind    string
	}{
		{fixture: "direct", reasons: []string{"no_separate_boot"}, kind: encrypt.KindPlain},
		{fixture: "raid", reasons: []string{"root_layout_unsupported"}},
		// btrfs on a partition is no plain layout (ext4 directly on one partition, plan M8e §3.1).
		{fixture: "btrfs", reasons: []string{"root_layout_unsupported", "root_not_ext4"}},
		{fixture: "two-pvs", reasons: []string{"root_layout_unsupported"}},
		{fixture: "swap-tail", reasons: []string{"pv_tail_in_use"}, kind: encrypt.KindLVM},
		{fixture: "cmdline-sda3", reasons: []string{"root_reference_unsupported"}, kind: encrypt.KindPlain},
		{fixture: "lvm", reasons: []string{"low_free_space"}, kind: encrypt.KindLVM, change: func(f *fakeSystem) {
			f.set("findmnt -bno SIZE,AVAIL /", "20012101632 1073741823\n", 0)
		}},
		{fixture: "lvm", reasons: []string{"no_tpm2"}, kind: encrypt.KindLVM, change: func(f *fakeSystem) {
			f.remove("/sys/class/tpm")
		}},
		{fixture: "lvm", reasons: []string{"no_uefi"}, kind: encrypt.KindLVM, change: func(f *fakeSystem) {
			f.remove("/sys/firmware/efi")
		}},
		{fixture: "lvm", reasons: []string{"release_unsupported"}, kind: encrypt.KindLVM, change: func(f *fakeSystem) {
			f.write("/etc/os-release", "NAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\n")
		}},
		{fixture: "plain", reasons: []string{"boot_on_root_device"}, kind: encrypt.KindPlain, change: func(f *fakeSystem) {
			f.set("findmnt -no SOURCE /boot", "/dev/nvme0n1p3[/@boot]\n", 0)
			f.set("lsblk --noheadings --nodeps --paths --output TYPE -- /dev/nvme0n1p3", "part\n", 0)
		}},
		{fixture: "plain", reasons: []string{"root_layout_unsupported"}, change: func(f *fakeSystem) {
			f.set("blkid -p -o value -s PTTYPE /dev/nvme0n1", "dos\n", 0)
		}},
		{fixture: "lvm", reasons: []string{"low_free_space", "no_tpm2", "no_uefi", "pv_tail_in_use", "release_unsupported"},
			kind: encrypt.KindLVM, change: func(f *fakeSystem) {
				f.set("findmnt -bno SIZE,AVAIL /", "20012101632 0\n", 0)
				f.set("lvm pvs --segments --noheadings --units b -o pv_name,pvseg_start,pvseg_size,lv_name",
					"  /dev/sda3 0 4863 ubuntu-lv\n  /dev/sda3 4863 100 home\n", 0)
				f.remove("/sys/class/tpm")
				f.remove("/sys/firmware/efi")
				f.remove("/etc/os-release")
			}},
	} {
		f := loadFixture(t, tc.fixture)
		if tc.change != nil {
			tc.change(f)
		}
		got := f.preflight()
		if got.Eligible || !slices.Equal(got.Reasons, tc.reasons) || got.Kind != tc.kind {
			t.Errorf("%s: eligible %v, reasons %v, kind %q; want %v, kind %q", tc.fixture, got.Eligible, got.Reasons, got.Kind,
				tc.reasons, tc.kind)
		}
		f.checkCalls(tc.fixture != "lvm" && tc.fixture != "two-pvs" && tc.fixture != "swap-tail")
	}
}

// TestPreflightAlreadyEncrypted: a root on LUKS reports already_encrypted and an unsupported layout.
func TestPreflightAlreadyEncrypted(t *testing.T) {
	f := loadFixture(t, "lvm")
	f.set("lsblk --inverse --json --paths --bytes --output NAME,TYPE,FSTYPE,PKNAME,PARTUUID,SIZE -- /dev/mapper/ubuntu--vg-ubuntu--lv",
		`{"blockdevices":[{"name":"/dev/mapper/ubuntu--vg-ubuntu--lv","type":"lvm","fstype":"ext4","children":[
  {"name":"/dev/mapper/dm_crypt-0","type":"crypt","fstype":"LVM2_member","children":[
    {"name":"/dev/sda3","type":"part","fstype":"crypto_LUKS","partuuid":"8c2f8d4e-5b7a-4f1c-9e0d-2a6b3c4d5e6f","children":[{"name":"/dev/sda","type":"disk"}]}]}]}]}`, 0)
	got := f.preflight()
	if !slices.Equal(got.Reasons, []string{"already_encrypted", "root_layout_unsupported"}) || got.Kind != "" || got.VG != "" {
		t.Fatalf("encrypted root: %+v", got)
	}
}

// TestPreflightRootReference: fstab and the kernel command line may name the root by its file system UUID or, for
// lvm, by /dev/mapper/<vg>-<lv>, /dev/<vg>/<lv> or the exact dm-uuid-LVM link of the root LV (correction of plan M8e
// decision 2, 2026-10-21).
func TestPreflightRootReference(t *testing.T) {
	const dmUUID = "/dev/disk/by-id/dm-uuid-LVM-Xb3k9f0aQeLm2T7yRvPq4Wn8ZsJc1dHg4fRt2x9KpL0mWqZx7cVb3nHy6uTg5eQa"
	for ref, ok := range map[string]bool{
		"UUID=3d5a2c71-8e4b-4f09-a1c6-7b2e9d0f4a85": true,
		"/dev/mapper/ubuntu--vg-ubuntu--lv":         true,
		"/dev/ubuntu-vg/ubuntu-lv":                  true,
		dmUUID:                                      true,
		"UUID=00000000-8e4b-4f09-a1c6-7b2e9d0f4a85": false,
		"/dev/sda3":                                 false,
		"/dev/mapper/ubuntu-vg-ubuntu-lv":           false,
		"/dev/disk/by-id/dm-uuid-LVM-Xb3k9f0aQeLm2T7yRvPq4Wn8ZsJc1dHg":                                   false, // the VG only
		"/dev/disk/by-id/dm-uuid-LVM-Xb3k9f0aQeLm2T7yRvPq4Wn8ZsJc1dHg0000000000000000000000000000000":    false, // another LV
		"/dev/disk/by-id/dm-uuid-LVM-Xb3k9f0aQeLm2T7yRvPq4Wn8ZsJc1dHg4fRt2x9KpL0mWqZx7cVb3nHy6uTg5eQaXX": false,
	} {
		for _, where := range []string{"fstab", "cmdline"} {
			f := loadFixture(t, "lvm")
			if where == "fstab" {
				f.set("findmnt --fstab -no SOURCE /", ref+"\n", 0)
			} else {
				f.write("/proc/cmdline", "BOOT_IMAGE=/vmlinuz root=/dev/sda1 root="+ref+" ro\n")
			}
			got := f.preflight()
			if got.Eligible != ok || (!ok && !slices.Equal(got.Reasons, []string{"root_reference_unsupported"})) {
				t.Errorf("%s %s: eligible %v, reasons %v", where, ref, got.Eligible, got.Reasons)
			}
		}
	}
	f := loadFixture(t, "lvm")
	f.write("/proc/cmdline", "BOOT_IMAGE=/vmlinuz ro\n")
	if got := f.preflight(); !slices.Equal(got.Reasons, []string{"root_reference_unsupported"}) {
		t.Fatalf("a command line without root=: %v", got.Reasons)
	}
}

// TestPreflightInitramfs (plan M8e decisions 32–34): dpkg-query decides the generator; without dracut the removal set
// is the sorted Remv packages of the simulation, empty when it failed.
func TestPreflightInitramfs(t *testing.T) {
	f := loadFixture(t, "lvm")
	f.set("apt-get -s -o Debug::NoLocking=true install dracut", "E: Unable to locate package dracut\n", 100)
	if got := f.preflight(); !got.Eligible || got.Initramfs != encrypt.InitramfsTools || got.InitramfsRemoves != nil {
		t.Fatalf("failed simulation: %+v", got)
	}
	for _, status := range []string{"config-files", "not-installed", "half-installed"} {
		f := loadFixture(t, "lvm")
		f.set("dpkg-query -W -f=${db:Status-Status} dracut", status, 0)
		if got := f.preflight(); got.Initramfs != encrypt.InitramfsTools || len(got.InitramfsRemoves) != 2 {
			t.Fatalf("dracut %s: %+v", status, got)
		}
	}
	f = loadFixture(t, "lvm")
	f.set("dpkg-query -W -f=${db:Status-Status} dracut", "installed", 0)
	if got := f.preflight(); got.Initramfs != encrypt.InitramfsDracut || got.InitramfsRemoves != nil {
		t.Fatalf("dracut installed: %+v", got)
	}
	f.checkCalls(true)
}

// TestPreflightCleanupPending (invariant I3 of plan M8e §14.10): an unfinished cleanup is the only reason, and nothing
// else is checked.
func TestPreflightCleanupPending(t *testing.T) {
	f := loadFixture(t, "lvm")
	got := encrypt.Preflight(context.Background(), f, f.root, true)
	if !reflect.DeepEqual(got, encrypt.Layout{Reasons: []string{"cleanup_pending"}}) || len(f.calls) != 0 {
		t.Fatalf("cleanup pending: %+v, calls %v", got, f.calls)
	}
}

func (f *fakeSystem) remove(path string) {
	f.t.Helper()
	if err := os.RemoveAll(filepath.Join(f.root, path)); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeSystem) write(path, content string) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.root, path), []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
}
