package encrypt_test

import (
	"bytes"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/encrypt"
	"github.com/phischl/paddock-mdm/agent/internal/paths"
)

// The init script runs with a stub toolchain: every tool it calls is a shell stub that records its command line and
// answers from the scenario's rules (a case statement on "<tool> <args>"), under every POSIX shell of the host. The
// fake root carries the plan, the partition, the root device and the power supplies (plan M8e decision 16).

const (
	bootPartUUID = "8c2f8d4e-5b7a-4f1c-9e0d-2a6b3c4d5e6f"
	bootLUKSUUID = "5f0c3d1e-2a4b-4c6d-8e9f-0a1b2c3d4e5f"
	bootFSUUID   = "3d5a2c71-8e4b-4f09-a1c6-7b2e9d0f4a85"
	bootPartSize = int64(40793800704)
	bootLVSize   = int64(20396900352)
	// bootKey stands in for the conversion key; it must never reach a command line or the output.
	bootKey = "cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-cbdefghi-jklnrtuv"
)

// stubTools are the tools the init script may call; anything else fails with 127.
var stubTools = []string{"udevadm", "cryptsetup", "lvm", "e2fsck", "resize2fs", "dumpe2fs", "blockdev", "blkid", "plymouth", "sleep"}

// mappedFunc is what an init or open does to the fake /dev: the mapping appears and the plain root's UUID link moves
// from the raw partition to it.
const mappedFunc = `mapped() {
	r=$PADDOCK_ENCRYPT_TEST_ROOT
	: >"$r/dev/mapper/dm_crypt-0"
	: >"$r/dev/dm-0"
	ln -sf ../../dm-0 "$r/dev/disk/by-uuid/` + bootFSUUID + `"
}
`

// defaultRules answer like an unencrypted device before the shrink whose init and open create the mapping; a
// scenario's rules come first and win.
const defaultRules = `
"cryptsetup isLuks "*) exit 1 ;;
"cryptsetup reencrypt "* | "cryptsetup open "*) mapped ;;
"lvm pvs --noheadings -o vg_name "*) echo "  ubuntu-vg" ;;
"blkid -o device -t PARTUUID=` + bootPartUUID + `") echo "$PADDOCK_ENCRYPT_TEST_ROOT/dev/disk/by-partuuid/` + bootPartUUID + `" ;;
"blkid -p -s UUID -o value "*) echo "` + bootFSUUID + `" ;;
"blockdev --getsize64 "*) echo "${LV_BYTES}" ;;
"lvm pvs "*) echo "  ${PV_BYTES}B" ;;
"dumpe2fs -h "*) printf 'Filesystem UUID:          x\nBlock count:              %s\nBlock size:               4096\n' "${FS_BLOCKS}" ;;
`

type boot struct {
	t      *testing.T
	shell  []string
	dir    string
	root   string
	plan   encrypt.Plan
	rules  string
	env    []string
	calls  []string
	output string
	result map[string]string
}

// shells are the POSIX shells of the host the script is run with: dash (Debian's sh) and bash in POSIX mode (dracut's
// /bin/sh). Not busybox: dracut does not use it, and its applets would shadow the stub toolchain.
func shells(t *testing.T) map[string][]string {
	t.Helper()
	all := map[string][]string{}
	for name, cmd := range map[string][]string{"dash": {"dash"}, "bash": {"bash", "--posix"}} {
		if p, err := exec.LookPath(cmd[0]); err == nil {
			all[name] = append([]string{p}, cmd[1:]...)
		}
	}
	if len(all) == 0 {
		t.Fatal("no POSIX shell on the host")
	}
	return all
}

func lvmPlan() encrypt.Plan {
	target := bootLVSize - 16*4194304
	return encrypt.Plan{Layout: encrypt.KindLVM, PartUUID: bootPartUUID, LUKSUUID: bootLUKSUUID, Mapping: "dm_crypt-0",
		VG: "ubuntu-vg", LV: "ubuntu-lv", FSUUID: bootFSUUID, FSTargetBytes: target, PVTargetBytes: bootPartSize - 32<<20}
}

func plainPlan() encrypt.Plan {
	return encrypt.Plan{Layout: encrypt.KindPlain, PartUUID: bootPartUUID, LUKSUUID: bootLUKSUUID, Mapping: "dm_crypt-0",
		FSUUID: bootFSUUID, FSTargetBytes: bootPartSize - 64<<20, PVTargetBytes: bootPartSize - 32<<20}
}

// newBoot is a device at the conversion restart: the partition and the root device exist, no power supply, sizes
// before the shrink.
func newBoot(t *testing.T, shell []string, plan encrypt.Plan) *boot {
	t.Helper()
	b := &boot{t: t, shell: shell, dir: t.TempDir(), plan: plan}
	b.root = filepath.Join(b.dir, "root")
	env, err := plan.Env()
	if err != nil {
		t.Fatal(err)
	}
	b.write("/etc/paddock/encrypt-plan.env", string(env))
	b.write("/etc/paddock/encrypt-key", bootKey)
	b.write("/proc/uptime", "12.34 40.00\n")
	b.write("/lib/dracut-lib.sh", `getarg() {
	case $1 in
	paddock.encrypt.testdelay=) v=$TESTDELAY ;;
	resume=) v=$RESUME ;;
	*) return 1 ;;
	esac
	[ -n "$v" ] && echo "$v"
}
`)
	b.write("/dev/disk/by-partuuid/"+bootPartUUID, "")
	if err := os.MkdirAll(filepath.Join(b.root, "dev/mapper"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The plain root's UUID link exists before the conversion too, on the raw partition.
	b.write("/dev/disk/by-uuid/"+bootFSUUID, "")
	if plan.Layout == encrypt.KindLVM {
		b.write("/dev/"+plan.VG+"/"+plan.LV, "")
	}
	b.sizes(bootLVSize, bootPartSize, bootPartSize/4096)
	return b
}

func (b *boot) write(path, content string) {
	b.t.Helper()
	p := filepath.Join(b.root, path)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		b.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		b.t.Fatal(err)
	}
}

func (b *boot) remove(path string) {
	b.t.Helper()
	if err := os.Remove(filepath.Join(b.root, path)); err != nil {
		b.t.Fatal(err)
	}
}

// sizes sets what blockdev reports for the LV, lvm for the PV and dumpe2fs for the plain file system.
func (b *boot) sizes(lv, pv, fsBlocks int64) {
	b.env = append(b.env, "LV_BYTES="+strconv.FormatInt(lv, 10), "PV_BYTES="+strconv.FormatInt(pv, 10),
		"FS_BLOCKS="+strconv.FormatInt(fsBlocks, 10))
}

// atTarget is a re-run after the shrink completed.
func (b *boot) atTarget() {
	b.sizes(b.plan.FSTargetBytes, b.plan.PVTargetBytes, b.plan.FSTargetBytes/4096)
}

func (b *boot) supply(name, typ, online, scope string) {
	b.write("/sys/class/power_supply/"+name+"/type", typ+"\n")
	if online != "" {
		b.write("/sys/class/power_supply/"+name+"/online", online+"\n")
	}
	if scope != "" {
		b.write("/sys/class/power_supply/"+name+"/scope", scope+"\n")
	}
}

// testHooks is a dev build's initrd with paddock.encrypt.testdelay=<arg> on the kernel command line.
func (b *boot) testHooks(arg string) {
	b.write("/etc/paddock/encrypt-test", "")
	b.env = append(b.env, "TESTDELAY="+arg)
}

func (b *boot) run() {
	b.t.Helper()
	bin := filepath.Join(b.dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		b.t.Fatal(err)
	}
	stub := "#!/bin/sh\nname=${0##*/}\nprintf '%s\\n' \"$name $*\" >>\"$STUB_LOG\"\n. \"$STUB_RULES\"\nexit 0\n"
	for _, tool := range stubTools {
		if err := os.WriteFile(filepath.Join(bin, tool), []byte(stub), 0o755); err != nil { //nolint:gosec // a test stub must be executable
			b.t.Fatal(err)
		}
	}
	for _, tool := range []string{"mkdir", "rm", "ln", "readlink", "test"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			b.t.Fatal(err)
		}
		if err := os.Symlink(p, filepath.Join(bin, tool)); err != nil {
			b.t.Fatal(err)
		}
	}
	rules := filepath.Join(b.dir, "rules.sh")
	if err := os.WriteFile(rules, []byte(mappedFunc+"case \"$name $*\" in\n"+b.rules+defaultRules+"esac\n"), 0o600); err != nil {
		b.t.Fatal(err)
	}
	script, err := fs.ReadFile(encrypt.Module(), "paddock-encrypt-init.sh")
	if err != nil {
		b.t.Fatal(err)
	}
	scriptPath := filepath.Join(b.dir, "encrypt-init.sh")
	if err := os.WriteFile(scriptPath, script, 0o600); err != nil {
		b.t.Fatal(err)
	}
	log := filepath.Join(b.dir, "calls")
	cmd := exec.Command(b.shell[0], append(slices.Clone(b.shell[1:]), scriptPath)...) //nolint:gosec // the host's shell
	cmd.Env = append([]string{"PATH=" + bin, "PADDOCK_ENCRYPT_TEST_ROOT=" + b.root, "STUB_LOG=" + log, "STUB_RULES=" + rules,
		"STUB_DIR=" + b.dir, "TESTDELAY=", "RESUME="}, b.env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		b.t.Fatalf("the script exited with %v (it must always exit 0):\n%s", err, out.String())
	}
	b.output = out.String()
	raw, _ := os.ReadFile(log)
	b.calls = strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	b.result = map[string]string{}
	env, err := os.ReadFile(filepath.Join(b.root, "run/paddock/encrypt-boot.env"))
	if err != nil {
		b.t.Fatalf("no boot result: %v\n%s", err, b.output)
	}
	for line := range strings.Lines(string(env)) {
		k, v, _ := strings.Cut(strings.TrimSuffix(line, "\n"), "=")
		b.result[k] = v
	}
	b.keyNeverLeaks()
	if _, err := os.Stat(filepath.Join(b.root, "run/paddock/encrypt-init.err")); !os.IsNotExist(err) {
		b.t.Errorf("the script left its stderr file behind: %v", err)
	}
}

// keyNeverLeaks: the key is passed by path only and never appears in a command line or the output.
func (b *boot) keyNeverLeaks() {
	b.t.Helper()
	for _, c := range b.calls {
		if strings.Contains(c, bootKey) {
			b.t.Errorf("the key is on a command line: %s", c)
		}
		if strings.Contains(c, "encrypt-key") && !strings.Contains(c, " --key-file /etc/paddock/encrypt-key ") {
			b.t.Errorf("encrypt-key not passed as the key file path: %s", c)
		}
	}
	if strings.Contains(b.output, bootKey) {
		b.t.Errorf("the key is in the output:\n%s", b.output)
	}
}

func (b *boot) dev() string { return b.root + "/dev/disk/by-partuuid/" + bootPartUUID }
func (b *boot) lv() string  { return b.root + "/dev/ubuntu-vg/ubuntu-lv" }

func (b *boot) initCall() string {
	return "cryptsetup reencrypt --encrypt --type luks2 --init-only --reduce-device-size 32M --uuid " + bootLUKSUUID +
		" --key-file /etc/paddock/encrypt-key --batch-mode " + b.dev() + " dm_crypt-0"
}

// wantResult checks encrypt-boot.env.
func (b *boot) wantResult(status, stage, reason string) {
	b.t.Helper()
	if b.result["PADDOCK_BOOT_STATUS"] != status || b.result["PADDOCK_BOOT_STAGE"] != stage ||
		b.result["PADDOCK_BOOT_REASON"] != reason || b.result["PADDOCK_BOOT_SECONDS"] != "0" {
		b.t.Fatalf("result %v, want %s %s %q\ncalls:\n%s\noutput:\n%s", b.result, status, stage, reason,
			strings.Join(b.calls, "\n"), b.output)
	}
}

// inOrder checks that want appear among the calls in this order.
func (b *boot) inOrder(want ...string) {
	b.t.Helper()
	i := 0
	for _, c := range b.calls {
		if i < len(want) && c == want[i] {
			i++
		}
	}
	if i < len(want) {
		b.t.Fatalf("call %q missing or out of order; calls:\n%s", want[i], strings.Join(b.calls, "\n"))
	}
}

// never checks that no call starts with any of prefixes.
func (b *boot) never(prefixes ...string) {
	b.t.Helper()
	for _, c := range b.calls {
		for _, p := range prefixes {
			if strings.HasPrefix(c, p) {
				b.t.Errorf("unexpected call %q", c)
			}
		}
	}
}

func (b *boot) count(call string) int {
	n := 0
	for _, c := range b.calls {
		if c == call {
			n++
		}
	}
	return n
}

func (b *boot) logged(lines ...string) {
	b.t.Helper()
	for _, l := range lines {
		if !strings.Contains(b.output, "paddock-encrypt: "+l+"\n") {
			b.t.Errorf("log line %q missing:\n%s", l, b.output)
		}
	}
}

func (b *boot) notLogged(lines ...string) {
	b.t.Helper()
	for _, l := range lines {
		if strings.Contains(b.output, "paddock-encrypt: "+l+"\n") {
			b.t.Errorf("unexpected log line %q", l)
		}
	}
}

func eachShell(t *testing.T, plan func() encrypt.Plan, fn func(b *boot)) {
	t.Helper()
	for name, shell := range shells(t) {
		t.Run(name, func(t *testing.T) {
			fn(newBoot(t, shell, plan()))
		})
	}
}

func TestInitScriptLVMFirstRun(t *testing.T) {
	eachShell(t, lvmPlan, func(b *boot) {
		b.run()
		p := b.plan
		b.inOrder("udevadm settle --timeout=30", "cryptsetup isLuks "+b.dev(),
			"lvm vgchange -ay ubuntu-vg",
			"e2fsck -f -p "+b.lv(),
			"resize2fs "+b.lv()+" "+strconv.FormatInt(p.FSTargetBytes/512, 10)+"s",
			"lvm lvreduce -f -L "+strconv.FormatInt(p.FSTargetBytes, 10)+"b "+b.lv(),
			"lvm pvresize -y --setphysicalvolumesize "+strconv.FormatInt(p.PVTargetBytes, 10)+"b "+b.dev(),
			"lvm vgchange -an ubuntu-vg",
			b.initCall(),
			"udevadm settle --timeout=30",
			"lvm vgchange -ay ubuntu-vg")
		b.wantResult("ok", "init", "")
		b.logged("shrink done", "init done")
		b.inOrder(splashCall, "lvm vgchange -ay ubuntu-vg", splashCall, b.initCall())
		b.notLogged("file system already at target", "header found, opening")
		b.never("sleep ", "cryptsetup open")
	})
}

// splashCall is what the boot splash shows before the shrink and before the init (amendment 2026-10-21).
const splashCall = "plymouth display-message --text=Encrypting the disk - do not switch off"

func TestInitScriptLVMRerunAfterShrink(t *testing.T) {
	eachShell(t, lvmPlan, func(b *boot) {
		b.atTarget()
		b.run()
		b.inOrder("lvm vgchange -ay ubuntu-vg", "e2fsck -f -p "+b.lv(), "lvm vgchange -an ubuntu-vg", b.initCall(),
			"lvm vgchange -ay ubuntu-vg")
		b.never("resize2fs", "lvm lvreduce", "lvm pvresize")
		b.wantResult("ok", "init", "")
		b.logged("file system already at target", "shrink done", "init done")
	})
}

func TestInitScriptPlainFirstRun(t *testing.T) {
	eachShell(t, plainPlan, func(b *boot) {
		b.run()
		b.inOrder("e2fsck -f -p "+b.dev(), "dumpe2fs -h "+b.dev(),
			"resize2fs "+b.dev()+" "+strconv.FormatInt(b.plan.FSTargetBytes/512, 10)+"s", b.initCall(),
			"udevadm settle --timeout=30")
		b.never("lvm ", "blockdev ")
		b.wantResult("ok", "init", "")
		b.logged("shrink done", "init done")
	})
}

func TestInitScriptPlainRerunAfterShrink(t *testing.T) {
	eachShell(t, plainPlan, func(b *boot) {
		b.atTarget()
		b.run()
		b.never("resize2fs", "lvm ")
		b.inOrder("e2fsck -f -p "+b.dev(), b.initCall())
		b.wantResult("ok", "init", "")
		b.logged("file system already at target", "shrink done")
	})
}

// TestInitScriptOpensHeader: a header on the disk is opened before anything else, also on battery and with the test
// delays armed (the open path never sleeps, decision 19).
func TestInitScriptOpensHeader(t *testing.T) {
	eachShell(t, lvmPlan, func(b *boot) {
		b.rules = `"cryptsetup isLuks "*) exit 0 ;;` + "\n"
		b.supply("BAT0", "Battery", "", "")
		b.supply("AC", "Mains", "0", "")
		b.testHooks("init:120")
		b.run()
		want := []string{"udevadm settle --timeout=30", "cryptsetup isLuks " + b.dev(),
			"cryptsetup open --key-file /etc/paddock/encrypt-key " + b.dev() + " dm_crypt-0", "lvm vgchange -ay ubuntu-vg"}
		if !slices.Equal(b.calls, want) {
			b.t.Fatalf("calls:\n%s", strings.Join(b.calls, "\n"))
		}
		b.wantResult("ok", "open", "")
		b.logged("header found, opening")
	})
	eachShell(t, plainPlan, func(b *boot) {
		b.rules = `"cryptsetup isLuks "*) exit 0 ;;` + "\n"
		b.run()
		b.inOrder("cryptsetup open --key-file /etc/paddock/encrypt-key " + b.dev() + " dm_crypt-0")
		b.never("lvm ", "e2fsck")
		b.wantResult("ok", "open", "")
	})
}

// TestInitScriptMappingActive: a mapping that is already open (the crypttab line of decision 20) is not opened again.
func TestInitScriptMappingActive(t *testing.T) {
	eachShell(t, plainPlan, func(b *boot) {
		b.rules = `"cryptsetup isLuks "*) exit 0 ;;` + "\n"
		b.write("/dev/mapper/dm_crypt-0", "")
		b.run()
		b.never("cryptsetup open")
		b.wantResult("ok", "open", "")
	})
}

func TestInitScriptOpenFails(t *testing.T) {
	eachShell(t, lvmPlan, func(b *boot) {
		b.rules = `"cryptsetup isLuks "*) exit 0 ;;` + "\n" +
			`"cryptsetup open "*) printf 'No key available with this passphrase.' >&2; exit 2 ;;` + "\n"
		b.run()
		b.wantResult("failed", "open", "No_key_available_with_this_passphrase.")
		b.never("lvm ")
	})
}

func TestInitScriptOnBattery(t *testing.T) {
	cases := []struct {
		name     string
		supplies [][4]string
		skipped  bool
	}{
		{"battery without mains", [][4]string{{"BAT0", "Battery", "", ""}, {"AC", "Mains", "0", ""}}, true},
		{"battery only", [][4]string{{"BAT0", "Battery", "", "System"}}, true},
		{"battery on mains", [][4]string{{"BAT0", "Battery", "", ""}, {"AC", "Mains", "1", ""}}, false},
		{"peripheral battery", [][4]string{{"hid-mouse-battery", "Battery", "", "Device"}}, false},
		{"desktop", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eachShell(t, lvmPlan, func(b *boot) {
				for _, s := range tc.supplies {
					b.supply(s[0], s[1], s[2], s[3])
				}
				b.run()
				if !tc.skipped {
					b.wantResult("ok", "init", "")
					return
				}
				b.wantResult("skipped", "init", "on_battery")
				want := []string{"udevadm settle --timeout=30", "cryptsetup isLuks " + b.dev()}
				if !slices.Equal(b.calls, want) {
					b.t.Fatalf("a tool ran on battery:\n%s", strings.Join(b.calls, "\n"))
				}
			})
		})
	}
}

func TestInitScriptFsckFails(t *testing.T) {
	eachShell(t, lvmPlan, func(b *boot) {
		b.rules = `"e2fsck "*) exit 4 ;;` + "\n"
		b.run()
		b.wantResult("failed", "init", "fsck_4")
		b.inOrder("e2fsck -f -p "+b.lv(), "lvm vgchange -ay ubuntu-vg")
		b.never("resize2fs", "lvm lvreduce", "lvm pvresize", "lvm vgchange -an", "cryptsetup reencrypt")
	})
	eachShell(t, plainPlan, func(b *boot) {
		b.rules = `"e2fsck "*) exit 8 ;;` + "\n"
		b.run()
		b.wantResult("failed", "init", "fsck_8")
		b.never("resize2fs", "cryptsetup reencrypt")
	})
}

// TestInitScriptFsckCorrected: e2fsck exit 1 (errors corrected) lets the conversion go on.
func TestInitScriptFsckCorrected(t *testing.T) {
	eachShell(t, plainPlan, func(b *boot) {
		b.rules = `"e2fsck "*) exit 1 ;;` + "\n"
		b.run()
		b.wantResult("ok", "init", "")
	})
}

func TestInitScriptVGBusy(t *testing.T) {
	eachShell(t, lvmPlan, func(b *boot) {
		b.rules = `"lvm vgchange -an "*) echo "Logical volume ubuntu-vg/ubuntu-lv in use." >&2; exit 5 ;;` + "\n"
		b.run()
		b.wantResult("failed", "init", "vg_busy")
		b.inOrder("lvm vgchange -an ubuntu-vg", "lvm vgchange -ay ubuntu-vg")
		b.never("cryptsetup reencrypt")
	})
}

// TestInitScriptShrinkFails: a failing resize stops before the LV, the PV or the header is touched.
func TestInitScriptShrinkFails(t *testing.T) {
	eachShell(t, lvmPlan, func(b *boot) {
		b.rules = `"resize2fs "*) exit 1 ;;` + "\n"
		b.run()
		b.wantResult("failed", "init", "resize2fs_1")
		b.never("lvm lvreduce", "lvm pvresize", "cryptsetup reencrypt")
	})
	eachShell(t, lvmPlan, func(b *boot) {
		b.rules = `"lvm lvreduce "*) exit 5 ;;` + "\n"
		b.run()
		b.wantResult("failed", "init", "lvreduce_5")
		b.never("lvm pvresize", "cryptsetup reencrypt")
	})
	eachShell(t, lvmPlan, func(b *boot) {
		b.rules = `"blockdev "*) echo "blockdev: cannot open" >&2; exit 1 ;;` + "\n"
		b.run()
		b.wantResult("failed", "init", "size_unknown")
		b.never("resize2fs", "lvm lvreduce", "cryptsetup reencrypt")
	})
	eachShell(t, plainPlan, func(b *boot) {
		b.rules = `"dumpe2fs "*) echo "Block count: lots" ;;` + "\n"
		b.run()
		b.wantResult("failed", "init", "size_unknown")
		b.never("resize2fs", "cryptsetup reencrypt")
	})
}

func TestInitScriptLUKSInitFails(t *testing.T) {
	eachShell(t, lvmPlan, func(b *boot) {
		b.rules = `"cryptsetup reencrypt "*) exit 3 ;;` + "\n"
		b.run()
		b.wantResult("failed", "init", "luks_init_3")
		b.inOrder(b.initCall(), "cryptsetup isLuks "+b.dev(), "lvm vgchange -ay ubuntu-vg")
		b.never("cryptsetup open")
		b.notLogged("init done")
	})
	eachShell(t, plainPlan, func(b *boot) {
		b.rules = `"cryptsetup reencrypt "*) exit 1 ;;` + "\n"
		b.run()
		b.wantResult("failed", "init", "luks_init_1")
		b.never("lvm ")
	})
}

// TestInitScriptHeaderWrittenDespiteFailure: once the header is on the disk the device boots only through it, so a
// failing init continues as an online reencryption.
func TestInitScriptHeaderWrittenDespiteFailure(t *testing.T) {
	eachShell(t, lvmPlan, func(b *boot) {
		b.rules = `"cryptsetup isLuks "*) [ -e "$STUB_DIR/header" ] && exit 0; exit 1 ;;` + "\n" +
			`"cryptsetup reencrypt "*) : >"$STUB_DIR/header"; exit 1 ;;` + "\n"
		b.run()
		b.inOrder(b.initCall(), "cryptsetup isLuks "+b.dev(),
			"cryptsetup open --key-file /etc/paddock/encrypt-key "+b.dev()+" dm_crypt-0", "lvm vgchange -ay ubuntu-vg")
		b.wantResult("ok", "init", "")
	})
}

func TestInitScriptDeviceMissing(t *testing.T) {
	eachShell(t, lvmPlan, func(b *boot) {
		b.remove("/dev/disk/by-partuuid/" + bootPartUUID)
		b.run()
		b.wantResult("failed", "init", "device_missing")
		if b.count("sleep 1") != 30 {
			b.t.Fatalf("waited %d s", b.count("sleep 1"))
		}
		b.never("cryptsetup", "lvm", "e2fsck")
	})
}

func TestInitScriptRootMissing(t *testing.T) {
	eachShell(t, plainPlan, func(b *boot) {
		// The init creates the mapping, but the UUID link stays on the raw partition.
		b.rules = `"cryptsetup reencrypt "*) : >"$PADDOCK_ENCRYPT_TEST_ROOT/dev/mapper/dm_crypt-0" ;;` + "\n"
		b.run()
		b.wantResult("failed", "init", "root_missing")
		b.logged("init done")
	})
}

func TestInitScriptBadPlan(t *testing.T) {
	eachShell(t, lvmPlan, func(b *boot) {
		b.write("/etc/paddock/encrypt-plan.env", "PADDOCK_LAYOUT=lvm\n")
		b.run()
		b.wantResult("failed", "init", "plan_invalid")
		b.never("udevadm", "cryptsetup", "lvm", "e2fsck")
	})
	// A plan the shell cannot parse ends the script's main part; the fallback still records a result and exits 0.
	eachShell(t, lvmPlan, func(b *boot) {
		b.write("/etc/paddock/encrypt-plan.env", "PADDOCK_LAYOUT=(\n")
		b.run()
		if b.result["PADDOCK_BOOT_STATUS"] != "failed" || b.result["PADDOCK_BOOT_STAGE"] != "init" ||
			!strings.HasPrefix(b.result["PADDOCK_BOOT_REASON"], "script_") {
			b.t.Fatalf("result %v", b.result)
		}
		b.never("udevadm", "cryptsetup", "lvm", "e2fsck")
	})
}

func TestInitScriptTestDelays(t *testing.T) {
	eachShell(t, lvmPlan, func(b *boot) {
		b.testHooks("init:120")
		b.run()
		b.inOrder("lvm vgchange -an ubuntu-vg", "sleep 120", b.initCall())
		b.wantResult("ok", "init", "")
	})
	eachShell(t, plainPlan, func(b *boot) {
		b.testHooks("open:60")
		b.run()
		b.inOrder(b.initCall(), "sleep 60", "udevadm settle --timeout=30")
		if b.count("sleep 60") != 1 {
			b.t.Fatal("open delay not exactly once")
		}
	})
	// Without the marker of a dev build the command line is ignored.
	eachShell(t, lvmPlan, func(b *boot) {
		b.testHooks("init:120")
		b.remove("/etc/paddock/encrypt-test")
		b.run()
		b.never("sleep")
	})
}

// moduleHarness sources module-setup.sh the way dracut does, with recording stand-ins for dracut's functions.
const moduleHarness = `set -u
log=$1 dracutsysrootdir=$2 initdir=$3 moddir=$4
systemdsystemunitdir=/usr/lib/systemd/system SYSTEMCTL=systemctl_stub hostonly=yes
systemctl_stub() { echo "systemctl $*" >>"$log"; }
inst_multiple() { echo "inst_multiple $*" >>"$log"; }
dfatal() { echo "dfatal $*" >>"$log"; }
instmods() { echo "instmods hostonly=${hostonly-unset} $*" >>"$log"; }
inst_simple() {
	echo "inst_simple $*" >>"$log"
	mkdir -p "$initdir${2%/*}"
	if [[ -e $dracutsysrootdir$1 ]]; then cp "$dracutsysrootdir$1" "$initdir$2"; else cp "$1" "$initdir$2"; fi
}
. "$moddir/module-setup.sh"
check; echo "check $?" >>"$log"
[[ $5 == check ]] && exit 0
echo "depends $(depends)" >>"$log"
installkernel; echo "installkernel $?" >>"$log"
install
`

type dracutBuild struct {
	sysroot, initdir string
	log              []string
}

// buildModule runs the module against a host with the given files and returns dracut's view of it.
func buildModule(t *testing.T, host map[string]string, phase string) dracutBuild {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("dracut modules are bash; no bash on the host")
	}
	dir := t.TempDir()
	b := dracutBuild{sysroot: filepath.Join(dir, "sysroot"), initdir: filepath.Join(dir, "initrd")}
	moddir := filepath.Join(dir, "99paddock-encrypt")
	if err := encrypt.WriteModule(paths.Layout{Root: dir}, encrypt.Module()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, encrypt.ModuleDir), moddir); err != nil {
		t.Fatal(err)
	}
	for p, content := range host {
		full := filepath.Join(b.sysroot, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	harness := filepath.Join(dir, "harness.sh")
	if err := os.WriteFile(harness, []byte(moduleHarness), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "log")
	out, err := exec.Command(bash, harness, logPath, b.sysroot, b.initdir, moddir, phase).CombinedOutput() //nolint:gosec // the host's bash
	if err != nil {
		t.Fatalf("module-setup.sh: %v\n%s", err, out)
	}
	raw, _ := os.ReadFile(logPath)
	b.log = strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	return b
}

func hostWithPlan(t *testing.T, plan encrypt.Plan) map[string]string {
	t.Helper()
	env, err := plan.Env()
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{"/var/lib/paddock/encrypt/plan.env": string(env), "/var/lib/paddock/install-passphrase": bootKey}
}

func TestModuleSetupCheck(t *testing.T) {
	if got := buildModule(t, hostWithPlan(t, lvmPlan()), "check").log; !slices.Equal(got, []string{"check 0"}) {
		t.Fatalf("with the plan: %v", got)
	}
	if got := buildModule(t, map[string]string{"/var/lib/paddock/install-passphrase": bootKey}, "check").log; !slices.Equal(got, []string{"check 1"}) {
		t.Fatalf("without the plan: %v", got)
	}
}

// TestModuleSetupWithoutKey: an initrd with the plan but without the key is never built: installkernel() fails, which
// makes dracut stop and keep the previous initrd (dracut ignores install()'s status).
func TestModuleSetupWithoutKey(t *testing.T) {
	host := hostWithPlan(t, lvmPlan())
	delete(host, "/var/lib/paddock/install-passphrase")
	b := buildModule(t, host, "install")
	if !slices.Contains(b.log, "check 0") || !slices.Contains(b.log, "installkernel 1") ||
		!slices.Contains(b.log, "dfatal paddock-encrypt: /var/lib/paddock/install-passphrase is missing") {
		t.Fatalf("log:\n%s", strings.Join(b.log, "\n"))
	}
}

func TestModuleSetupInstallLVM(t *testing.T) {
	b := buildModule(t, hostWithPlan(t, lvmPlan()), "install")
	want := []string{
		"check 0",
		"depends systemd crypt lvm",
		"instmods hostonly= dm_crypt dm_mod =crypto",
		"installkernel 0",
		"inst_multiple cryptsetup e2fsck resize2fs dumpe2fs blockdev blkid udevadm mkdir rm sleep readlink",
		"inst_multiple -o plymouth",
		"inst_multiple lvm",
		"inst_simple /var/lib/paddock/encrypt/plan.env /etc/paddock/encrypt-plan.env",
		"inst_simple /var/lib/paddock/install-passphrase /etc/paddock/encrypt-key",
	}
	if !slices.Equal(b.log[:len(want)], want) {
		t.Fatalf("log:\n%s", strings.Join(b.log, "\n"))
	}
	rest := strings.Join(b.log[len(want):], "\n")
	for _, line := range []string{"/paddock-encrypt-init.sh /usr/libexec/paddock/encrypt-init.sh",
		"/paddock-encrypt-init.service /usr/lib/systemd/system/paddock-encrypt-init.service",
		"systemctl -q --root " + b.initdir + " enable paddock-encrypt-init.service"} {
		if !strings.Contains(rest, line) {
			t.Errorf("missing %q in:\n%s", line, rest)
		}
	}
	if strings.Contains(rest, "encrypt-test") {
		t.Error("a release host installed the test marker")
	}
	for _, p := range []string{"/etc/paddock/encrypt-key", "/etc/paddock/encrypt-plan.env"} {
		info, err := os.Stat(filepath.Join(b.initdir, p))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", p, info, err)
		}
	}
	if raw, _ := os.ReadFile(filepath.Join(b.initdir, "/etc/paddock/encrypt-key")); string(raw) != bootKey {
		t.Error("the key in the initrd differs")
	}
	if raw, _ := os.ReadFile(filepath.Join(b.initdir, rdLUKSConf)); string(raw) != "rd.luks=0\n" {
		t.Errorf("cmdline.d: %q", raw)
	}
}

// rdLUKSConf turns off dracut's own LUKS handling in an initrd that carries the module (amendment 2026-10-21).
const rdLUKSConf = "/etc/cmdline.d/91paddock-encrypt.conf"

// TestRDLUKSOnlyFromInstall: only install() writes rd.luks=0 — check() leaves the initrd alone, and the init script
// never touches it.
func TestRDLUKSOnlyFromInstall(t *testing.T) {
	for _, host := range []map[string]string{hostWithPlan(t, lvmPlan()), {}} {
		b := buildModule(t, host, "check")
		if _, err := os.Stat(filepath.Join(b.initdir, rdLUKSConf)); !os.IsNotExist(err) {
			t.Fatalf("check() wrote %s: %v", rdLUKSConf, err)
		}
	}
	script, err := fs.ReadFile(encrypt.Module(), "paddock-encrypt-init.sh")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(script), "rd.luks") || strings.Contains(string(script), "91paddock-encrypt.conf") {
		t.Fatal("the init script touches rd.luks")
	}
}

func TestModuleSetupInstallPlainWithTestHooks(t *testing.T) {
	host := hostWithPlan(t, plainPlan())
	host["/var/lib/paddock/encrypt/test-hooks"] = ""
	b := buildModule(t, host, "install")
	all := strings.Join(b.log, "\n")
	if !slices.Contains(b.log, "depends systemd crypt") || strings.Contains(all, "inst_multiple lvm") {
		t.Fatalf("plain layout:\n%s", all)
	}
	if !slices.Contains(b.log, "inst_simple /var/lib/paddock/encrypt/test-hooks /etc/paddock/encrypt-test") {
		t.Fatalf("test marker not installed:\n%s", all)
	}
}

// TestModuleFiles: the build carries exactly the module's three files, and the unit is plan M8e §6.4 byte for byte.
func TestModuleFiles(t *testing.T) {
	entries, err := fs.ReadDir(encrypt.Module(), ".")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if !slices.Equal(names, []string{"module-setup.sh", "paddock-encrypt-init.service", "paddock-encrypt-init.sh"}) {
		t.Fatalf("module files %v", names)
	}
	plan, err := os.ReadFile("../../../docs/plans/M8e-in-place-encryption.md")
	if err != nil {
		t.Fatal(err)
	}
	_, after, ok := strings.Cut(string(plan), "`paddock-encrypt-init.service` (binding):\n\n```ini\n")
	unit, _, ok2 := strings.Cut(after, "```\n")
	if !ok || !ok2 {
		t.Fatal("the binding unit is not in the plan")
	}
	got, err := fs.ReadFile(encrypt.Module(), "paddock-encrypt-init.service")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != unit {
		t.Fatalf("unit differs from plan §6.4:\n%s\nwant:\n%s", got, unit)
	}
}

// TestInitScriptIsLuksUnknown: when cryptsetup cannot tell whether the partition is LUKS nothing is changed.
func TestInitScriptIsLuksUnknown(t *testing.T) {
	eachShell(t, lvmPlan, func(b *boot) {
		b.rules = `"cryptsetup isLuks "*) exit 4 ;;` + "\n"
		b.run()
		b.wantResult("failed", "init", "isluks_4")
		b.never("e2fsck", "lvm", "resize2fs", "cryptsetup reencrypt", "cryptsetup open")
	})
}

func TestInitScriptVGActivateFails(t *testing.T) {
	eachShell(t, lvmPlan, func(b *boot) {
		b.rules = `"lvm vgchange -ay "*) exit 5 ;;` + "\n"
		b.run()
		b.wantResult("failed", "init", "vg_activate_5")
		b.never("e2fsck", "resize2fs", "cryptsetup reencrypt")
	})
	eachShell(t, lvmPlan, func(b *boot) {
		b.rules = `"cryptsetup isLuks "*) exit 0 ;;` + "\n" + `"lvm vgchange -ay "*) exit 5 ;;` + "\n"
		b.run()
		b.wantResult("failed", "open", "vg_activate_5")
	})
}

// TestInitScriptLVMRerunAfterLVReduce: a power cut after lvreduce and before pvresize resizes only the PV.
func TestInitScriptLVMRerunAfterLVReduce(t *testing.T) {
	eachShell(t, lvmPlan, func(b *boot) {
		b.sizes(b.plan.FSTargetBytes, bootPartSize, 0)
		b.run()
		b.never("resize2fs", "lvm lvreduce")
		b.inOrder("lvm pvresize -y --setphysicalvolumesize "+strconv.FormatInt(b.plan.PVTargetBytes, 10)+"b "+b.dev(),
			"lvm vgchange -an ubuntu-vg", b.initCall())
		b.wantResult("ok", "init", "")
		b.logged("file system already at target")
	})
}

// TestInitScriptDeviceMismatch: a partition with the plan's PARTUUID but another file system or VG (a cloned disk)
// is never touched.
func TestInitScriptDeviceMismatch(t *testing.T) {
	eachShell(t, lvmPlan, func(b *boot) {
		b.rules = `"lvm pvs --noheadings -o vg_name "*) echo "  other-vg" ;;` + "\n"
		b.run()
		b.wantResult("failed", "init", "device_mismatch")
		b.never("lvm vgchange", "e2fsck", "resize2fs", "cryptsetup reencrypt")
	})
	eachShell(t, plainPlan, func(b *boot) {
		b.rules = `"blkid "*) echo "11111111-2222-3333-4444-555555555555" ;;` + "\n"
		b.run()
		b.wantResult("failed", "init", "device_mismatch")
		b.never("e2fsck", "resize2fs", "cryptsetup reencrypt")
	})
}

// TestInitScriptMappingMissing: the plain root's UUID link exists before the conversion, so success needs the mapping.
func TestInitScriptMappingMissing(t *testing.T) {
	eachShell(t, plainPlan, func(b *boot) {
		b.rules = `"cryptsetup reencrypt "*) exit 0 ;;` + "\n"
		b.run()
		b.wantResult("failed", "init", "mapping_missing")
	})
}

// TestInitScriptResumeSet: a configured resume from hibernation skips the conversion before any tool that changes
// the disk; a header on the disk is still opened.
func TestInitScriptResumeSet(t *testing.T) {
	eachShell(t, lvmPlan, func(b *boot) {
		b.env = append(b.env, "RESUME=UUID=0b1c")
		b.run()
		b.wantResult("skipped", "init", "resume_set")
		want := []string{"udevadm settle --timeout=30", "cryptsetup isLuks " + b.dev()}
		if !slices.Equal(b.calls, want) {
			b.t.Fatalf("calls:\n%s", strings.Join(b.calls, "\n"))
		}
	})
	eachShell(t, lvmPlan, func(b *boot) {
		b.env = append(b.env, "RESUME=UUID=0b1c")
		b.rules = `"cryptsetup isLuks "*) exit 0 ;;` + "\n"
		b.run()
		b.wantResult("ok", "open", "")
	})
}

// TestInitScriptDuplicatePartUUID: two devices with the plan's PARTUUID (a cloned disk) stop the conversion.
func TestInitScriptDuplicatePartUUID(t *testing.T) {
	eachShell(t, plainPlan, func(b *boot) {
		b.rules = `"blkid -o device -t "*) printf '/dev/sda3\n/dev/sdb3\n' ;;` + "\n"
		b.run()
		b.wantResult("failed", "init", "device_mismatch")
		b.never("e2fsck", "resize2fs", "cryptsetup reencrypt")
	})
}

// TestInitScriptFsckPreensOnly: the file system check never answers yes to every repair.
func TestInitScriptFsckPreensOnly(t *testing.T) {
	eachShell(t, plainPlan, func(b *boot) {
		b.run()
		for _, c := range b.calls {
			if strings.HasPrefix(c, "e2fsck") && c != "e2fsck -f -p "+b.dev() {
				b.t.Fatalf("e2fsck call %q", c)
			}
		}
	})
}
