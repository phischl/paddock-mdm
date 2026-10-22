package encrypt_test

import (
	"context"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/encrypt"
	"github.com/phischl/paddock-mdm/agent/internal/state"
)

// convertedFixture is a prepared device whose disk converted at the restart: the partition is LUKS with the
// conversion key's keyslot and the reencrypt keyslot.
func convertedFixture(t *testing.T) *fixture {
	t.Helper()
	f := preparedFixture(t)
	f.dev.set(func(d *device) { d.luks, d.slots = true, []string{"password", "reencrypt"} })
	return f
}

// TestRegenerateInitrd: plan M8e decision 20 in the order of invariant I1 (amendment 2026-10-21, item 8) — the
// crypttab line first, then every kernel's initrd is built without the module while the host still has it, and only
// after all were verified the module and the plan files go, plan.env last; the conversion key stays for the luks
// reconciler.
func TestRegenerateInitrd(t *testing.T) {
	f := convertedFixture(t)
	c := f.conversion()
	f.dev.Write("/etc/crypttab", "# existing\ndata UUID=1111 none luks")
	f.dev.Write("/var/lib/paddock/encrypt/test-hooks", "")
	var order []string
	f.dev.set(func(d *device) {
		d.afterDracut = func(d *device) {
			crypttab, _ := os.ReadFile(d.Path("/etc/crypttab"))
			order = append(order, "dracut", "crypttab:"+strconv.Itoa(strings.Count(string(crypttab), c.LUKSUUID+" none")),
				"module:"+boolString(d.Exists(encrypt.ModuleDir) || d.Exists(encrypt.ModuleConf)),
				"plan.env:"+boolString(d.Exists("/var/lib/paddock/encrypt/plan.env")))
		}
	})
	if err := encrypt.RegenerateInitrd(context.Background(), f.dev, f.dev.layout, c.Mapping, c.LUKSUUID, true); err != nil {
		t.Fatal(err)
	}
	if want := []string{"dracut", "crypttab:1", "module:true", "plan.env:true", "dracut", "crypttab:1", "module:true",
		"plan.env:true"}; !slices.Equal(order, want) {
		t.Fatalf("order %v", order)
	}
	if got := f.read("/etc/crypttab"); got != "# existing\ndata UUID=1111 none luks\n"+c.Mapping+" UUID="+c.LUKSUUID+
		" none luks,tpm2-device=auto\n" {
		t.Fatalf("crypttab %q", got)
	}
	for _, p := range []string{"/var/lib/paddock/encrypt/plan.env", "/var/lib/paddock/encrypt/plan.json",
		"/var/lib/paddock/encrypt/test-hooks", encrypt.ModuleDir, encrypt.ModuleConf} {
		if f.dev.Exists(p) {
			t.Errorf("%s left", p)
		}
	}
	if !f.dev.Exists("/var/lib/paddock/install-passphrase") || f.dev.initrdCarriesModule(runningKernel) ||
		f.dev.initrdCarriesModule(olderKernel) {
		t.Fatal("the key went, or an initrd still carries the module")
	}
	// A second run (a retry after a failed save) adds no second line.
	if err := encrypt.RegenerateInitrd(context.Background(), f.dev, f.dev.layout, c.Mapping, c.LUKSUUID, true); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(f.read("/etc/crypttab"), c.LUKSUUID); n != 1 {
		t.Fatalf("crypttab lines %d", n)
	}
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// TestRegenerateInitrdFailure: amendment 2026-10-21, item 8 (adversarial review M1) — a failed build, a new initrd
// that still carries the module, lacks the TPM unlock, or whose crypttab does not open the volume, replaces no
// initrd: every current initrd still carries the module and the key, the host keeps the module, plan.env, plan.json
// and the key, and no temporary file is left; the retry then succeeds.
func TestRegenerateInitrdFailure(t *testing.T) {
	for name, set := range map[string]func(d *device){
		"dracut fails":   func(d *device) { d.dracutExit = 1 },
		"stale initrd":   func(d *device) { d.stale = true },
		"lsinitrd fails": func(d *device) { d.missing = map[string]bool{"lsinitrd": true, "lsinitramfs": true} },
		"no TPM unlock":  func(d *device) { d.noTPM = true },
		"no crypttab": func(d *device) {
			d.afterDracut = func(d *device) { _ = os.Remove(d.Path("/etc/crypttab")) }
		},
	} {
		f := convertedFixture(t)
		c := f.conversion()
		f.dev.set(set)
		if err := encrypt.RegenerateInitrd(context.Background(), f.dev, f.dev.layout, c.Mapping, c.LUKSUUID, true); err == nil {
			t.Fatalf("%s: no error", name)
		}
		for _, v := range []string{runningKernel, olderKernel} {
			if !f.dev.initrdCarriesModule(v) {
				t.Fatalf("%s: the initrd of %s lost its unlock path", name, v)
			}
		}
		if temps := glob(t, f.dev.Path("/boot/.initrd.img-*")); len(temps) != 0 {
			t.Fatalf("%s: temporary initrds left: %v", name, temps)
		}
		for _, p := range []string{encrypt.ModuleDir, encrypt.ModuleConf, "/var/lib/paddock/encrypt/plan.env",
			"/var/lib/paddock/encrypt/plan.json", "/var/lib/paddock/install-passphrase"} {
			if !f.dev.Exists(p) {
				t.Fatalf("%s: %s removed before the verification", name, p)
			}
		}
		f.dev.set(func(d *device) { d.dracutExit, d.stale, d.missing, d.noTPM, d.afterDracut = 0, false, nil, false, nil })
		if name == "no crypttab" {
			f.dev.Write("/etc/crypttab", "")
		}
		if err := encrypt.RegenerateInitrd(context.Background(), f.dev, f.dev.layout, c.Mapping, c.LUKSUUID, true); err != nil {
			t.Fatalf("%s: retry: %v", name, err)
		}
		if f.dev.Exists("/var/lib/paddock/encrypt/plan.env") {
			t.Fatalf("%s: plan.env left after the retry", name)
		}
	}
}

// TestRestoreModule: plan M8e decision 18 — an adopted conversion whose cleanup removed the module, its configuration
// and plan.env gets them back from the embedded copy and plan.json, and every installed kernel's initrd carries the
// module again; an initrd still without it fails the restore.
func TestRestoreModule(t *testing.T) {
	f := convertedFixture(t)
	for _, p := range []string{encrypt.ModuleDir, encrypt.ModuleConf, "/var/lib/paddock/encrypt/plan.env"} {
		if err := os.RemoveAll(f.dev.Path(p)); err != nil {
			t.Fatal(err)
		}
	}
	f.dev.buildInitrds()
	if !encrypt.ModuleMissing(f.dev.layout) {
		t.Fatal("the removed module is not missing")
	}
	if err := encrypt.RestoreModule(context.Background(), f.dev, f.dev.layout, module); err != nil {
		t.Fatal(err)
	}
	if encrypt.ModuleMissing(f.dev.layout) || !f.dev.initrdCarriesModule(runningKernel) || !f.dev.initrdCarriesModule(olderKernel) ||
		!strings.Contains(f.read("/var/lib/paddock/encrypt/plan.env"), "PADDOCK_MAPPING=dm_crypt-0\n") ||
		f.read(encrypt.ModuleConf) != "add_dracutmodules+=\" paddock-encrypt \"\n" || f.mode("/var/lib/paddock/encrypt/plan.env") != 0o600 {
		t.Fatalf("not restored: calls %v", f.dev.Calls())
	}
	for _, v := range []string{runningKernel, olderKernel} {
		if f.mode("/boot/initrd.img-"+v) != 0o600 {
			t.Fatalf("initrd %s readable by others", v)
		}
	}

	for name, set := range map[string]func(d *device){
		"incomplete":   func(d *device) { d.incomplete = true },
		"dracut fails": func(d *device) { d.dracutExit = 1 },
	} {
		f := convertedFixture(t)
		_ = os.RemoveAll(f.dev.Path(encrypt.ModuleDir))
		f.dev.set(set)
		if err := encrypt.RestoreModule(context.Background(), f.dev, f.dev.layout, module); err == nil {
			t.Fatalf("%s: restored", name)
		}
	}
	f = convertedFixture(t)
	_ = os.Remove(f.dev.Path("/var/lib/paddock/encrypt/plan.json"))
	if err := encrypt.RestoreModule(context.Background(), f.dev, f.dev.layout, module); err == nil {
		t.Fatal("restored without plan.json")
	}
}

// TestRearmDiskSetup: plan M8e decision 52 — the marker of the PIN dialogue is re-created when missing, an existing one
// is left alone.
func TestRearmDiskSetup(t *testing.T) {
	f := convertedFixture(t)
	if armed, err := encrypt.RearmDiskSetup(f.dev.layout); err != nil || armed {
		t.Fatalf("existing marker: %v %v", armed, err)
	}
	_ = os.Remove(f.dev.Path("/var/lib/paddock/disk-setup-pending"))
	if armed, err := encrypt.RearmDiskSetup(f.dev.layout); err != nil || !armed || !f.dev.Exists("/var/lib/paddock/disk-setup-pending") {
		t.Fatalf("re-arm: %v %v", armed, err)
	}
}

// TestBootResult: /run/paddock/encrypt-boot.env as the init script writes it, and init_result (plan M8e decision 18).
func TestBootResult(t *testing.T) {
	f := newFixture(t)
	if r, err := encrypt.ReadBootResult(f.dev.layout); r != nil || err != nil || r.InitResult() != "unknown" {
		t.Fatalf("missing file: %+v %v", r, err)
	}
	for content, want := range map[string]string{
		"PADDOCK_BOOT_STATUS=ok\nPADDOCK_BOOT_STAGE=init\nPADDOCK_BOOT_REASON=\nPADDOCK_BOOT_SECONDS=42\n":                "ok",
		"PADDOCK_BOOT_STATUS=failed\nPADDOCK_BOOT_STAGE=init\nPADDOCK_BOOT_REASON=root_missing\nPADDOCK_BOOT_SECONDS=9\n": "init:root_missing",
		"PADDOCK_BOOT_STATUS=skipped\nPADDOCK_BOOT_STAGE=init\nPADDOCK_BOOT_REASON=on_battery\nPADDOCK_BOOT_SECONDS=1\n":  "init:on_battery",
		"PADDOCK_BOOT_STATUS=failed\nPADDOCK_BOOT_STAGE=open\nPADDOCK_BOOT_REASON=" + strings.Repeat("x", 300) + "\n":     "open:" + strings.Repeat("x", 195),
		"garbage\n": "unknown",
	} {
		f.dev.Write("/run/paddock/encrypt-boot.env", content)
		r, err := encrypt.ReadBootResult(f.dev.layout)
		if err != nil || r.InitResult() != want {
			t.Fatalf("%q: %q %v", content, r.InitResult(), err)
		}
	}
	f.dev.Write("/run/paddock/encrypt-boot.env", "garbage\n")
	if r, _ := encrypt.ReadBootResult(f.dev.layout); r.Seconds != -1 || r.Failed() {
		t.Fatalf("garbage: %+v", r)
	}
	f.dev.Write("/run/paddock/encrypt-boot.env", "PADDOCK_BOOT_STATUS=ok\nPADDOCK_BOOT_SECONDS=42\n")
	if r, _ := encrypt.ReadBootResult(f.dev.layout); r.Seconds != 42 || r.Failed() {
		t.Fatalf("seconds: %+v", r)
	}
	if err := encrypt.RemoveBootResult(f.dev.layout); err != nil || f.dev.Exists("/run/paddock/encrypt-boot.env") {
		t.Fatalf("remove: %v", err)
	}
	if err := encrypt.RemoveBootResult(f.dev.layout); err != nil {
		t.Fatalf("remove twice: %v", err)
	}
}

// TestRegenerateInitrdByUUIDLine: Review 1, M2 — a crypttab line that names the volume as /dev/disk/by-uuid/<uuid> is
// kept as it is and passes the verification; no second line is added.
func TestRegenerateInitrdByUUIDLine(t *testing.T) {
	f := convertedFixture(t)
	c := f.conversion()
	line := c.Mapping + " /dev/disk/by-uuid/" + c.LUKSUUID + " none luks,tpm2-device=auto\n"
	f.dev.Write("/etc/crypttab", line)
	if err := encrypt.RegenerateInitrd(context.Background(), f.dev, f.dev.layout, c.Mapping, c.LUKSUUID, true); err != nil {
		t.Fatal(err)
	}
	if got := f.read("/etc/crypttab"); got != line || f.dev.Exists("/var/lib/paddock/encrypt/plan.env") {
		t.Fatalf("crypttab %q", got)
	}
}

// TestRegenerateInitrdKernelAddedMidRun: adversarial review round 2, m1 (amendment item 13) — a kernel installed while
// the initrds are rebuilt (its package built an initrd with the module) fails the regeneration: the host keeps the
// module and plan.env, and the next pass rebuilds every initrd.
func TestRegenerateInitrdKernelAddedMidRun(t *testing.T) {
	f := convertedFixture(t)
	c := f.conversion()
	const newKernel = "6.8.0-90-generic"
	f.dev.set(func(d *device) {
		d.afterDracut = func(d *device) {
			if !d.Exists("/boot/vmlinuz-" + newKernel) {
				d.Write("/boot/vmlinuz-"+newKernel, "kernel")
				d.Write("/lib/modules/"+newKernel+"/modules.dep", "")
				d.buildInitrd("/boot/initrd.img-"+newKernel, newKernel, true)
			}
		}
	})
	if err := encrypt.RegenerateInitrd(context.Background(), f.dev, f.dev.layout, c.Mapping, c.LUKSUUID, true); err == nil {
		t.Fatal("regenerated with a kernel added meanwhile")
	}
	for _, p := range []string{encrypt.ModuleDir, encrypt.ModuleConf, "/var/lib/paddock/encrypt/plan.env"} {
		if !f.dev.Exists(p) {
			t.Fatalf("%s removed", p)
		}
	}
	f.dev.set(func(d *device) { d.afterDracut = nil })
	if err := encrypt.RegenerateInitrd(context.Background(), f.dev, f.dev.layout, c.Mapping, c.LUKSUUID, true); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if f.dev.initrdCarriesModule(newKernel) {
		t.Fatal("the new kernel's initrd still carries the module")
	}
}

// TestRegenerateInitrdPackageLock: amendment items 14 and 16 — the builds run without dpkg's locks; the renames, the
// final verification and the removal from the host run under them. While a package run holds them no initrd is
// replaced and nothing leaves the host; a current initrd that changed during the builds (a kernel package's dracut)
// is not replaced either; a write over a renamed initrd fails the final verification before the module leaves.
func TestRegenerateInitrdPackageLock(t *testing.T) {
	f := convertedFixture(t)
	c := f.conversion()
	f.dev.PackagesBusy = true
	builds := len(f.dev.Long())
	if err := encrypt.RegenerateInitrd(context.Background(), f.dev, f.dev.layout, c.Mapping, c.LUKSUUID, true); !errors.Is(err,
		encrypt.ErrPackagesBusy) || !f.dev.initrdCarriesModule(runningKernel) || !f.dev.Exists(encrypt.ModuleDir) ||
		len(glob(t, f.dev.Path("/boot/.initrd.img-*"))) != 0 || len(f.dev.Long()) != builds {
		t.Fatalf("built or changed while apt held the lock: %v", err)
	}
	f.dev.PackagesBusy = false

	unlockedBuilds, builds := true, 0
	f.dev.set(func(d *device) {
		d.afterDracut = func(d *device) {
			unlockedBuilds = unlockedBuilds && !d.PackagesLocked()
			// The last build: every current initrd's stamp was taken before its own build started.
			if builds++; builds == 2 {
				d.Write("/boot/initrd.img-"+olderKernel, "a package's rebuild\n")
			}
		}
	})
	if err := encrypt.RegenerateInitrd(context.Background(), f.dev, f.dev.layout, c.Mapping, c.LUKSUUID, true); err == nil ||
		f.read("/boot/initrd.img-"+olderKernel) != "a package's rebuild\n" || !f.dev.Exists(encrypt.ModuleDir) {
		t.Fatalf("replaced an initrd that changed during the build: %v", err)
	}
	if !unlockedBuilds {
		t.Fatal("the builds ran under dpkg's locks")
	}

	locked := false
	f.dev.set(func(d *device) {
		d.afterDracut = nil
		d.beforeFinalList = lateAt(3, func(d *device) {
			locked = d.PackagesLocked()
			d.buildInitrd("/boot/initrd.img-"+runningKernel, runningKernel, true)
		})
	})
	if err := encrypt.RegenerateInitrd(context.Background(), f.dev, f.dev.layout, c.Mapping, c.LUKSUUID, true); err == nil {
		t.Fatal("a late write over a verified initrd passed")
	}
	if !locked || f.dev.PackagesLocked() {
		t.Fatalf("final verification under the lock %v, released %v", locked, !f.dev.PackagesLocked())
	}
	for _, p := range []string{encrypt.ModuleDir, encrypt.ModuleConf, "/var/lib/paddock/encrypt/plan.env"} {
		if !f.dev.Exists(p) {
			t.Fatalf("%s removed after a failed re-verification", p)
		}
	}
	if err := encrypt.RegenerateInitrd(context.Background(), f.dev, f.dev.layout, c.Mapping, c.LUKSUUID, true); err != nil {
		t.Fatalf("retry: %v", err)
	}
}

// TestRegenerateInitrdCancelled: PDK-374 — a revocation hand-over (ctx ends) during the builds replaces no initrd and
// leaves no temporary file.
func TestRegenerateInitrdCancelled(t *testing.T) {
	f := convertedFixture(t)
	c := f.conversion()
	ctx, cancel := context.WithCancel(context.Background())
	f.dev.set(func(d *device) { d.afterDracut = func(*device) { cancel() } })
	if err := encrypt.RegenerateInitrd(ctx, f.dev, f.dev.layout, c.Mapping, c.LUKSUUID, true); !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
	if !f.dev.initrdCarriesModule(runningKernel) || !f.dev.initrdCarriesModule(olderKernel) || !f.dev.Exists(encrypt.ModuleDir) ||
		len(glob(t, f.dev.Path("/boot/.initrd.img-*"))) != 0 {
		t.Fatal("a cancelled regeneration changed the initrds or the host")
	}
}

// TestVerifyInitrdExactParts: review 4, m10 — a new initrd fails the verification with a module file but no module
// name, without systemd-cryptsetup alone, and without the TPM2 libraries alone.
func TestVerifyInitrdExactParts(t *testing.T) {
	for name, edit := range map[string]func(string) string{
		"module file": func(s string) string {
			return strings.Replace(s, "usr/sbin/cryptsetup\n", "usr/sbin/cryptsetup\n-rwxr-xr-x   1 root     root          123 Oct 21 10:00 etc/paddock/encrypt-key\n", 1)
		},
		"no systemd-cryptsetup": func(s string) string {
			return strings.Replace(s, "usr/lib/systemd/systemd-cryptsetup", "usr/lib/systemd/other", 1)
		},
		"no libtss2": func(s string) string { return strings.Replace(s, "libtss2-esys.so.0", "libother.so.0", 1) },
	} {
		f := convertedFixture(t)
		c := f.conversion()
		f.dev.set(func(d *device) {
			d.beforeFinalList = lateAt(3, func(d *device) {
				p := "/boot/initrd.img-" + runningKernel
				raw, _ := os.ReadFile(d.Path(p))
				d.Write(p, edit(string(raw)))
			})
		})
		if err := encrypt.RegenerateInitrd(context.Background(), f.dev, f.dev.layout, c.Mapping, c.LUKSUUID, true); err == nil {
			t.Fatalf("%s: passed", name)
		}
		if !f.dev.Exists(encrypt.ModuleDir) {
			t.Fatalf("%s: module removed", name)
		}
	}
}

// TestRegenerateInitrdLeftoverKernel: adversarial review round 4, minor 2 (amendment item 15) — only kernels that
// regenerate-all builds (vmlinuz and modules.dep) are rebuilt and verified: a leftover initrd and a leftover module
// directory of a removed kernel neither fail the regeneration nor the restore.
func TestRegenerateInitrdLeftoverKernel(t *testing.T) {
	f := convertedFixture(t)
	c := f.conversion()
	f.dev.Write("/boot/initrd.img-6.5.0-9-generic", "an initrd nobody can build again\n")
	f.dev.MkdirAll("/lib/modules/6.4.0-1-generic")
	_ = os.RemoveAll(f.dev.Path(encrypt.ModuleDir))
	if err := encrypt.RestoreModule(context.Background(), f.dev, f.dev.layout, module); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if err := encrypt.RegenerateInitrd(context.Background(), f.dev, f.dev.layout, c.Mapping, c.LUKSUUID, true); err != nil {
		t.Fatalf("regenerate: %v", err)
	}
	for _, l := range f.dev.Long() {
		if strings.Contains(l, "6.5.0-9") || strings.Contains(l, "6.4.0-1") {
			t.Fatalf("built a leftover kernel: %s", l)
		}
	}
}

// TestRestoreModuleUnderLock: final adversarial review, major 2 (amendment item 16) — the reinstall runs under dpkg's
// locks (busy: nothing written, retried), and a kernel added during it fails the reinstall, so that
// ModuleRestorePending stays until a pass verified every kernel.
func TestRestoreModuleUnderLock(t *testing.T) {
	f := convertedFixture(t)
	_ = os.RemoveAll(f.dev.Path(encrypt.ModuleDir))
	f.dev.PackagesBusy = true
	if err := encrypt.RestoreModule(context.Background(), f.dev, f.dev.layout, module); !errors.Is(err, encrypt.ErrPackagesBusy) ||
		f.dev.Exists(encrypt.ModuleDir) {
		t.Fatalf("reinstalled while apt held the lock: %v", err)
	}
	f.dev.PackagesBusy = false
	locked := true
	f.dev.set(func(d *device) {
		d.afterDracut = func(d *device) {
			locked = locked && d.PackagesLocked()
			d.Write("/boot/vmlinuz-6.8.0-90-generic", "kernel")
			d.Write("/lib/modules/6.8.0-90-generic/modules.dep", "")
		}
	})
	if err := encrypt.RestoreModule(context.Background(), f.dev, f.dev.layout, module); err == nil || !locked {
		t.Fatalf("a kernel added during the reinstall passed: %v, locked %v", err, locked)
	}
}

// TestPrepareInitrdUnderLock: final adversarial review, minor 4, and review 6, M1 (amendment items 16 and 17) — step 8
// rebuilds the initrds under dpkg's locks; while a package run holds them, for any number of passes, the preparation
// waits without counting a retry, and nothing is rebuilt.
func TestPrepareInitrdUnderLock(t *testing.T) {
	f := stoppedBeforePrepared(t)
	f.dev.PackagesBusy = true
	rebuilds := f.longCalls("dracut -f --regenerate-all")
	var since *time.Time
	for range encrypt.TransientRetries + 2 {
		if got := f.preparer().Prepare(context.Background()); got != encrypt.Stopped || f.longCalls("dracut -f --regenerate-all") != rebuilds ||
			f.conversion().TransientErrors != 0 || f.conversion().Phase != state.ConversionPreparing {
			t.Fatalf("outcome %v, %+v", got, f.conversion())
		}
		// The start of the wait is kept for the health (paused_reason packages_busy).
		c := f.conversion()
		if since == nil {
			since = c.PackagesBusySince
		}
		if c.PackagesBusySince == nil || !c.PackagesBusySince.Equal(*since) {
			t.Fatalf("wait not recorded once: %+v", c)
		}
		f.now = f.now.Add(time.Hour)
	}
	// Once step 8 holds the locks the wait is over, also when the pass stops before prepared.
	f.dev.PackagesBusy = false
	p := f.preparer()
	n := 0
	p.Hold = func(context.Context) error {
		if n++; n == 9 {
			return errors.New("agent stopped")
		}
		return nil
	}
	if got := p.Prepare(context.Background()); got != encrypt.Stopped || f.conversion().PackagesBusySince != nil {
		t.Fatalf("wait not ended with the lock: %v %+v", got, f.conversion())
	}
	locked := true
	f.dev.set(func(d *device) { d.afterDracut = func(d *device) { locked = locked && d.PackagesLocked() } })
	if got := f.preparer().Prepare(context.Background()); got != encrypt.Prepared || !locked || f.conversion().PackagesBusySince != nil {
		t.Fatalf("outcome %v, locked %v, %+v", got, locked, f.conversion())
	}
}

// TestRegenerateInitrdCancelledBeforeRenames: review 6, M2 (c) — a hand-over (ctx ends) after a build was verified,
// before its rename, replaces no initrd.
func TestRegenerateInitrdCancelledBeforeRenames(t *testing.T) {
	f := convertedFixture(t)
	c := f.conversion()
	ctx, cancel := context.WithCancel(context.Background())
	n := 0
	f.dev.set(func(d *device) {
		d.onTempCrypttab = func() {
			if n++; n == 1 {
				cancel()
			}
		}
	})
	if err := encrypt.RegenerateInitrd(ctx, f.dev, f.dev.layout, c.Mapping, c.LUKSUUID, true); !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
	if !f.dev.initrdCarriesModule(runningKernel) || !f.dev.initrdCarriesModule(olderKernel) || !f.dev.Exists(encrypt.ModuleDir) ||
		len(glob(t, f.dev.Path("/boot/.initrd.img-*"))) != 0 {
		t.Fatal("a regeneration cancelled before the renames changed the initrds or the host")
	}
}

// TestBootableKernelsDepBin: amendment item 19(k) — a kernel whose module directory has only modules.dep.bin is
// bootable, not buildable: the regeneration, the cleanup and the reinstall build nothing and report it with its
// version, its initrd stays, and the orphan rule never removes it.
func TestBootableKernelsDepBin(t *testing.T) {
	const v = "6.8.0-91-generic"
	for _, job := range []string{"regeneration", "cleanup", "reinstall"} {
		var f *fixture
		if job == "cleanup" {
			f = preparedFixture(t)
		} else {
			f = convertedFixture(t)
		}
		if job == "reinstall" {
			_ = os.RemoveAll(f.dev.Path(encrypt.ModuleDir))
		}
		c := f.conversion()
		f.dev.Write("/lib/modules/"+v+"/modules.dep.bin", "")
		f.dev.Write("/boot/vmlinuz-"+v, "kernel")
		f.dev.buildInitrd("/boot/initrd.img-"+v, v, true)
		before, calls := f.read("/boot/initrd.img-"+v), len(f.dev.Long())
		var err error
		switch job {
		case "regeneration":
			err = encrypt.RegenerateInitrd(context.Background(), f.dev, f.dev.layout, c.Mapping, c.LUKSUUID, true)
		case "cleanup":
			_, _, err = encrypt.Cleanup(context.Background(), f.dev, f.dev.layout, true)
		default:
			err = encrypt.RestoreModule(context.Background(), f.dev, f.dev.layout, module)
		}
		var nb *encrypt.KernelNotBuildableError
		if !errors.As(err, &nb) || nb.Version != v || f.read("/boot/initrd.img-"+v) != before || len(f.dev.Long()) != calls {
			t.Fatalf("%s: %v, calls %v", job, err, f.dev.Long()[calls:])
		}
	}
}

// TestRebuildKilledLeavesInitrds: amendment item 18 — the cleanup's and the reinstall's rebuilds go through temporary
// files: a build that fails (or is killed) halfway replaces no initrd and leaves no temporary file.
func TestRebuildKilledLeavesInitrds(t *testing.T) {
	for _, job := range []string{"cleanup", "reinstall"} {
		var f *fixture
		if job == "cleanup" {
			f = preparedFixture(t)
		} else {
			f = convertedFixture(t)
			_ = os.RemoveAll(f.dev.Path(encrypt.ModuleDir))
		}
		before, calls := f.read("/boot/initrd.img-"+runningKernel), len(f.dev.Long())
		n := 0
		f.dev.set(func(d *device) {
			d.afterDracut = func(d *device) {
				if n++; n == 2 {
					d.dracutExit = 1
				}
			}
		})
		var err error
		if job == "cleanup" {
			_, _, err = encrypt.Cleanup(context.Background(), f.dev, f.dev.layout, true)
		} else {
			err = encrypt.RestoreModule(context.Background(), f.dev, f.dev.layout, module)
		}
		if err == nil || f.read("/boot/initrd.img-"+runningKernel) != before || len(glob(t, f.dev.Path("/boot/.initrd.img-*"))) != 0 {
			t.Fatalf("%s: a failed rebuild changed an initrd or left a temporary file: %v", job, err)
		}
		for _, l := range f.dev.Long()[calls:] {
			if strings.HasPrefix(l, "dracut -f --regenerate-all") {
				t.Fatalf("%s rebuilt in place", job)
			}
		}
	}
}

// TestRemoveStaleTempsOnlyLocksWithFiles: PDK-375 nit — without a leftover temporary initrd the start takes no dpkg
// lock (a busy lock is then no error).
func TestRemoveStaleTempsOnlyLocksWithFiles(t *testing.T) {
	f := convertedFixture(t)
	f.dev.PackagesBusy = true
	if err := encrypt.RemoveStaleTemps(f.dev, f.dev.layout); err != nil {
		t.Fatalf("locked without a temporary file: %v", err)
	}
	f.dev.Write("/boot/.initrd.img-"+runningKernel+".paddock", "half built")
	if err := encrypt.RemoveStaleTemps(f.dev, f.dev.layout); !errors.Is(err, encrypt.ErrPackagesBusy) {
		t.Fatalf("with a temporary file: %v", err)
	}
}

// lateAt runs hook at the n-th listing of an initrd in place: the kernels are replaced one after the other, each
// verified after its rename (calls 1 and 2 for the two kernels), then all are verified again before the module leaves
// the host (from call 3 on).
func lateAt(n int, hook func(d *device)) func(d *device) {
	calls := 0
	var arm func(d *device)
	arm = func(d *device) {
		if calls++; calls == n {
			hook(d)
			return
		}
		d.beforeFinalList = arm
	}
	return arm
}

// initrdContents are the current initrds by kernel, to compare byte for byte.
func initrdContents(f *fixture) map[string]string {
	out := map[string]string{}
	for _, v := range []string{runningKernel, olderKernel} {
		out[v] = f.read("/boot/initrd.img-" + v)
	}
	return out
}

// TestBootSpaceLow: PDK-380 (amendment item 19) — with too little room in /boot no initrd is built: the regeneration,
// the cleanup and the reinstall report the bytes needed and free, and every current initrd stays byte for byte.
func TestBootSpaceLow(t *testing.T) {
	for _, job := range []string{"regeneration", "cleanup", "reinstall"} {
		var f *fixture
		if job == "cleanup" {
			f = preparedFixture(t)
		} else {
			f = convertedFixture(t)
		}
		if job == "reinstall" {
			_ = os.RemoveAll(f.dev.Path(encrypt.ModuleDir))
		}
		c := f.conversion()
		before, calls := initrdContents(f), len(f.dev.Long())
		f.dev.Free = 1 << 20
		var err error
		switch job {
		case "regeneration":
			err = encrypt.RegenerateInitrd(context.Background(), f.dev, f.dev.layout, c.Mapping, c.LUKSUUID, true)
		case "cleanup":
			_, _, err = encrypt.Cleanup(context.Background(), f.dev, f.dev.layout, true)
		default:
			err = encrypt.RestoreModule(context.Background(), f.dev, f.dev.layout, module)
		}
		var space *encrypt.BootSpaceError
		if !errors.As(err, &space) || space.Free != 1<<20 || space.Needed < 32<<20 {
			t.Fatalf("%s: err %v", job, err)
		}
		for _, l := range f.dev.Long()[calls:] {
			if strings.HasPrefix(l, "dracut") {
				t.Fatalf("%s: built with too little room: %s", job, l)
			}
		}
		if got := initrdContents(f); !maps.Equal(got, before) {
			t.Fatalf("%s: an initrd changed", job)
		}
	}
}

// TestBootSpaceRunsOutDuringBuild: PDK-380 — dracut running out of space removes its temporary file, leaves the
// current initrd, reports boot space, and the retry with room succeeds.
func TestBootSpaceRunsOutDuringBuild(t *testing.T) {
	f := convertedFixture(t)
	c := f.conversion()
	before := initrdContents(f)
	f.dev.set(func(d *device) {
		d.afterDracut = func(d *device) {
			d.Write(tempPath(runningKernel), "half written")
			d.Write(tempPath(olderKernel), "half written")
			d.dracutExit = 1
		}
	})
	f.dev.Stderr = func(line string) string { return "dracut: cp: error writing: No space left on device\n" }
	var space *encrypt.BootSpaceError
	if err := encrypt.RegenerateInitrd(context.Background(), f.dev, f.dev.layout, c.Mapping, c.LUKSUUID, true); !errors.As(err, &space) {
		t.Fatalf("err %v", err)
	}
	if len(glob(t, f.dev.Path("/boot/.initrd.img-*"))) > 1 || !maps.Equal(initrdContents(f), before) {
		t.Fatal("a failed build changed an initrd")
	}
	if err := encrypt.RemoveStaleTemps(f.dev, f.dev.layout); err != nil || len(glob(t, f.dev.Path("/boot/.initrd.img-*"))) != 0 {
		t.Fatalf("temporary files after the start: %v", err)
	}
	f.dev.set(func(d *device) { d.afterDracut, d.dracutExit = nil, 0 })
	if err := encrypt.RegenerateInitrd(context.Background(), f.dev, f.dev.layout, c.Mapping, c.LUKSUUID, true); err != nil {
		t.Fatalf("retry: %v", err)
	}
}

func tempPath(v string) string { return "/boot/.initrd.img-" + v + ".paddock" }

// TestOneTemporaryInitrdAtATime: PDK-380 — with several kernels at most one temporary initrd exists at any moment, in
// the regeneration, the cleanup and the reinstall; each rebuilt initrd is readable by root only.
func TestOneTemporaryInitrdAtATime(t *testing.T) {
	for _, job := range []string{"regeneration", "cleanup", "reinstall"} {
		var f *fixture
		if job == "cleanup" {
			f = preparedFixture(t)
		} else {
			f = convertedFixture(t)
		}
		if job == "reinstall" {
			_ = os.RemoveAll(f.dev.Path(encrypt.ModuleDir))
		}
		const third = "6.8.0-91-generic"
		f.dev.Write("/boot/vmlinuz-"+third, "kernel")
		f.dev.Write("/lib/modules/"+third+"/modules.dep", "")
		most := 0
		f.dev.set(func(d *device) {
			d.afterDracut = func(d *device) { most = max(most, len(glob(t, d.Path("/boot/.initrd.img-*")))) }
		})
		c := f.conversion()
		var err error
		switch job {
		case "regeneration":
			err = encrypt.RegenerateInitrd(context.Background(), f.dev, f.dev.layout, c.Mapping, c.LUKSUUID, true)
		case "cleanup":
			_, _, err = encrypt.Cleanup(context.Background(), f.dev, f.dev.layout, true)
		default:
			err = encrypt.RestoreModule(context.Background(), f.dev, f.dev.layout, module)
		}
		if err != nil || most > 0 {
			// afterDracut runs before the fake writes the build's own file: any temporary file then is a second one.
			t.Fatalf("%s: err %v, temporary files beside a build: %d", job, err, most)
		}
		for _, v := range []string{runningKernel, olderKernel, third} {
			if f.mode("/boot/initrd.img-"+v) != 0o600 {
				t.Fatalf("%s: initrd %s readable by others", job, v)
			}
		}
	}
}

// TestCleanupVerifiesRebuiltInitrd: PDK-381 — the cleanup's rebuild is verified before it replaces anything: a new
// initrd that still carries the module is discarded, and the current one stays byte for byte.
func TestCleanupVerifiesRebuiltInitrd(t *testing.T) {
	f := preparedFixture(t)
	f.dev.set(func(d *device) { d.stale = true })
	before := f.read("/boot/initrd.img-" + olderKernel)
	if done, _, err := encrypt.Cleanup(context.Background(), f.dev, f.dev.layout, true); done || err == nil {
		t.Fatalf("cleanup %v %v", done, err)
	}
	if f.read("/boot/initrd.img-"+olderKernel) != before || len(glob(t, f.dev.Path("/boot/.initrd.img-*"))) != 0 {
		t.Fatal("an unverified initrd replaced the current one")
	}
}

// TestCleanupNoBootableKernel: PDK-381 — without a kernel dracut would build, the cleanup reports no_bootable_kernel
// and stays pending: the key and the plan stay.
func TestCleanupNoBootableKernel(t *testing.T) {
	f := preparedFixture(t)
	for _, v := range []string{runningKernel, olderKernel} {
		_ = os.Remove(f.dev.Path("/lib/modules/" + v + "/modules.dep"))
	}
	if done, _, err := encrypt.Cleanup(context.Background(), f.dev, f.dev.layout, true); done || !errors.Is(err, encrypt.ErrNoBootableKernel) ||
		!f.dev.Exists("/var/lib/paddock/install-passphrase") {
		t.Fatalf("cleanup %v %v", done, err)
	}
}

// TestPrepareStep8BootSpaceLow: amendment item 19(h) — step 8 builds through temporary files with the room in /boot
// checked: too little room builds nothing, keeps every initrd byte for byte, reports boot_space_low and waits without
// counting a retry; with room the preparation reaches prepared and the issue is gone.
func TestPrepareStep8BootSpaceLow(t *testing.T) {
	f := newFixture(t)
	p := f.preparer()
	n := 0
	p.Hold = func(context.Context) error {
		if n++; n == 8 {
			f.dev.Free = 1 << 20
		}
		return nil
	}
	before := initrdContents(f)
	if got := p.Prepare(context.Background()); got != encrypt.Stopped {
		t.Fatalf("outcome %v", got)
	}
	c := f.conversion()
	if c.Phase != state.ConversionPreparing || c.InitrdIssue != encrypt.IssueBootSpaceLow || c.BootSpaceFree != 1<<20 ||
		c.TransientErrors != 0 || f.longCalls("dracut -f") != 0 || !maps.Equal(initrdContents(f), before) {
		t.Fatalf("conversion %+v, calls %v", c, f.dev.Long())
	}
	f.dev.Free = 0
	if got := f.preparer().Prepare(context.Background()); got != encrypt.Prepared || f.conversion().InitrdIssue != "" {
		t.Fatalf("with room: %v %+v", got, f.conversion())
	}
}

// TestNoInPlaceRegeneration: amendment item 19(h) — no Paddock path runs dracut --regenerate-all (in place) any more.
func TestNoInPlaceRegeneration(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	more, _ := filepath.Glob("../agent/*.go")
	for _, f := range append(files, more...) {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(f) //nolint:gosec // the package's own sources
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), `"--regenerate-all"`) {
			t.Fatalf("%s runs dracut --regenerate-all", f)
		}
	}
}

// TestUnifiedKernelImageRejected: amendment item 19 — a build that came out as a unified kernel image (a host with
// uefi=yes, should --no-uefi not take) is rejected: the temporary file goes and the current initrd stays.
func TestUnifiedKernelImageRejected(t *testing.T) {
	for _, job := range []string{"regeneration", "cleanup"} {
		var f *fixture
		if job == "cleanup" {
			f = preparedFixture(t)
		} else {
			f = convertedFixture(t)
		}
		c := f.conversion()
		before := initrdContents(f)
		f.dev.set(func(d *device) { d.pe = true })
		var err error
		if job == "cleanup" {
			_, _, err = encrypt.Cleanup(context.Background(), f.dev, f.dev.layout, true)
		} else {
			err = encrypt.RegenerateInitrd(context.Background(), f.dev, f.dev.layout, c.Mapping, c.LUKSUUID, true)
		}
		if err == nil || !strings.Contains(err.Error(), "unified kernel image") || !maps.Equal(initrdContents(f), before) ||
			len(glob(t, f.dev.Path("/boot/.initrd.img-*"))) != 0 {
			t.Fatalf("%s: %v", job, err)
		}
	}
}

// TestCleanupRemovesStaleTemps: amendment item 19 — a temporary initrd a killed reinstall left, of a kernel removed
// since (so no build replaces it), carries the key: the cleanup removes it and finishes only without one.
func TestCleanupRemovesStaleTemps(t *testing.T) {
	f := preparedFixture(t)
	f.dev.Write(tempPath("6.5.0-9-generic"), "a key-carrying temporary initrd")
	if done, _, err := encrypt.Cleanup(context.Background(), f.dev, f.dev.layout, true); !done || err != nil {
		t.Fatalf("cleanup %v %v", done, err)
	}
	if len(glob(t, f.dev.Path("/boot/.initrd.img-*"))) != 0 {
		t.Fatal("a temporary initrd outlived the cleanup")
	}
}

// TestCleanupOrphanInitrds: amendment item 19(g) — the initrd of a kernel without modules.dep (it can neither boot nor
// be rebuilt) that carries the module is removed by the cleanup, which then finishes; one without the module stays, and
// a bootable kernel's initrd is never removed.
func TestCleanupOrphanInitrds(t *testing.T) {
	const orphan, plain = "6.5.0-9-generic", "6.4.0-1-generic"
	f := preparedFixture(t)
	f.dev.Write("/boot/vmlinuz-"+orphan, "kernel")
	f.dev.buildInitrd("/boot/initrd.img-"+orphan, orphan, true)
	f.dev.Write("/boot/vmlinuz-"+plain, "kernel")
	f.dev.Write("/boot/initrd.img-"+plain, "an initrd without the module\n")
	done, orphans, err := encrypt.Cleanup(context.Background(), f.dev, f.dev.layout, true)
	if !done || err != nil || !slices.Equal(orphans, []string{orphan}) {
		t.Fatalf("cleanup %v %v %v", done, orphans, err)
	}
	if f.dev.Exists("/boot/initrd.img-"+orphan) || f.read("/boot/initrd.img-"+plain) != "an initrd without the module\n" ||
		!f.dev.Exists("/boot/initrd.img-"+runningKernel) || !f.dev.Exists("/boot/initrd.img-"+olderKernel) {
		t.Fatal("wrong initrds removed")
	}
	_, _ = encrypt.RunCleanup(context.Background(), f.dev, f.dev.layout, f.store)
}

// TestBuildRemovesOwnStaleTemp: review 9, m7 — a kernel's own temporary file a kill left is removed before the room is
// measured, so it does not count against it.
func TestBuildRemovesOwnStaleTemp(t *testing.T) {
	f := convertedFixture(t)
	c := f.conversion()
	f.dev.Write(tempPath(olderKernel), strings.Repeat("x", 1<<20))
	f.dev.FreeFunc = func(string) int64 {
		free := int64(32<<20 + 512<<10)
		for _, p := range glob(t, f.dev.Path("/boot/.initrd.img-*")) {
			if info, err := os.Stat(p); err == nil {
				free -= info.Size()
			}
		}
		return free
	}
	if err := encrypt.RegenerateInitrd(context.Background(), f.dev, f.dev.layout, c.Mapping, c.LUKSUUID, true); err != nil {
		t.Fatalf("the own stale temporary file counted against the room: %v", err)
	}
}

// TestReplaceKeepsInitrdChangedDuringItsBuild: review 9, M5 (a) — a kernel package writing kernel v's current initrd
// during v's own build keeps that initrd: the new one is not renamed over it, and the module stays on the host.
func TestReplaceKeepsInitrdChangedDuringItsBuild(t *testing.T) {
	f := convertedFixture(t)
	c := f.conversion()
	n := 0
	f.dev.set(func(d *device) {
		d.afterDracut = func(d *device) {
			if n++; n == 1 {
				d.Write("/boot/initrd.img-"+olderKernel, "a package's rebuild\n")
			}
		}
	})
	if err := encrypt.RegenerateInitrd(context.Background(), f.dev, f.dev.layout, c.Mapping, c.LUKSUUID, true); err == nil ||
		f.read("/boot/initrd.img-"+olderKernel) != "a package's rebuild\n" || !f.dev.Exists(encrypt.ModuleDir) {
		t.Fatalf("replaced an initrd written during its build: %v", err)
	}
}

// TestRegenerateNoBootableKernel: review 9, M5 (b).
func TestRegenerateNoBootableKernel(t *testing.T) {
	f := convertedFixture(t)
	c := f.conversion()
	for _, v := range []string{runningKernel, olderKernel} {
		_ = os.Remove(f.dev.Path("/lib/modules/" + v + "/modules.dep"))
	}
	if err := encrypt.RegenerateInitrd(context.Background(), f.dev, f.dev.layout, c.Mapping, c.LUKSUUID, true); !errors.Is(err,
		encrypt.ErrNoBootableKernel) {
		t.Fatalf("err %v", err)
	}
}

// TestBootSpaceBoundary: review 9, M5 (c) — a new initrd needs 1.5 times the current one plus 32 MiB: 1.0 times plus
// 32 MiB is too little, exactly the rule fits; a kernel without an initrd is measured against the largest one.
func TestBootSpaceBoundary(t *testing.T) {
	const size = 10 << 20
	need := int64(size + size/2 + 32<<20)
	for name, tc := range map[string]struct {
		free    int64
		without bool
		low     bool
	}{
		"1.0 times":          {free: size + 32<<20, low: true},
		"just below":         {free: need - 1, low: true},
		"exactly":            {free: need},
		"no initrd, largest": {free: need - 1, without: true, low: true},
	} {
		f := convertedFixture(t)
		c := f.conversion()
		for _, v := range []string{runningKernel, olderKernel} {
			f.dev.Write("/boot/initrd.img-"+v, strings.Repeat("i", size))
		}
		if tc.without {
			_ = os.Remove(f.dev.Path("/boot/initrd.img-" + olderKernel))
		}
		f.dev.Free = tc.free
		calls := len(f.dev.Long())
		err := encrypt.RegenerateInitrd(context.Background(), f.dev, f.dev.layout, c.Mapping, c.LUKSUUID, true)
		var space *encrypt.BootSpaceError
		if low := errors.As(err, &space); low != tc.low || (low && space.Needed != need) {
			t.Fatalf("%s: %v", name, err)
		}
		// Too little room for the first kernel (the older one, without an initrd in the last case) builds nothing.
		if tc.low && len(f.dev.Long()) != calls {
			t.Fatalf("%s: built %v", name, f.dev.Long()[calls:])
		}
	}
}

// TestPackagesBusySinceEndsAtPreparedAndFailure: review 9, M5 (d) — also when step 8 could not record the end of the
// wait (its save failed), prepared and a failure end it.
func TestPackagesBusySinceEndsAtPreparedAndFailure(t *testing.T) {
	for _, outcome := range []encrypt.Outcome{encrypt.Prepared, encrypt.Failed} {
		f := stoppedBeforePrepared(t)
		since := f.now
		_ = f.store.Update(func(c *state.DiskConversion, _ *state.LUKS) { c.PackagesBusySince = &since })
		failed := false
		f.store.saveErr = func(c *state.DiskConversion) error {
			if !failed && c.PackagesBusySince != nil {
				failed = true
				return errors.New("disk full")
			}
			return nil
		}
		if outcome == encrypt.Failed {
			f.dev.set(func(d *device) { d.incomplete = true })
		}
		if got := f.preparer().Prepare(context.Background()); got != outcome || !failed || f.conversion().PackagesBusySince != nil {
			t.Fatalf("%v: outcome %v, %+v", outcome, got, f.conversion())
		}
	}
}

// TestStaleTempsRemovedByEveryRebuild: the reinstall's rebuild and a cleanup that rebuilds nothing (dracut gone) each
// remove a temporary initrd left by a killed run of a kernel removed since.
func TestStaleTempsRemovedByEveryRebuild(t *testing.T) {
	f := convertedFixture(t)
	_ = os.RemoveAll(f.dev.Path(encrypt.ModuleDir))
	f.dev.Write(tempPath("6.5.0-9-generic"), "a key-carrying temporary initrd")
	if err := encrypt.RestoreModule(context.Background(), f.dev, f.dev.layout, module); err != nil ||
		len(glob(t, f.dev.Path("/boot/.initrd.img-*"))) != 0 {
		t.Fatalf("reinstall: %v", err)
	}

	f = preparedFixture(t)
	f.dev.set(func(d *device) { d.packages["dracut"] = "config-files" })
	f.dev.buildInitrds()
	_ = os.Remove(f.dev.Path(encrypt.ModuleConf))
	_ = os.RemoveAll(f.dev.Path(encrypt.ModuleDir))
	f.dev.buildInitrds()
	f.dev.Write(tempPath("6.5.0-9-generic"), "a key-carrying temporary initrd")
	if done, _, err := encrypt.Cleanup(context.Background(), f.dev, f.dev.layout, true); !done || err != nil ||
		len(glob(t, f.dev.Path("/boot/.initrd.img-*"))) != 0 {
		t.Fatalf("cleanup without dracut: %v %v", done, err)
	}
}

// TestCleanupStrayInitrds: amendment item 19(i) — an initrd of a kernel removed with its vmlinuz and modules (only
// /boot/initrd.img-<v> is left) is found: with the module it is removed, without it stays; a symlink is never followed.
func TestCleanupStrayInitrds(t *testing.T) {
	const stray, plain, link = "6.2.0-1-generic", "6.1.0-1-generic", "6.0.0-1-generic"
	f := preparedFixture(t)
	f.dev.buildInitrd("/boot/initrd.img-"+stray, stray, true)
	f.dev.Write("/boot/initrd.img-"+plain, "an initrd without the module\n")
	if err := os.Symlink(f.dev.Path("/boot/initrd.img-"+runningKernel), f.dev.Path("/boot/initrd.img-"+link)); err != nil {
		t.Fatal(err)
	}
	done, orphans, err := encrypt.Cleanup(context.Background(), f.dev, f.dev.layout, true)
	if !done || err != nil || !slices.Equal(orphans, []string{stray}) {
		t.Fatalf("cleanup %v %v %v", done, orphans, err)
	}
	if f.dev.Exists("/boot/initrd.img-"+stray) || f.read("/boot/initrd.img-"+plain) != "an initrd without the module\n" {
		t.Fatal("wrong stray initrds handled")
	}
	if info, err := os.Lstat(f.dev.Path("/boot/initrd.img-" + link)); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the symlink was touched")
	}
}

// TestRegenerateRemovesStaleTemps: amendment item 19(j) — the regeneration removes a temporary initrd of a kernel
// removed since (it would carry the key).
func TestRegenerateRemovesStaleTemps(t *testing.T) {
	f := convertedFixture(t)
	c := f.conversion()
	f.dev.Write(tempPath("6.5.0-9-generic"), "a key-carrying temporary initrd")
	if err := encrypt.RegenerateInitrd(context.Background(), f.dev, f.dev.layout, c.Mapping, c.LUKSUUID, true); err != nil ||
		len(glob(t, f.dev.Path("/boot/.initrd.img-*"))) != 0 {
		t.Fatalf("regeneration: %v", err)
	}
}

// TestCleanupNeverFollowsInitrdSymlinks: amendment item 19(i) — an initrd.img-<v> that is a symlink is no initrd of
// its own: a symlink without a kernel is not looked at, and one of a kernel without modules is never shredded through
// (its target stays; the cleanup does not finish while it carries the module).
func TestCleanupNeverFollowsInitrdSymlinks(t *testing.T) {
	for _, withKernel := range []bool{false, true} {
		f := preparedFixture(t)
		target := f.dev.Path("/var/tmp/initrd-elsewhere")
		f.dev.buildInitrd("/var/tmp/initrd-elsewhere", "6.0.0-1-generic", true)
		before := f.read("/var/tmp/initrd-elsewhere")
		if err := os.Symlink(target, f.dev.Path("/boot/initrd.img-6.0.0-1-generic")); err != nil {
			t.Fatal(err)
		}
		if withKernel {
			f.dev.Write("/boot/vmlinuz-6.0.0-1-generic", "kernel")
		}
		done, orphans, _ := encrypt.Cleanup(context.Background(), f.dev, f.dev.layout, true)
		if f.read("/var/tmp/initrd-elsewhere") != before || len(orphans) != 0 || done != !withKernel {
			t.Fatalf("kernel %v: done %v, orphans %v", withKernel, done, orphans)
		}
	}
}

// TestRegenerateFailedRemovesStaleTemps: amendment item 19(j) — the regeneration removes temporary files of removed
// kernels at its start, also when it fails afterwards.
func TestRegenerateFailedRemovesStaleTemps(t *testing.T) {
	f := convertedFixture(t)
	c := f.conversion()
	f.dev.Write(tempPath("6.5.0-9-generic"), "a key-carrying temporary initrd")
	f.dev.set(func(d *device) { d.dracutExit = 1 })
	if err := encrypt.RegenerateInitrd(context.Background(), f.dev, f.dev.layout, c.Mapping, c.LUKSUUID, true); err == nil ||
		len(glob(t, f.dev.Path("/boot/.initrd.img-*"))) != 0 {
		t.Fatalf("regeneration: %v", err)
	}
}

// TestPrepareStep8KernelNotBuildable: amendment item 19(k) — step 8 waits (no retry counted) while a bootable kernel
// cannot be built, and reports it with the version.
func TestPrepareStep8KernelNotBuildable(t *testing.T) {
	f := newFixture(t)
	f.dev.Write("/lib/modules/6.8.0-91-generic/modules.dep.bin", "")
	if got := f.preparer().Prepare(context.Background()); got != encrypt.Stopped {
		t.Fatalf("outcome %v", got)
	}
	if c := f.conversion(); c.TransientErrors != 0 || c.InitrdIssue != encrypt.IssueKernelNotBuildable || c.InitrdIssueKernel != "6.8.0-91-generic" {
		t.Fatalf("conversion %+v", c)
	}
}

// TestCleanupUnreadableStray: amendment item 19(i) — an unreadable initrd of no kernel (a remnant, a truncated build)
// is an orphan: removed, and the cleanup finishes; an unreadable initrd of a bootable kernel stays and is an error.
func TestCleanupUnreadableStray(t *testing.T) {
	f := preparedFixture(t)
	f.dev.Write("/boot/initrd.img-6.2.0-1-generic", "TRUNCATED")
	done, orphans, err := encrypt.Cleanup(context.Background(), f.dev, f.dev.layout, true)
	if !done || err != nil || !slices.Equal(orphans, []string{"6.2.0-1-generic"}) || f.dev.Exists("/boot/initrd.img-6.2.0-1-generic") {
		t.Fatalf("stray: %v %v %v", done, orphans, err)
	}

	f = preparedFixture(t)
	f.dev.set(func(d *device) { d.packages["dracut"] = "config-files" })
	f.dev.Write("/boot/initrd.img-"+olderKernel, "TRUNCATED")
	done, _, err = encrypt.Cleanup(context.Background(), f.dev, f.dev.layout, true)
	// The listing error itself, not a stray treatment of a bootable kernel's initrd.
	if done || err == nil || !strings.Contains(err.Error(), "exit 1") || f.read("/boot/initrd.img-"+olderKernel) != "TRUNCATED" {
		t.Fatalf("bootable: %v %v", done, err)
	}
}

// TestCleanupHardLinkedOrphan: review 10, M7 — an orphan initrd that is a hard link to a bootable kernel's initrd is
// only unlinked: the bootable kernel's initrd stays byte for byte; a single-link orphan is overwritten before it goes.
func TestCleanupHardLinkedOrphan(t *testing.T) {
	f := preparedFixture(t)
	f.dev.set(func(d *device) { d.packages["dracut"] = "config-files" })
	before := f.read("/boot/initrd.img-" + runningKernel)
	if err := os.Link(f.dev.Path("/boot/initrd.img-"+runningKernel), f.dev.Path("/boot/initrd.img-6.2.0-1-generic")); err != nil {
		t.Fatal(err)
	}
	_, orphans, _ := encrypt.Cleanup(context.Background(), f.dev, f.dev.layout, true)
	if !slices.Contains(orphans, "6.2.0-1-generic") || f.dev.Exists("/boot/initrd.img-6.2.0-1-generic") ||
		f.read("/boot/initrd.img-"+runningKernel) != before {
		t.Fatalf("hard link: orphans %v", orphans)
	}

	f = preparedFixture(t)
	f.dev.buildInitrd("/boot/initrd.img-6.2.0-1-generic", "6.2.0-1-generic", true)
	held, err := os.Open(f.dev.Path("/boot/initrd.img-6.2.0-1-generic"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	if _, orphans, _ := encrypt.Cleanup(context.Background(), f.dev, f.dev.layout, true); !slices.Contains(orphans, "6.2.0-1-generic") {
		t.Fatalf("orphans %v", orphans)
	}
	raw, _ := io.ReadAll(held)
	if strings.Trim(string(raw), "\x00") != "" {
		t.Fatal("a single-link orphan was not overwritten")
	}
}

// TestPrepareWaitsKeepFieldsApart: review 10, M6 and PDK-382 — waiting for room in /boot or for a buildable kernel is
// no wait for dpkg's locks (no packages_busy, no flapping start), and each issue replaces every field of the other.
func TestPrepareWaitsKeepFieldsApart(t *testing.T) {
	f := newFixture(t)
	f.dev.Free = 1 << 20
	for range 2 {
		if got := f.preparer().Prepare(context.Background()); got != encrypt.Stopped {
			t.Fatalf("outcome %v", got)
		}
		if c := f.conversion(); c.PackagesBusySince != nil || c.InitrdIssue != encrypt.IssueBootSpaceLow || c.InitrdIssueKernel != "" ||
			c.TransientErrors != 0 {
			t.Fatalf("boot space: %+v", c)
		}
	}
	f.dev.Free = 0
	f.dev.Write("/lib/modules/6.8.0-91-generic/modules.dep.bin", "")
	if got := f.preparer().Prepare(context.Background()); got != encrypt.Stopped {
		t.Fatalf("outcome %v", got)
	}
	if c := f.conversion(); c.PackagesBusySince != nil || c.InitrdIssue != encrypt.IssueKernelNotBuildable || c.BootSpaceNeeded != 0 ||
		c.BootSpaceFree != 0 || c.InitrdIssueKernel != "6.8.0-91-generic" {
		t.Fatalf("not buildable after boot space: %+v", c)
	}
	_ = os.Remove(f.dev.Path("/lib/modules/6.8.0-91-generic/modules.dep.bin"))
	f.dev.Free = 1 << 20
	if got := f.preparer().Prepare(context.Background()); got != encrypt.Stopped {
		t.Fatalf("outcome %v", got)
	}
	if c := f.conversion(); c.InitrdIssue != encrypt.IssueBootSpaceLow || c.InitrdIssueKernel != "" {
		t.Fatalf("boot space after not buildable: %+v", c)
	}
}
