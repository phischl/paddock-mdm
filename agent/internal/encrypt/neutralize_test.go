package encrypt_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/encrypt"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// TestInitScriptNeutralizedPlan: PDK-482 — the override segment unpacked over a prepared initrd's root (the kernel
// replaces a file a later archive names again) makes the init step report plan_invalid before it touches the disk.
func TestInitScriptNeutralizedPlan(t *testing.T) {
	cpio, err := exec.LookPath("cpio")
	if err != nil {
		t.Skip("cpio is not installed")
	}
	for _, plan := range []func() encrypt.Plan{lvmPlan, plainPlan} {
		eachShell(t, plan, func(b *boot) {
			unpack := exec.Command(cpio, "-i", "-d", "-u", "--quiet", "--no-preserve-owner", "-D", b.root) //nolint:gosec // the test's own tool
			unpack.Stdin = bytes.NewReader(encrypt.NeutralizeSegment)
			if out, err := unpack.CombinedOutput(); err != nil {
				t.Fatalf("cpio: %v %s", err, out)
			}
			b.run()
			b.wantResult("failed", "init", "plan_invalid")
			b.never("udevadm", "cryptsetup", "lvm", "e2fsck", "resize2fs", "blkid")
		})
	}
}

// neutralized reports whether a kernel's initrd is the original, zeros up to a multiple of 4 and the override segment.
func neutralized(t *testing.T, f *fixture, v, original string) bool {
	t.Helper()
	pad := strings.Repeat("\x00", (4-len(original)%4)%4)
	return f.read("/boot/initrd.img-"+v) == original+pad+string(encrypt.NeutralizeSegment)
}

// TestAbortNeutralizesInitrds: PDK-482 (plan M8e item 18, amendment 2026-10-30) — an abort whose cleanup cannot
// rebuild the initrds leaves each prepared initrd neutralized: its content unchanged, followed by the override segment,
// written through a temporary file that is gone afterwards. A second neutralization appends nothing. The cleanup of the
// neutralized initrds then completes normally.
func TestAbortNeutralizesInitrds(t *testing.T) {
	f := preparedFixture(t)
	originals := map[string]string{}
	for _, v := range []string{runningKernel, olderKernel} {
		originals[v] = f.read("/boot/initrd.img-" + v)
	}
	f.dev.set(func(d *device) { d.dracutExit = 1 })
	if aborted, _ := encrypt.Abort(context.Background(), f.dev, f.dev.layout, f.store, conversionID, encrypt.ByAdmin, false, nil); !aborted {
		t.Fatal("not aborted")
	}
	for v, original := range originals {
		if !neutralized(t, f, v, original) {
			t.Fatalf("the initrd of %s is not neutralized", v)
		}
		if f.mode("/boot/initrd.img-"+v) != 0o600 {
			t.Errorf("the initrd of %s has mode %v", v, f.mode("/boot/initrd.img-"+v))
		}
	}
	if temps := glob(t, f.dev.Path("/boot/.initrd.img-*")); len(temps) != 0 {
		t.Fatalf("temporary files left: %v", temps)
	}
	if ev := f.store.events; len(ev) != 1 || ev[0].typ != protocol.EventDiskConversionAborted {
		t.Fatalf("events %+v", ev)
	}
	once := f.read("/boot/initrd.img-" + runningKernel)
	if err := encrypt.NeutralizeInitrds(context.Background(), f.dev, f.dev.layout); err != nil || f.read("/boot/initrd.img-"+runningKernel) != once {
		t.Fatalf("a second neutralization changed the initrd: %v", err)
	}
	f.dev.set(func(d *device) { d.dracutExit = 0 })
	if done, err := encrypt.RunCleanup(context.Background(), f.dev, f.dev.layout, f.store); !done || err != nil {
		t.Fatalf("cleanup %v %v", done, err)
	}
	for v := range originals {
		if f.dev.initrdCarriesModule(v) || strings.Contains(f.read("/boot/initrd.img-"+v), "PADDOCK_LAYOUT=cancelled") {
			t.Fatalf("the initrd of %s still carries the module or the override", v)
		}
	}
	if c := f.conversion(); c.Phase != state.ConversionCancelled || c.CleanupPending || f.dev.Exists("/var/lib/paddock/install-passphrase") {
		t.Fatalf("conversion %+v", c)
	}
}

// TestAbortNeutralizesLinkedInitrd: rule B (0) of plan M8e item 19 — an initrd name that is a bootable kernel's symlink
// to a temporary initrd is replaced by the neutralized copy; the file the link pointed to is neither written nor
// unlinked by the neutralization, and the copy is built at the other temporary name.
func TestAbortNeutralizesLinkedInitrd(t *testing.T) {
	f := preparedFixture(t)
	name := f.dev.Path("/boot/initrd.img-" + runningKernel)
	target := f.dev.Path("/boot/.initrd.img-" + runningKernel + ".paddock")
	original := f.read("/boot/initrd.img-" + runningKernel)
	if err := os.Rename(name, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(target), name); err != nil {
		t.Fatal(err)
	}
	if err := encrypt.NeutralizeInitrds(context.Background(), f.dev, f.dev.layout); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || !neutralized(t, f, runningKernel, original) {
		t.Fatalf("the link was not replaced by the neutralized copy: %v %v", info, err)
	}
	if raw, err := os.ReadFile(target); err != nil || string(raw) != original { //nolint:gosec // test root
		t.Fatalf("the link's target changed: %v", err)
	}
	if f.dev.Exists("/boot/.initrd.img-" + runningKernel + ".next.paddock") {
		t.Fatal("the copy's temporary file is left")
	}
}

// TestNeutralizeLinkedInitrdAtNext: PDK-481 (rule B (0) of plan M8e item 19) — when the temporary initrd a bootable
// kernel's symlink refers to is also hard-linked at the ".next" name, the copy is built at a name no bootable link
// refers to: the link is replaced by the neutralized copy, the linked file is neither written nor unlinked under
// either name, and the copy's temporary file is gone.
func TestNeutralizeLinkedInitrdAtNext(t *testing.T) {
	f := preparedFixture(t)
	name := f.dev.Path("/boot/initrd.img-" + runningKernel)
	target := f.dev.Path("/boot/.initrd.img-" + runningKernel + ".paddock")
	next := f.dev.Path("/boot/.initrd.img-" + runningKernel + ".next.paddock")
	original := f.read("/boot/initrd.img-" + runningKernel)
	if err := os.Rename(name, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, next); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(target), name); err != nil {
		t.Fatal(err)
	}
	if err := encrypt.NeutralizeInitrds(context.Background(), f.dev, f.dev.layout); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || !neutralized(t, f, runningKernel, original) {
		t.Fatalf("the link was not replaced by the neutralized copy: %v %v", info, err)
	}
	for _, linked := range []string{target, next} {
		if raw, err := os.ReadFile(linked); err != nil || string(raw) != original { //nolint:gosec // test root
			t.Fatalf("the link's target %s changed: %v", linked, err)
		}
	}
	if f.dev.Exists("/boot/.initrd.img-" + runningKernel + ".next2.paddock") {
		t.Fatal("the copy's temporary file is left")
	}
}

// TestAbortNeutralizeBootFull: PDK-482 — a /boot without room for the copy leaves the initrds as they were, logs the
// error and reports disk.conversion_neutralize_failed with reason boot_space_low; the cleanup runs as before.
func TestAbortNeutralizeBootFull(t *testing.T) {
	f := preparedFixture(t)
	original := f.read("/boot/initrd.img-" + runningKernel)
	f.dev.Free = 1024
	if aborted, _ := encrypt.Abort(context.Background(), f.dev, f.dev.layout, f.store, conversionID, encrypt.ByAdmin, false, nil); !aborted {
		t.Fatal("not aborted")
	}
	if f.read("/boot/initrd.img-"+runningKernel) != original {
		t.Fatal("the initrd changed")
	}
	ev := f.store.events
	if len(ev) != 2 || ev[0].typ != protocol.EventDiskConversionAborted || ev[1].typ != protocol.EventDiskConversionNeutralizeFailed ||
		ev[1].data["reason"] != encrypt.IssueBootSpaceLow || ev[1].data["conversion_id"] != conversionID {
		t.Fatalf("events %+v", ev)
	}
	// The cleanup ran: it removed the module and stopped at its own room check.
	if c := f.conversion(); c.Phase != state.ConversionCancelled || !c.CleanupPending || !f.moduleGone() ||
		!strings.Contains(c.CleanupError, "/boot has 1024 bytes free") {
		t.Fatalf("the cleanup did not run: %+v", c)
	}
	// With room again, the cleanup completes.
	f.dev.Free = 0
	if done, err := encrypt.RunCleanup(context.Background(), f.dev, f.dev.layout, f.store); !done || err != nil {
		t.Fatalf("cleanup %v %v", done, err)
	}
}

// TestAbortNeutralizeWriteFails: a copy that cannot be written (a directory at the temporary path, which rule B does
// not remove) is reported with its reason; that initrd is unchanged and the cleanup still runs (and keeps failing
// closed on the directory).
func TestAbortNeutralizeWriteFails(t *testing.T) {
	f := preparedFixture(t)
	original := f.read("/boot/initrd.img-" + olderKernel)
	f.dev.MkdirAll("/boot/.initrd.img-" + olderKernel + ".paddock")
	if aborted, _ := encrypt.Abort(context.Background(), f.dev, f.dev.layout, f.store, conversionID, encrypt.ByAdmin, false, nil); !aborted {
		t.Fatal("not aborted")
	}
	ev := f.store.events
	if len(ev) != 2 || ev[1].typ != protocol.EventDiskConversionNeutralizeFailed || ev[1].data["reason"] == "" {
		t.Fatalf("events %+v", ev)
	}
	if f.read("/boot/initrd.img-"+olderKernel) != original {
		t.Fatal("the initrd changed")
	}
	if !f.moduleGone() || !f.conversion().CleanupPending {
		t.Fatalf("the cleanup did not run: %+v", f.conversion())
	}
}

// rearm is a dracut run that was already under way at the abort finishing after the neutralization: the initrd of v
// carries the module, the key and the plan again.
func rearm(f *fixture, v string) string {
	f.dev.buildInitrd("/boot/initrd.img-"+v, v, true)
	return f.read("/boot/initrd.img-" + v)
}

// TestDisarmWhilePackagesBusy: review 1 of PDK-482, B1 (architect decision 2026-10-30, (a)) — an abort while a package
// run holds dpkg's locks cannot clean up, so the abort removes the module and its dracut configuration itself and
// neutralizes the initrds; plan.env and the key stay. An initrd a dracut run already under way rebuilds afterwards, and
// a new kernel's initrd, are neutralized by the next disarm; a later dracut run omits the module. The cleanup completes
// once the locks are free.
func TestDisarmWhilePackagesBusy(t *testing.T) {
	f := preparedFixture(t)
	originals := map[string]string{runningKernel: f.read("/boot/initrd.img-" + runningKernel),
		olderKernel: f.read("/boot/initrd.img-" + olderKernel)}
	f.dev.PackagesBusy = true
	if aborted, _ := encrypt.Abort(context.Background(), f.dev, f.dev.layout, f.store, conversionID, encrypt.ByAdmin, false, nil); !aborted {
		t.Fatal("not aborted")
	}
	for v, original := range originals {
		if !neutralized(t, f, v, original) {
			t.Fatalf("the initrd of %s is not neutralized", v)
		}
	}
	if c := f.conversion(); !f.moduleGone() || !c.CleanupPending || !f.dev.Exists("/var/lib/paddock/encrypt/plan.env") ||
		!f.dev.Exists("/var/lib/paddock/install-passphrase") {
		t.Fatalf("after the abort: module gone %v, %+v", f.moduleGone(), c)
	}
	if ev := f.store.events; len(ev) != 1 || ev[0].typ != protocol.EventDiskConversionAborted {
		t.Fatalf("events %+v", ev)
	}
	const newKernel = "6.8.0-90-generic"
	f.dev.Write("/boot/vmlinuz-"+newKernel, "kernel")
	f.dev.Write("/lib/modules/"+newKernel+"/modules.dep", "")
	rearmed := map[string]string{runningKernel: rearm(f, runningKernel), newKernel: rearm(f, newKernel)}
	if err := encrypt.Disarm(context.Background(), f.dev, f.dev.layout, f.store); err != nil {
		t.Fatal(err)
	}
	for v, original := range rearmed {
		if !neutralized(t, f, v, original) {
			t.Fatalf("the rebuilt initrd of %s is not neutralized", v)
		}
	}
	if !neutralized(t, f, olderKernel, originals[olderKernel]) {
		t.Fatal("the older kernel's initrd changed")
	}
	f.dev.set(func(d *device) { d.buildInitrds() })
	if f.dev.initrdCarriesModule(runningKernel) {
		t.Fatal("a dracut run after the disarm built the module in")
	}
	f.dev.PackagesBusy = false
	if done, err := encrypt.RunCleanup(context.Background(), f.dev, f.dev.layout, f.store); !done || err != nil {
		t.Fatalf("cleanup %v %v", done, err)
	}
	for _, v := range []string{runningKernel, olderKernel, newKernel} {
		if f.dev.initrdCarriesModule(v) || strings.Contains(f.read("/boot/initrd.img-"+v), "PADDOCK_LAYOUT=cancelled") {
			t.Fatalf("the initrd of %s still carries the module or the override", v)
		}
	}
}

// TestDisarmRecordsModuleWritten: B1 (a) — a conversion whose state does not record the written module (step 7 killed
// before it saved the flag) gets it recorded before the module files are removed, so that the cleanup still rebuilds
// and verifies the initrds instead of taking the missing files for a module that was never written.
func TestDisarmRecordsModuleWritten(t *testing.T) {
	f := preparedFixture(t)
	if err := f.store.Update(func(c *state.DiskConversion, _ *state.LUKS) { c.ModuleWritten = false }); err != nil {
		t.Fatal(err)
	}
	f.dev.PackagesBusy = true
	if aborted, _ := encrypt.Abort(context.Background(), f.dev, f.dev.layout, f.store, conversionID, encrypt.ByAdmin, false, nil); !aborted {
		t.Fatal("not aborted")
	}
	if c := f.conversion(); !c.ModuleWritten || !f.moduleGone() {
		t.Fatalf("module written not recorded: %+v", c)
	}
	f.dev.PackagesBusy = false
	if done, err := encrypt.RunCleanup(context.Background(), f.dev, f.dev.layout, f.store); !done || err != nil {
		t.Fatalf("cleanup %v %v", done, err)
	}
	if f.dev.initrdCarriesModule(runningKernel) || f.dev.initrdCarriesModule(olderKernel) {
		t.Fatal("the cleanup skipped the rebuild")
	}
}

// TestDisarmOnlyPendingCleanup: Disarm changes nothing for a conversion that is not cancelled or failed with its
// cleanup pending (a prepared one, or a failed one without a cleanup, keeps its module and initrds).
func TestDisarmOnlyPendingCleanup(t *testing.T) {
	for name, set := range map[string]func(c *state.DiskConversion){
		"prepared":           func(*state.DiskConversion) {},
		"failed, no cleanup": func(c *state.DiskConversion) { c.Phase, c.CleanupPending = state.ConversionFailed, false },
	} {
		f := preparedFixture(t)
		_ = f.store.Update(func(c *state.DiskConversion, _ *state.LUKS) { set(c) })
		original := f.read("/boot/initrd.img-" + runningKernel)
		if err := encrypt.Disarm(context.Background(), f.dev, f.dev.layout, f.store); err != nil {
			t.Fatal(err)
		}
		if f.moduleGone() || f.read("/boot/initrd.img-"+runningKernel) != original {
			t.Fatalf("%s: disarmed", name)
		}
	}
}

// TestPrepareFailureDisarms: PDK-579 (plan M8e item 18, amendment 2026-10-30) — a preparation that fails after step 7
// wrote the module disarms before its cleanup: when the cleanup cannot rebuild the initrds, the module and its
// configuration are gone and every initrd is the prepared one followed by the override segment, plan.env and the key
// stay for the cleanup, and no neutralize_failed is emitted. The next cleanup then completes normally.
func TestPrepareFailureDisarms(t *testing.T) {
	f := stoppedBeforePrepared(t)
	originals := map[string]string{}
	for _, v := range []string{runningKernel, olderKernel} {
		originals[v] = f.read("/boot/initrd.img-" + v)
	}
	_ = f.store.Update(func(c *state.DiskConversion, _ *state.LUKS) { c.TransientErrors = encrypt.TransientRetries })
	f.dev.set(func(d *device) { d.dracutExit = 1 })
	if got := f.preparer().Prepare(context.Background()); got != encrypt.Failed {
		t.Fatalf("outcome %v", got)
	}
	c := f.conversion()
	if c.Phase != state.ConversionFailed || c.FailureStage != state.StagePrepare || !c.CleanupPending || !c.ModuleWritten {
		t.Fatalf("conversion %+v", c)
	}
	for v, original := range originals {
		if !neutralized(t, f, v, original) {
			t.Fatalf("the initrd of %s is not neutralized", v)
		}
	}
	if !f.moduleGone() || !f.dev.Exists("/var/lib/paddock/encrypt/plan.env") || !f.dev.Exists("/var/lib/paddock/install-passphrase") {
		t.Fatal("not disarmed, or plan.env or the key removed before the cleanup")
	}
	if types := f.store.types(); slices.Contains(types, protocol.EventDiskConversionNeutralizeFailed) {
		t.Fatalf("events %v", types)
	}
	f.dev.set(func(d *device) { d.dracutExit = 0 })
	if done, err := encrypt.RunCleanup(context.Background(), f.dev, f.dev.layout, f.store); !done || err != nil {
		t.Fatalf("cleanup %v %v", done, err)
	}
	for v := range originals {
		if f.dev.initrdCarriesModule(v) || strings.Contains(f.read("/boot/initrd.img-"+v), "PADDOCK_LAYOUT=cancelled") {
			t.Fatalf("the initrd of %s still carries the module or the override", v)
		}
	}
	if c := f.conversion(); c.Phase != state.ConversionFailed || c.CleanupPending || f.dev.Exists("/var/lib/paddock/install-passphrase") {
		t.Fatalf("conversion %+v", c)
	}
}

// TestNeutralizeCarryingInstalledKernels: review 1 of PDK-482, E2 and E4 — only an initrd whose listing shows the
// module is neutralized (an initramfs-tools image that never carried it stays as it is, so that its lister keeps
// reading it), and every installed kernel's initrd counts, also one GRUB lists without modules.dep.
func TestNeutralizeCarryingInstalledKernels(t *testing.T) {
	f := preparedFixture(t)
	f.dev.Write("/boot/initrd.img-"+olderKernel, "initramfs-tools image\n")
	const noModules = "6.8.0-60-generic"
	f.dev.Write("/boot/vmlinuz-"+noModules, "kernel")
	stray := rearm(f, noModules)
	if err := encrypt.NeutralizeInitrds(context.Background(), f.dev, f.dev.layout); err != nil {
		t.Fatal(err)
	}
	if f.read("/boot/initrd.img-"+olderKernel) != "initramfs-tools image\n" {
		t.Fatal("an initrd without the module was neutralized")
	}
	if !neutralized(t, f, noModules, stray) {
		t.Fatal("the initrd of a kernel without modules.dep is not neutralized")
	}
}

// TestNeutralizeChangedWhileCopied: review 1 of PDK-482, M1 and E3 — an initrd a kernel package's dracut run replaces
// while it is neutralized (here: while it is listed) is left as the run wrote it, the copy is removed and the failure
// names the change; the other kernels are still neutralized, and the next disarm neutralizes the new initrd.
func TestNeutralizeChangedWhileCopied(t *testing.T) {
	f := preparedFixture(t)
	older := f.read("/boot/initrd.img-" + olderKernel)
	rebuilt := f.read("/boot/initrd.img-"+runningKernel) + "rebuilt by a kernel package\n"
	f.dev.set(func(d *device) {
		d.onList = func(d *device, initrd string) {
			if initrd == "/boot/initrd.img-"+runningKernel {
				d.onList = nil
				d.Write(initrd, rebuilt)
			}
		}
	})
	err := encrypt.NeutralizeInitrds(context.Background(), f.dev, f.dev.layout)
	if err == nil || !strings.Contains(err.Error(), "changed while it was copied") {
		t.Fatalf("error %v", err)
	}
	if f.read("/boot/initrd.img-"+runningKernel) != rebuilt || !neutralized(t, f, olderKernel, older) {
		t.Fatal("the rebuilt initrd was overwritten or the other kernel skipped")
	}
	if temps := glob(t, f.dev.Path("/boot/.initrd.img-*")); len(temps) != 0 {
		t.Fatalf("temporary files left: %v", temps)
	}
	if err := encrypt.NeutralizeInitrds(context.Background(), f.dev, f.dev.layout); err != nil || !neutralized(t, f, runningKernel, rebuilt) {
		t.Fatalf("the rebuilt initrd is not neutralized at the retry: %v", err)
	}
}

// TestNeutralizeReason: review 1 of PDK-482, E5 — the event's reason comes from the first kernel that failed, not from
// a BootSpaceError anywhere in the joined errors.
func TestNeutralizeReason(t *testing.T) {
	space := fmt.Errorf("the initrd of b: %w", &encrypt.BootSpaceError{Needed: 2, Free: 1})
	other := fmt.Errorf("the initrd of a: %w", errors.New("permission denied\nmore"))
	if got := encrypt.NeutralizeReason(errors.Join(other, space)); got != "the initrd of a: permission denied" {
		t.Fatalf("reason %q", got)
	}
	if got := encrypt.NeutralizeReason(errors.Join(errors.Join(space), other)); got != encrypt.IssueBootSpaceLow {
		t.Fatalf("reason %q", got)
	}
}

// cpioZstd is a zstd-compressed newc archive of files (name → content), built with GNU cpio and zstd.
func cpioZstd(t *testing.T, files map[string]string) []byte {
	t.Helper()
	return cpioImage(t, files, "zstd -q -c")
}

// cpioImage is a newc archive of files (name → content) built with GNU cpio, piped through compress ("cat": none).
func cpioImage(t *testing.T, files map[string]string, compress string) []byte {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(name)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("sh", "-c", "find . | LC_ALL=C sort | cpio -o -H newc --quiet | "+compress) //nolint:gosec // the test's own pipeline
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("cpio | %s: %v", compress, err)
	}
	return out
}

// TestNeutralizeRealImages: review 1 of PDK-482, E2 — against real zstd-compressed cpio images listed by
// initramfs-tools' lsinitramfs (a host without dracut's lsinitrd): the image that carries the key and the plan is
// neutralized, the one that never carried them is left alone, so lsinitramfs still reads it (it fails on an image
// with the segment appended).
func TestNeutralizeRealImages(t *testing.T) {
	for _, tool := range []string{"cpio", "zstd", "lsinitramfs"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " is not installed")
		}
	}
	d := newDevice(t)
	d.missing = map[string]bool{"lsinitrd": true}
	d.Handle = func(line string) (string, int, bool) {
		initrd, ok := strings.CutPrefix(line, "lsinitramfs ")
		if !ok {
			return "", 0, false
		}
		out, err := exec.Command("lsinitramfs", d.Path(initrd)).Output() //nolint:gosec // the test's own tool and file
		if err != nil {
			return "", 1, true
		}
		return string(out), 0, true
	}
	carrying := string(cpioZstd(t, map[string]string{"usr/bin/tool": "x", "etc/paddock/encrypt-plan.env": "PADDOCK_LAYOUT=lvm\n",
		"etc/paddock/encrypt-key": "key"}))
	clean := string(cpioZstd(t, map[string]string{"usr/bin/tool": "x", "conf/initramfs.conf": "MODULES=most\n"}))
	d.Write("/boot/initrd.img-"+runningKernel, carrying)
	d.Write("/boot/initrd.img-"+olderKernel, clean)
	if err := encrypt.NeutralizeInitrds(context.Background(), d, d.layout); err != nil {
		t.Fatal(err)
	}
	pad := strings.Repeat("\x00", (4-len(carrying)%4)%4)
	if d.readOrEmpty("/boot/initrd.img-"+runningKernel) != carrying+pad+string(encrypt.NeutralizeSegment) {
		t.Fatal("the carrying image is not neutralized")
	}
	if d.readOrEmpty("/boot/initrd.img-"+olderKernel) != clean {
		t.Fatal("the clean image changed")
	}
	if out, err := exec.Command("lsinitramfs", d.Path("/boot/initrd.img-"+olderKernel)).CombinedOutput(); err != nil { //nolint:gosec // test
		t.Fatalf("lsinitramfs on the clean image: %v %s", err, out)
	}
}

// realListing makes d list initrds with the real lsinitramfs (lsinitrd missing); every other command goes to the fake.
func realListing(d *device) {
	d.missing = map[string]bool{"lsinitrd": true}
	d.Handle = func(line string) (string, int, bool) {
		initrd, ok := strings.CutPrefix(line, "lsinitramfs ")
		if !ok {
			return d.handle(line)
		}
		out, err := exec.Command("lsinitramfs", d.Path(initrd)).Output() //nolint:gosec // the test's own tool and file
		if err != nil {
			return "", 1, true
		}
		return string(out), 0, true
	}
}

// TestNeutralizeRealEarlyArchive: review 2 of PDK-482, X2 — real images with an uncompressed early archive (microcode)
// before a gzip- or xz-compressed main archive, built with GNU cpio, are neutralized: the early archive is skipped to
// the main archive's magic.
func TestNeutralizeRealEarlyArchive(t *testing.T) {
	for _, tool := range []string{"cpio", "gzip", "xz", "lsinitramfs"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " is not installed")
		}
	}
	for _, compress := range []string{"gzip -c", "xz -c --check=crc32"} {
		d := newDevice(t)
		realListing(d)
		image := string(cpioImage(t, map[string]string{"kernel/x86/microcode/GenuineIntel.bin": "ucode"}, "cat")) +
			string(cpioImage(t, map[string]string{"usr/bin/tool": "x", "etc/paddock/encrypt-key": "key"}, compress))
		d.Write("/boot/initrd.img-"+runningKernel, image)
		d.Write("/boot/initrd.img-"+olderKernel, string(cpioImage(t, map[string]string{"usr/bin/tool": "x"}, compress)))
		if err := encrypt.NeutralizeInitrds(context.Background(), d, d.layout); err != nil {
			t.Fatalf("%s: %v", compress, err)
		}
		pad := strings.Repeat("\x00", (4-len(image)%4)%4)
		if d.readOrEmpty("/boot/initrd.img-"+runningKernel) != image+pad+string(encrypt.NeutralizeSegment) {
			t.Fatalf("%s: the image is not neutralized", compress)
		}
	}
}

// TestNeutralizeRefusesUnsafeCompression: review 2 of PDK-482, X2 — an initrd whose main archive is compressed with lz4
// (no end marker, the kernel may not reach an archive appended to it) is left unchanged and the disarm fails with that
// reason; the other kernel's initrd is neutralized. With a report function Abort hands the failure to it and emits no
// event itself (X3).
func TestNeutralizeRefusesUnsafeCompression(t *testing.T) {
	f := preparedFixture(t)
	f.dev.set(func(d *device) { d.dracutExit = 1 })
	lz4 := "\x02\x21\x4c\x18\n" + strings.TrimPrefix(f.read("/boot/initrd.img-"+runningKernel), zstdMagic)
	f.dev.Write("/boot/initrd.img-"+runningKernel, lz4)
	older := f.read("/boot/initrd.img-" + olderKernel)
	var reported []error
	report := func(_ context.Context, err error) { reported = append(reported, err) }
	if aborted, _ := encrypt.Abort(context.Background(), f.dev, f.dev.layout, f.store, conversionID, encrypt.ByAdmin, false, report); !aborted {
		t.Fatal("not aborted")
	}
	if len(reported) != 1 || reported[0] == nil || !strings.Contains(encrypt.NeutralizeReason(reported[0]), "lz4-compressed") {
		t.Fatalf("reported %v", reported)
	}
	if f.read("/boot/initrd.img-"+runningKernel) != lz4 || !neutralized(t, f, olderKernel, older) {
		t.Fatal("the lz4 initrd changed or the other kernel's initrd is not neutralized")
	}
	for _, e := range f.store.events {
		if e.typ == protocol.EventDiskConversionNeutralizeFailed {
			t.Fatalf("Abort emitted the failure itself: %+v", e)
		}
	}
}

// TestNeutralizeUnlistable: review 2 of PDK-482, m2 — a carrying initrd that lsinitrd cannot list is neutralized all
// the same; the failed listing is logged, not returned.
func TestNeutralizeUnlistable(t *testing.T) {
	f := preparedFixture(t)
	original := f.read("/boot/initrd.img-" + runningKernel)
	handle := f.dev.Handle
	f.dev.Handle = func(line string) (string, int, bool) {
		if line == "lsinitrd /boot/initrd.img-"+runningKernel {
			return "", 1, true
		}
		return handle(line)
	}
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(prev)
	if err := encrypt.NeutralizeInitrds(context.Background(), f.dev, f.dev.layout); err != nil {
		t.Fatal(err)
	}
	if !neutralized(t, f, runningKernel, original) {
		t.Fatal("the unlistable initrd is not neutralized")
	}
	if !strings.Contains(logs.String(), "cannot be listed") {
		t.Fatalf("the failed listing is not logged: %s", logs.String())
	}
}

// TestCleanupListsNeutralizedReal: review 2 of PDK-482 — on a host whose only lister is initramfs-tools' lsinitramfs,
// which stops at the segment, a neutralized initrd counts as carrying (it carries the cancelled plan) rather than as
// unreadable: the cleanup removes the neutralized initrd of a kernel without modules.dep as an orphan and completes.
func TestCleanupListsNeutralizedReal(t *testing.T) {
	for _, tool := range []string{"cpio", "zstd", "lsinitramfs"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " is not installed")
		}
	}
	d := newDevice(t)
	realListing(d)
	clean := string(cpioZstd(t, map[string]string{"usr/bin/tool": "x", "conf/initramfs.conf": "MODULES=most\n"}))
	d.Write("/boot/initrd.img-"+runningKernel, clean)
	d.Write("/boot/initrd.img-"+olderKernel, clean)
	const noModules = "6.8.0-60-generic"
	d.Write("/boot/vmlinuz-"+noModules, "kernel")
	d.Write("/boot/initrd.img-"+noModules, string(cpioZstd(t, map[string]string{"etc/paddock/encrypt-key": "key"})))
	if err := encrypt.NeutralizeInitrds(context.Background(), d, d.layout); err != nil {
		t.Fatal(err)
	}
	done, orphans, err := encrypt.Cleanup(context.Background(), d, d.layout, true)
	if err != nil || !done || len(orphans) != 1 || orphans[0] != noModules || d.Exists("/boot/initrd.img-"+noModules) {
		t.Fatalf("cleanup: done %v, orphans %v, error %v", done, orphans, err)
	}
}

// TestRestoreReason: review 2 of PDK-482, X1 — the reason of disk.conversion_unlock_restore_failed names the initrd
// issue of the first failure, else its first line.
func TestRestoreReason(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{fmt.Errorf("rebuild: %w", &encrypt.KernelNotBuildableError{Version: "6.8.0-90-generic"}), encrypt.IssueKernelNotBuildable},
		{encrypt.ErrNoBootableKernel, encrypt.IssueNoBootableKernel},
		{errors.Join(&encrypt.BootSpaceError{Needed: 2, Free: 1}, errors.New("other")), encrypt.IssueBootSpaceLow},
		{errors.Join(errors.New("dracut: exit 1\nmore"), &encrypt.KernelNotBuildableError{Version: "x"}), "dracut: exit 1"},
	}
	for _, tt := range tests {
		if got := encrypt.RestoreReason(tt.err); got != tt.want {
			t.Errorf("%v: reason %q, want %q", tt.err, got, tt.want)
		}
	}
}
