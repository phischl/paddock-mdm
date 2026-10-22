package encrypt_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/encrypt"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// preparedFixture is a fixture whose conversion is prepared.
func preparedFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	if got := f.preparer().Prepare(context.Background()); got != encrypt.Prepared {
		t.Fatalf("outcome %v", got)
	}
	f.store.events = nil
	// The marker an agent before plan M8e amendment 2026-10-22 (item 22) armed at step 5: the cleanup still removes it.
	f.dev.Write("/var/lib/paddock/disk-setup-pending", "")
	// A kernel whose modules are left over without an initrd has nothing that could carry the module.
	f.dev.MkdirAll("/lib/modules/6.5.0-9-generic")
	return f
}

// leftovers are the files of a preparation that step (4) of the cleanup deletes.
var leftovers = []string{"/var/lib/paddock/install-passphrase", "/var/lib/paddock/encrypt/plan.json",
	"/var/lib/paddock/encrypt/plan.env", "/etc/paddock/disk-setup.json", "/var/lib/paddock/disk-setup-pending"}

// TestAbortPrepared: encrypt-abort in phase prepared removes the module, its configuration, the plan directory, the key
// and the disk-setup files, rebuilds every initrd and cancels the conversion (plan M8e decision 14).
func TestAbortPrepared(t *testing.T) {
	f := preparedFixture(t)
	f.dev.Write("/var/lib/paddock/encrypt/test-hooks", "")
	aborted, reason := encrypt.Abort(context.Background(), f.dev, f.dev.layout, f.store, "", encrypt.ByOperator, false)
	if !aborted || reason != "" {
		t.Fatalf("abort %v %s", aborted, reason)
	}
	c := f.conversion()
	if c.Phase != state.ConversionCancelled || c.CleanupPending {
		t.Fatalf("conversion %+v", c)
	}
	if !f.moduleGone() || f.dev.Exists("/var/lib/paddock/encrypt") || f.dev.initrdCarriesModule(runningKernel) ||
		f.dev.initrdCarriesModule(olderKernel) {
		t.Fatal("module or plan left")
	}
	for _, p := range leftovers {
		if f.dev.Exists(p) {
			t.Errorf("%s left", p)
		}
	}
	if ev := f.store.events; len(ev) != 1 || ev[0].typ != protocol.EventDiskConversionAborted || ev[0].data["by"] != "operator" ||
		ev[0].data["conversion_id"] != conversionID {
		t.Fatalf("events %+v", ev)
	}
}

// TestAbortCleanupOrder: the cleanup order of plan M8e decision 14 under invariant I3 — while dracut fails or an
// initrd of an installed kernel still lists the module, the key and the plan stay and CleanupPending holds; the next
// full pass retries and finishes; the event is emitted once.
func TestAbortCleanupOrder(t *testing.T) {
	f := preparedFixture(t)
	f.dev.set(func(d *device) { d.dracutExit = 1 })
	if aborted, _ := encrypt.Abort(context.Background(), f.dev, f.dev.layout, f.store, conversionID, encrypt.ByAdmin, false); !aborted {
		t.Fatal("not aborted")
	}
	pending := func(step string) {
		t.Helper()
		if c := f.conversion(); c.Phase != state.ConversionCancelled || !c.CleanupPending {
			t.Fatalf("%s: conversion %+v", step, c)
		}
		if !f.moduleGone() {
			t.Fatalf("%s: module directory or conf left", step)
		}
		for _, p := range leftovers {
			if !f.dev.Exists(p) {
				t.Fatalf("%s: %s deleted before the initrds were verified", step, p)
			}
		}
	}
	pending("dracut fails")
	if !f.dev.initrdCarriesModule(runningKernel) {
		t.Fatal("the fake initrd lost the module without a rebuild")
	}
	f.dev.set(func(d *device) { d.dracutExit, d.stale = 0, true })
	_, _ = encrypt.RunCleanup(context.Background(), f.dev, f.dev.layout, f.store)
	pending("older initrd still carries the module")
	f.dev.set(func(d *device) { d.stale = false })
	_, _ = encrypt.RunCleanup(context.Background(), f.dev, f.dev.layout, f.store)
	if c := f.conversion(); c.CleanupPending || c.Phase != state.ConversionCancelled {
		t.Fatalf("conversion %+v", c)
	}
	for _, p := range leftovers {
		if f.dev.Exists(p) {
			t.Errorf("%s left", p)
		}
	}
	if types := f.store.types(); len(types) != 1 || types[0] != protocol.EventDiskConversionAborted {
		t.Fatalf("events %v", types)
	}
}

// TestAbortRefused: an unknown conversion, a phase other than prepared and a partition that is LUKS already (I1)
// change nothing.
func TestAbortRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		id, phase string
		luks      bool
		want      string
	}{
		"foreign id":  {id: "00000000-0000-4000-8000-000000000000", phase: state.ConversionPrepared, want: "unknown_conversion"},
		"encrypting":  {phase: state.ConversionEncrypting, want: "not_abortable"},
		"completed":   {phase: state.ConversionCompleted, want: "not_abortable"},
		"preparing":   {phase: state.ConversionPreparing, want: "not_abortable"},
		"cancelled":   {phase: state.ConversionCancelled, want: "not_abortable"},
		"luks header": {phase: state.ConversionPrepared, luks: true, want: "not_abortable"},
	} {
		f := preparedFixture(t)
		_ = f.store.Update(func(c *state.DiskConversion, _ *state.LUKS) { c.Phase = tc.phase })
		f.dev.set(func(d *device) { d.luks = tc.luks })
		aborted, reason := encrypt.Abort(context.Background(), f.dev, f.dev.layout, f.store, tc.id, encrypt.ByAdmin, false)
		if aborted || reason != tc.want {
			t.Fatalf("%s: %v %s", name, aborted, reason)
		}
		if f.conversion().Phase != tc.phase || f.moduleGone() || !f.dev.Exists("/var/lib/paddock/install-passphrase") ||
			len(f.store.events) != 0 {
			t.Fatalf("%s: something changed", name)
		}
	}
	f := newFixture(t)
	f.store.c = nil
	if aborted, reason := encrypt.Abort(context.Background(), f.dev, f.dev.layout, f.store, "", encrypt.ByOperator, false); aborted ||
		reason != "unknown_conversion" {
		t.Fatalf("without a conversion: %v %s", aborted, reason)
	}
}

// TestAbortRefusedWhenLUKSUnknown: invariant I1 — a partition that does not exist (udev has not created its link) or
// that cryptsetup cannot check is no "not LUKS": the abort is refused and nothing changes.
func TestAbortRefusedWhenLUKSUnknown(t *testing.T) {
	for name, setup := range map[string]func(f *fixture){
		"partition missing": func(f *fixture) {
			if err := removeAll(f.dev.Path(partition)); err != nil {
				t.Fatal(err)
			}
		},
		"cryptsetup error": func(f *fixture) { f.dev.set(func(d *device) { d.luksExit = 4 }) },
	} {
		f := preparedFixture(t)
		setup(f)
		aborted, reason := encrypt.Abort(context.Background(), f.dev, f.dev.layout, f.store, "", encrypt.ByOperator, false)
		if aborted || reason != "not_abortable" {
			t.Fatalf("%s: %v %s", name, aborted, reason)
		}
		if f.conversion().Phase != state.ConversionPrepared || f.moduleGone() || !f.dev.Exists("/var/lib/paddock/install-passphrase") ||
			len(f.store.events) != 0 {
			t.Fatalf("%s: something changed", name)
		}
	}
}

// TestCleanupWaitsForDracutStatus: invariant I3 — while dpkg cannot tell whether dracut is installed (an error, or an
// upgrade under way) the initrds are not verified, so the key and the plan stay and CleanupPending holds. dpkg
// reporting dracut not installed skips only the rebuild, never the verification of every initrd.
func TestCleanupWaitsForDracutStatus(t *testing.T) {
	for name, setup := range map[string]func(d *device){
		"dpkg-query fails": func(d *device) { d.dpkgExit = 2 },
		"half-configured":  func(d *device) { d.packages["dracut"] = "half-configured" },
		"triggers-pending": func(d *device) { d.packages["dracut"] = "triggers-pending" },
	} {
		f := preparedFixture(t)
		f.dev.set(setup)
		if aborted, _ := encrypt.Abort(context.Background(), f.dev, f.dev.layout, f.store, "", encrypt.ByOperator, false); !aborted {
			t.Fatalf("%s: not aborted", name)
		}
		if c := f.conversion(); !c.CleanupPending {
			t.Fatalf("%s: cleanup recorded as done: %+v", name, c)
		}
		for _, p := range leftovers {
			if !f.dev.Exists(p) {
				t.Fatalf("%s: %s deleted although the initrds were not verified", name, p)
			}
		}
		f.dev.set(func(d *device) { d.dpkgExit, d.packages["dracut"] = 0, "installed" })
		_, _ = encrypt.RunCleanup(context.Background(), f.dev, f.dev.layout, f.store)
		if c := f.conversion(); c.CleanupPending || f.dev.Exists("/var/lib/paddock/install-passphrase") {
			t.Fatalf("%s: retry did not finish: %+v", name, c)
		}
	}
	// Review 2, major-1: dracut unknown to dpkg, not-installed, or in rc after a local admin installed initramfs-tools
	// (dracut-core with dracut and lsinitrd stays; initramfs-tools rebuilds only the newest kernel's initrd). The
	// initrds built with the module still carry it, so the key and the plan stay until every initrd is verified clean.
	for _, status := range []string{"", "not-installed", "config-files"} {
		f := preparedFixture(t)
		f.dev.set(func(d *device) {
			if delete(d.packages, "dracut"); status != "" {
				d.packages["dracut"] = status
			}
		})
		if aborted, _ := encrypt.Abort(context.Background(), f.dev, f.dev.layout, f.store, "", encrypt.ByOperator, false); !aborted {
			t.Fatalf("dracut %q: not aborted", status)
		}
		f.dev.Write("/boot/initrd.img-"+runningKernel, "initramfs-tools image\n")
		_, _ = encrypt.RunCleanup(context.Background(), f.dev, f.dev.layout, f.store)
		if c := f.conversion(); !c.CleanupPending {
			t.Fatalf("dracut %q: cleanup recorded as done while the older initrd carries the module: %+v", status, c)
		}
		for _, p := range leftovers {
			if !f.dev.Exists(p) {
				t.Fatalf("dracut %q: %s deleted while the older initrd carries the module", status, p)
			}
		}
		// Only step 8's per-kernel builds of the preparation (two kernels).
		if f.longCalls("dracut") != 2 {
			t.Fatalf("dracut %q: the cleanup rebuilt the initrds of another tool: %v", status, f.dev.Long())
		}
		f.dev.Write("/boot/initrd.img-"+olderKernel, "initramfs-tools image\n")
		_, _ = encrypt.RunCleanup(context.Background(), f.dev, f.dev.layout, f.store)
		if c := f.conversion(); c.CleanupPending || f.dev.Exists("/var/lib/paddock/install-passphrase") {
			t.Fatalf("dracut %q: retry did not finish once every initrd was clean: %+v", status, c)
		}
	}
}

// TestCleanupListsWithAnyTool: invariant I3 — the initrds are verified with lsinitrd, else lsinitramfs; with neither
// installed nothing is deleted while an initrd exists, and with no initrd at all nothing can carry the module.
func TestCleanupListsWithAnyTool(t *testing.T) {
	f := preparedFixture(t)
	f.dev.set(func(d *device) { d.missing = map[string]bool{"lsinitrd": true}; d.stale = true })
	if aborted, _ := encrypt.Abort(context.Background(), f.dev, f.dev.layout, f.store, "", encrypt.ByOperator, false); !aborted {
		t.Fatal("not aborted")
	}
	if !f.conversion().CleanupPending || !f.dev.Exists("/var/lib/paddock/install-passphrase") ||
		f.dev.Count("lsinitramfs /boot/.initrd.img-"+olderKernel+".paddock") != 1 {
		t.Fatalf("lsinitramfs: the older initrd was not listed or its module ignored: %v", f.dev.Calls())
	}
	f.dev.set(func(d *device) { d.missing["lsinitramfs"], d.stale = true, false })
	_, _ = encrypt.RunCleanup(context.Background(), f.dev, f.dev.layout, f.store)
	if !f.conversion().CleanupPending || !f.dev.Exists("/var/lib/paddock/encrypt/plan.env") {
		t.Fatal("no lister: the cleanup finished without reading the initrds")
	}
	for _, v := range []string{runningKernel, olderKernel} {
		if err := removeAll(f.dev.Path("/boot/initrd.img-" + v)); err != nil {
			t.Fatal(err)
		}
	}
	f.dev.set(func(d *device) { d.packages["dracut"] = "config-files" })
	_, _ = encrypt.RunCleanup(context.Background(), f.dev, f.dev.layout, f.store)
	if f.conversion().CleanupPending || f.dev.Exists("/var/lib/paddock/install-passphrase") {
		t.Fatal("no initrd at all: the cleanup did not finish")
	}
}

// TestCleanupBeforeModule: before step 7 no initrd can carry the module: the cleanup rebuilds and lists nothing. A
// module file found anyway makes it verify (invariant I3).
func TestCleanupBeforeModule(t *testing.T) {
	f := newFixture(t)
	f.dev.set(func(d *device) { d.packages["dracut"] = "installed" })
	if done, _, err := encrypt.Cleanup(context.Background(), f.dev, f.dev.layout, false); !done || err != nil ||
		len(f.dev.Calls()) != 0 {
		t.Fatalf("no module: %v %v, calls %v", done, err, f.dev.Calls())
	}
	f.dev.Write(encrypt.ModuleConf, "add_dracutmodules+=\" paddock-encrypt \"\n")
	f.dev.set(func(d *device) { d.stale = true })
	if done, _, _ := encrypt.Cleanup(context.Background(), f.dev, f.dev.layout, false); done {
		t.Fatal("a module configuration found: the cleanup finished without verifying the initrds")
	}
}

// TestIsLUKSEvidence: amendment item 13 — "not LUKS" only with every piece of evidence; LUKS on isLuks exit 0.
func TestIsLUKSEvidence(t *testing.T) {
	f := preparedFixture(t)
	c := f.conversion()
	d := encrypt.DiskOf(c)
	if luks, ok := encrypt.IsLUKS(context.Background(), f.dev, f.dev.layout, d); luks || !ok {
		t.Fatalf("plain partition: %v %v", luks, ok)
	}
	for name, set := range map[string]func(){
		"mapping active": func() { f.dev.Write("/dev/mapper/"+c.Mapping, "") },
		"by-uuid link":   func() { f.dev.Write("/dev/disk/by-uuid/"+c.LUKSUUID, "") },
		"two devices":    func() { f.dev.set(func(d *device) { d.partDevices = "/dev/sda3\n/dev/sdb3\n" }) },
		"no device":      func() { f.dev.set(func(d *device) { d.partDevices = "\n" }) },
		"isLuks error":   func() { f.dev.set(func(d *device) { d.luksExit = 4 }) },
	} {
		set()
		if luks, ok := encrypt.IsLUKS(context.Background(), f.dev, f.dev.layout, d); luks || ok {
			t.Fatalf("%s: %v %v", name, luks, ok)
		}
		_ = os.Remove(f.dev.Path("/dev/mapper/" + c.Mapping))
		_ = os.Remove(f.dev.Path("/dev/disk/by-uuid/" + c.LUKSUUID))
		f.dev.set(func(d *device) { d.partDevices, d.luksExit = "", 0 })
	}
	f.dev.set(func(d *device) { d.luks = true })
	f.dev.Write("/dev/mapper/"+c.Mapping, "")
	if luks, ok := encrypt.IsLUKS(context.Background(), f.dev, f.dev.layout, d); !luks || !ok {
		t.Fatalf("LUKS: %v %v", luks, ok)
	}
}

// TestCleanupPackageLock: amendment item 14 — the cleanup holds dpkg's locks from (1) to (4) and waits for the next
// pass while a package run holds them, with nothing removed.
func TestCleanupPackageLock(t *testing.T) {
	f := preparedFixture(t)
	f.dev.PackagesBusy = true
	if done, _, err := encrypt.Cleanup(context.Background(), f.dev, f.dev.layout, true); done || !errors.Is(err, encrypt.ErrPackagesBusy) ||
		!f.dev.Exists(encrypt.ModuleConf) || !f.dev.Exists(encrypt.ModuleDir) {
		t.Fatalf("cleanup while apt held the lock: %v %v", done, err)
	}
	f.dev.PackagesBusy = false
	held := true
	f.dev.set(func(d *device) { d.afterDracut = func(d *device) { held = held && d.PackagesLocked() } })
	if done, _, err := encrypt.Cleanup(context.Background(), f.dev, f.dev.layout, true); !done || err != nil || !held || f.dev.PackagesLocked() {
		t.Fatalf("cleanup: %v %v, held %v", done, err, held)
	}
}

// TestCleanupRemovesConfFirst: adversarial review round 3, minor — the module's dracut configuration goes before its
// directory: a cleanup stopped in between never leaves a configuration that names a missing module (every dracut run
// would fail on it).
func TestCleanupRemovesConfFirst(t *testing.T) {
	f := preparedFixture(t)
	if err := os.RemoveAll(f.dev.Path("/usr/lib/dracut/modules.d")); err != nil {
		t.Fatal(err)
	}
	f.dev.Write("/usr/lib/dracut/modules.d", "not a directory") // removing the module directory fails
	if done, _, err := encrypt.Cleanup(context.Background(), f.dev, f.dev.layout, true); done || err == nil {
		t.Fatalf("cleanup %v %v", done, err)
	}
	if f.dev.Exists(encrypt.ModuleConf) {
		t.Fatal("the configuration outlived a failed removal of the module directory")
	}
}

// TestAbortClearsCleanupError: PDK-381 — the abort's own transition clears an earlier cleanup reason, also when the
// cleanup after it cannot record anything (the run loop is gone).
func TestAbortClearsCleanupError(t *testing.T) {
	f := preparedFixture(t)
	since := f.now
	_ = f.store.Update(func(c *state.DiskConversion, _ *state.LUKS) {
		c.CleanupError, c.PackagesBusySince = "an earlier reason", &since
	})
	f.store.goneAfter = func(c *state.DiskConversion) bool { return c.Phase == state.ConversionCancelled }
	if aborted, _ := encrypt.Abort(context.Background(), f.dev, f.dev.layout, f.store, "", encrypt.ByOperator, false); !aborted {
		t.Fatal("not aborted")
	}
	if f.store.c.CleanupError != "" || !f.store.c.CleanupPending || f.store.c.PackagesBusySince != nil {
		t.Fatalf("conversion %+v", f.store.c)
	}
}
