package encrypt_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/encrypt"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

const aptInstall = "apt-get install -y dracut"

// TestPrepareLVM: the steps of plan M8e decision 13 on an lvm device still on initramfs-tools.
func TestPrepareLVM(t *testing.T) {
	f := newFixture(t)
	f.server.statuses = []string{"pending", "pending"}
	f.server.onStatus = func() {
		// Nothing after step 4 runs before the server stored the key.
		if f.dev.Exists("/etc/paddock/disk-setup.json") || f.dev.Count(aptInstall) > 0 {
			t.Error("a step after the escrow ran before stored")
		}
	}
	if got := f.preparer().Prepare(context.Background()); got != encrypt.Prepared {
		t.Fatalf("outcome %v, conversion %+v", got, f.conversion())
	}
	key := f.read("/var/lib/paddock/install-passphrase")
	if len(key) != 71 || strings.Trim(key, "cbdefghijklnrtuv-") != "" || strings.Count(key, "-") != 7 || f.mode("/var/lib/paddock/install-passphrase") != 0o600 {
		t.Fatalf("conversion key %q", key)
	}
	for i, group := range strings.Split(key, "-") {
		if len(group) != 8 {
			t.Fatalf("group %d of %q", i, key)
		}
	}
	c := f.conversion()
	if len(f.server.requests) != 1 {
		t.Fatalf("escrow requests %+v", f.server.requests)
	}
	req := f.server.requests[0]
	// A header field on a secret is refused by POST /v1/escrow (the server's own predicate, PDK-247).
	if req.Kind != escrow.KindLUKSRecoveryKey || req.Generation != 3 || req.HasHeaderFields() || c.LUKSUUID == "" || req.Ciphertext == "" ||
		req.KeyVersion != 1 {
		t.Fatalf("escrow request %+v, conversion %+v", req, c)
	}
	if f.store.luks.RecoveryAttempted != 3 || f.store.luks.RecoveryStored != 3 || c.KeyEscrowGeneration != 3 {
		t.Fatalf("generations %+v %d", f.store.luks, c.KeyEscrowGeneration)
	}
	var plan encrypt.Plan
	if err := json.Unmarshal([]byte(f.read("/var/lib/paddock/encrypt/plan.json")), &plan); err != nil {
		t.Fatal(err)
	}
	const p = int64(40793800704)
	if plan.ConversionID != conversionID || plan.Layout != encrypt.KindLVM || plan.Mapping != "dm_crypt-0" || plan.VG != "ubuntu-vg" ||
		plan.LV != "ubuntu-lv" || plan.PVTargetBytes != p-32<<20 || plan.DataBytes != p-32<<20 ||
		plan.FSTargetBytes != 20396900352-16*4194304 || plan.UnlockMode != "tpm_only" || plan.BootPINMinLength != 6 ||
		plan.LUKSUUID != c.LUKSUUID || plan.Partition != "/dev/disk/by-partuuid/8c2f8d4e-5b7a-4f1c-9e0d-2a6b3c4d5e6f" {
		t.Fatalf("plan %+v", plan)
	}
	if f.mode("/var/lib/paddock/encrypt/plan.json") != 0o600 || f.mode("/var/lib/paddock/encrypt") != 0o700 {
		t.Fatal("plan files not root-only")
	}
	env := f.read("/var/lib/paddock/encrypt/plan.env")
	for _, line := range []string{"PADDOCK_LAYOUT=lvm", "PADDOCK_VG=ubuntu-vg", "PADDOCK_LV=ubuntu-lv", "PADDOCK_MAPPING=dm_crypt-0",
		"PADDOCK_LUKS_UUID=" + c.LUKSUUID, "PADDOCK_PART_UUID=8c2f8d4e-5b7a-4f1c-9e0d-2a6b3c4d5e6f",
		"PADDOCK_FS_UUID=3d5a2c71-8e4b-4f09-a1c6-7b2e9d0f4a85", "PADDOCK_FS_TARGET_SECTORS=39706624"} {
		if !strings.Contains(env, line+"\n") {
			t.Errorf("plan.env lacks %s:\n%s", line, env)
		}
	}
	if f.mode("/var/lib/paddock/encrypt/plan.env") != 0o600 {
		t.Fatal("plan.env not 0600")
	}
	// The marker waits for the completed reencryption (plan M8e amendment 2026-10-22, item 22).
	if got := f.read("/etc/paddock/disk-setup.json"); got != `{"boot_pin_min_length":6,"unlock_mode":"tpm_only"}` ||
		f.dev.Exists("/var/lib/paddock/disk-setup-pending") {
		t.Fatalf("disk setup %q", got)
	}
	if got := f.read(encrypt.TPM2Conf); got != "# Paddock: unlock LUKS with systemd-cryptsetup and TPM2+PIN (plan M4b)\nhostonly=\"yes\"\n"+
		"add_dracutmodules+=\" systemd crypt tpm2-tss lvm \"\n" {
		t.Fatalf("tpm2 conf %q", got)
	}
	if got := f.read(encrypt.ModuleConf); got != "add_dracutmodules+=\" paddock-encrypt \"\n" {
		t.Fatalf("module conf %q", got)
	}
	if f.mode(encrypt.ModuleDir) != 0o755 || f.mode(encrypt.ModuleDir+"/module-setup.sh") != 0o755 ||
		f.mode(encrypt.ModuleDir+"/paddock-encrypt-init.sh") != 0o755 || f.mode(encrypt.ModuleDir+"/paddock-encrypt-init.service") != 0o644 {
		t.Fatal("module file modes")
	}
	for _, initrd := range glob(t, f.dev.Path("/boot/initrd.img-*")) {
		if info, _ := statMode(initrd); info != 0o600 {
			t.Errorf("%s mode %v", initrd, info)
		}
	}
	if f.dev.Count(aptInstall) != 1 || f.longCalls("dracut -f --no-uefi /boot/.initrd.img-") != 2 || f.longCalls("dracut -f --regenerate-all") != 0 ||
		f.dev.Count("apt-get -s -o Debug::NoLocking=true install dracut") != 2 {
		t.Fatalf("calls %v", f.dev.Calls())
	}
	if c.Phase != state.ConversionPrepared || c.PreparedAt == nil || c.Layout != "lvm" || c.Mapping != "dm_crypt-0" || c.DataBytes != p-32<<20 {
		t.Fatalf("conversion %+v", c)
	}
	ev := f.store.events
	if len(ev) != 1 || ev[0].typ != protocol.EventDiskConversionPrepared || ev[0].data["conversion_id"] != conversionID ||
		ev[0].data["layout"] != "lvm" || ev[0].data["volume"] != c.LUKSUUID || ev[0].data["data_bytes"] != p-32<<20 {
		t.Fatalf("events %+v", ev)
	}
	for _, p := range []string{"/etc/crypttab", "/etc/fstab", "/etc/default/grub"} {
		if f.dev.Exists(p) {
			t.Errorf("the preparation wrote %s", p)
		}
	}
}

// TestPrepareDracutInstalled: with dracut installed nothing is simulated or installed, an existing tpm2 configuration
// is kept, and a taken mapping name is skipped.
func TestPrepareDracutInstalled(t *testing.T) {
	f := newFixture(t)
	f.dev.set(func(d *device) { d.packages["dracut"] = "installed" })
	f.dev.Write(encrypt.TPM2Conf, "custom\n")
	f.dev.Write("/dev/mapper/dm_crypt-0", "")
	if got := f.preparer().Prepare(context.Background()); got != encrypt.Prepared {
		t.Fatalf("outcome %v %+v", got, f.conversion())
	}
	if f.dev.Count(aptInstall) != 0 || f.read(encrypt.TPM2Conf) != "custom\n" || f.conversion().Mapping != "dm_crypt-1" {
		t.Fatalf("calls %v, mapping %s", f.dev.Calls(), f.conversion().Mapping)
	}
}

// TestPrepareRerun: a preparation interrupted before any step resumes on a second run without repeating a finished
// step — one key (AC 3), one escrow, one apt-get — and ends prepared.
func TestPrepareRerun(t *testing.T) {
	for stop := 1; stop <= 9; stop++ {
		f := newFixture(t)
		p := f.preparer()
		n := 0
		p.Hold = func(context.Context) error {
			if n++; n == stop {
				return errors.New("agent stopped")
			}
			return nil
		}
		if got := p.Prepare(context.Background()); got != encrypt.Stopped {
			t.Fatalf("stop %d: first outcome %v", stop, got)
		}
		key := ""
		if f.dev.Exists("/var/lib/paddock/install-passphrase") {
			key = f.read("/var/lib/paddock/install-passphrase")
		}
		if got := f.preparer().Prepare(context.Background()); got != encrypt.Prepared {
			t.Fatalf("stop %d: second outcome %v %+v", stop, got, f.conversion())
		}
		if len(f.server.requests) != 1 || f.dev.Count(aptInstall) != 1 || f.store.luks.RecoveryAttempted != 3 {
			t.Fatalf("stop %d: escrows %d, apt-get %d, attempted %d", stop, len(f.server.requests), f.dev.Count(aptInstall),
				f.store.luks.RecoveryAttempted)
		}
		if key != "" && f.read("/var/lib/paddock/install-passphrase") != key {
			t.Fatalf("stop %d: a second conversion key", stop)
		}
	}
}

// TestPrepareKeyKeptAcrossEscrowRetry: plan M8e decision 13 step 3 and AC 3 — an agent stopped while it waits for the
// escrow keeps its conversion key; the next run escrows the same key under the next generation.
func TestPrepareKeyKeptAcrossEscrowRetry(t *testing.T) {
	f := newFixture(t)
	p := f.preparer()
	p.Sleep = func(context.Context, time.Duration) error { return errors.New("agent stopped") }
	if got := p.Prepare(context.Background()); got != encrypt.Stopped {
		t.Fatalf("first outcome %v", got)
	}
	if c := f.conversion(); c.KeyEscrowGeneration != 0 || f.store.luks.RecoveryAttempted != 3 {
		t.Fatalf("conversion %+v, luks %+v", c, f.store.luks)
	}
	key := f.read("/var/lib/paddock/install-passphrase")
	if got := f.preparer().Prepare(context.Background()); got != encrypt.Prepared {
		t.Fatalf("second outcome %v", got)
	}
	if f.read("/var/lib/paddock/install-passphrase") != key {
		t.Fatal("a second conversion key")
	}
	if r := f.server.requests; len(r) != 2 || r[0].Generation != 3 || r[1].Generation != 4 || f.conversion().KeyEscrowGeneration != 4 {
		t.Fatalf("escrows %+v", r)
	}
}

// TestPrepareAbortBeforePrepared: an abort the loop records between the check before step 9 and step 9 itself keeps
// the conversion preparing and runs, so that its deferred command is not answered not_abortable for a prepared
// conversion (plan M8e decision 27).
func TestPrepareAbortBeforePrepared(t *testing.T) {
	f := newFixture(t)
	f.store.beforeUpdate = func(c *state.DiskConversion) {
		if f.dev.Exists(encrypt.ModuleConf) {
			c.AbortRequested = true
		}
	}
	if got := f.preparer().Prepare(context.Background()); got != encrypt.Aborted {
		t.Fatalf("outcome %v", got)
	}
	f.store.beforeUpdate = nil
	if c := f.conversion(); c.Phase != state.ConversionCancelled || c.PreparedAt != nil || !f.moduleGone() {
		t.Fatalf("conversion %+v", c)
	}
	if types := f.store.types(); len(types) != 1 || types[0] != protocol.EventDiskConversionAborted {
		t.Fatalf("events %v", types)
	}
}

// TestPrepareEscrowNotStored: failed, refused and no answer within 15 minutes end the preparation with
// escrow_not_stored; the key is shredded and nothing after step 4 runs.
func TestPrepareEscrowNotStored(t *testing.T) {
	timeout := make([]string, 31)
	for i := range timeout {
		timeout[i] = "pending"
	}
	for name, statuses := range map[string][]string{"failed": {escrow.StatusFailed}, "refused": {"pending", escrow.StatusRefused},
		"timeout": timeout} {
		f := newFixture(t)
		f.server.statuses = statuses
		if got := f.preparer().Prepare(context.Background()); got != encrypt.Failed {
			t.Fatalf("%s: outcome %v", name, got)
		}
		c := f.conversion()
		if c.Phase != state.ConversionFailed || c.FailureStage != state.StagePrepare || c.FailureReason != "escrow_not_stored" ||
			c.CleanupPending || c.KeyEscrowGeneration != 0 {
			t.Fatalf("%s: conversion %+v", name, c)
		}
		if f.dev.Exists("/var/lib/paddock/install-passphrase") || f.dev.Exists("/etc/paddock/disk-setup.json") || f.dev.Count(aptInstall) != 0 {
			t.Fatalf("%s: key kept or later steps ran: %v", name, f.dev.Calls())
		}
		if ev := f.store.events; len(ev) != 1 || ev[0].typ != protocol.EventDiskConversionFailed || ev[0].data["reason"] != "escrow_not_stored" ||
			ev[0].data["stage"] != "prepare" || ev[0].data["volume"] != c.LUKSUUID {
			t.Fatalf("%s: events %+v", name, ev)
		}
	}
}

// TestPrepareDracutRemoves: a simulation that would remove a package outside the allow list installs nothing (stop
// condition S11).
func TestPrepareDracutRemoves(t *testing.T) {
	f := newFixture(t)
	f.dev.Set("apt-get -s -o Debug::NoLocking=true install dracut",
		"Remv brltty [6.6]\nRemv ubuntu-desktop-minimal [1.539]\nRemv initramfs-tools [0.142]\nInst dracut (060)\n", 0)
	if got := f.preparer().Prepare(context.Background()); got != encrypt.Failed {
		t.Fatalf("outcome %v", got)
	}
	if c := f.conversion(); c.FailureReason != "dracut_removes:ubuntu-desktop-minimal" || c.CleanupPending {
		t.Fatalf("conversion %+v", c)
	}
	if f.dev.Count(aptInstall) != 0 {
		t.Fatal("dracut installed despite the simulation")
	}
}

// TestPrepareDracutInstallFailed: a failing apt-get install ends with dracut_install_failed.
func TestPrepareDracutInstallFailed(t *testing.T) {
	f := newFixture(t)
	f.dev.set(func(d *device) { d.aptExit = 100 })
	if got := f.preparer().Prepare(context.Background()); got != encrypt.Failed || f.conversion().FailureReason != "dracut_install_failed" {
		t.Fatalf("outcome %v %+v", got, f.conversion())
	}
	if f.dev.Exists(encrypt.ModuleDir) {
		t.Fatal("the module was written after a failed switch")
	}
}

// TestPrepareDracutRemovedDiffers: what really left is compared with the simulation on the installed state: a
// package left in rc counts, one that was not installed before never does, anything else fails the step.
func TestPrepareDracutRemovedDiffers(t *testing.T) {
	f := newFixture(t)
	f.dev.set(func(d *device) {
		d.realRemove = map[string]string{"brltty": "config-files", "initramfs-tools": "config-files", "bash": "not-installed",
			"old-tool": "not-installed"}
	})
	if got := f.preparer().Prepare(context.Background()); got != encrypt.Failed {
		t.Fatalf("outcome %v", got)
	}
	if c := f.conversion(); c.FailureReason != "dracut_removed_differs:bash" {
		t.Fatalf("conversion %+v", c)
	}
}

// TestPrepareInitrdIncomplete: a failure at step 8 runs the cleanup first (finding N2): no module files, every initrd
// rebuilt without the module, the key and the plan removed.
func TestPrepareInitrdIncomplete(t *testing.T) {
	f := newFixture(t)
	f.dev.set(func(d *device) { d.incomplete = true })
	if got := f.preparer().Prepare(context.Background()); got != encrypt.Failed {
		t.Fatalf("outcome %v", got)
	}
	c := f.conversion()
	if c.Phase != state.ConversionFailed || c.FailureReason != "initrd_incomplete" || c.CleanupPending {
		t.Fatalf("conversion %+v", c)
	}
	// Step 8 stops at the first kernel's incomplete initrd, then the cleanup rebuilds both (amendment items 18, 19(h)).
	if !f.moduleGone() || f.longCalls("dracut -f --regenerate-all") != 0 || f.longCalls("dracut -f --no-uefi /boot/.initrd.img-") != 3 ||
		f.dev.initrdCarriesModule(runningKernel) ||
		f.dev.initrdCarriesModule(olderKernel) {
		t.Fatalf("module left: %v", f.dev.Long())
	}
	for _, p := range []string{"/var/lib/paddock/install-passphrase", "/var/lib/paddock/encrypt", "/etc/paddock/disk-setup.json",
		"/var/lib/paddock/disk-setup-pending"} {
		if f.dev.Exists(p) {
			t.Errorf("%s left after the cleanup", p)
		}
	}
	if types := f.store.types(); len(types) != 1 || types[0] != protocol.EventDiskConversionFailed {
		t.Fatalf("events %v", types)
	}
}

// TestPrepareWithoutModule: a build without the embedded module fails at step 7 and cleans up.
func TestPrepareWithoutModule(t *testing.T) {
	f := newFixture(t)
	p := f.preparer()
	p.Module = nil
	if got := p.Prepare(context.Background()); got != encrypt.Failed || !f.moduleGone() || f.conversion().CleanupPending {
		t.Fatalf("outcome %v %+v", got, f.conversion())
	}
}

// TestPrepareNotEligible: step 1 repeats the preflight; dm_crypt is checked here only.
func TestPrepareNotEligible(t *testing.T) {
	f := newFixture(t)
	if err := removeAll(f.dev.Path("/sys/module/dm_crypt")); err != nil {
		t.Fatal(err)
	}
	f.dev.Set("modprobe dm_crypt", "", 1)
	if got := f.preparer().Prepare(context.Background()); got != encrypt.Failed {
		t.Fatalf("outcome %v", got)
	}
	if c := f.conversion(); c.FailureReason != "not_eligible:dm_crypt_missing" || f.dev.Exists("/var/lib/paddock/encrypt/plan.json") {
		t.Fatalf("conversion %+v", c)
	}
}

// TestPrepareAbortRequested: an abort received while preparing stops the worker before its next step and cancels the
// conversion (plan M8e decision 27).
func TestPrepareAbortRequested(t *testing.T) {
	f := newFixture(t)
	p := f.preparer()
	n := 0
	p.Hold = func(context.Context) error {
		if n++; n == 5 {
			_ = f.store.Update(func(c *state.DiskConversion, _ *state.LUKS) { c.AbortRequested = true })
		}
		return nil
	}
	if got := p.Prepare(context.Background()); got != encrypt.Aborted {
		t.Fatalf("outcome %v", got)
	}
	c := f.conversion()
	if c.Phase != state.ConversionCancelled || c.AbortRequested || c.CleanupPending || f.dev.Exists("/var/lib/paddock/install-passphrase") ||
		f.dev.Count(aptInstall) != 0 {
		t.Fatalf("conversion %+v, calls %v", c, f.dev.Calls())
	}
	if ev := f.store.events; len(ev) != 1 || ev[0].typ != protocol.EventDiskConversionAborted || ev[0].data["by"] != "admin" {
		t.Fatalf("events %+v", ev)
	}
}

// TestPrepareStopsWhenAdopted: a conversion that is no longer preparing (adopted at a full pass) runs no further step.
func TestPrepareStopsWhenAdopted(t *testing.T) {
	f := newFixture(t)
	p := f.preparer()
	p.Hold = func(context.Context) error {
		_ = f.store.Update(func(c *state.DiskConversion, _ *state.LUKS) { c.Phase = state.ConversionEncrypting })
		return nil
	}
	if got := p.Prepare(context.Background()); got != encrypt.Stopped || len(f.dev.Calls()) != 0 {
		t.Fatalf("outcome %v, calls %v", got, f.dev.Calls())
	}
}

// TestPreparePlanRecordedAfterStop: Review 2, major-2 — a run that wrote plan.json but could not record it in the state
// (stopped, or the save failed) leaves no conversion without its partition and LUKS UUID: the rerun records them from
// plan.json before step 3, and the key escrowed before the preparation is announced for that LUKS UUID (the escrow
// request itself carries no volume, plan M8e amendment item 20).
func TestPreparePlanRecordedAfterStop(t *testing.T) {
	f := newFixture(t)
	f.store.saveErr = func(*state.DiskConversion) error {
		if f.dev.Exists("/var/lib/paddock/encrypt/plan.json") {
			return errors.New("disk full")
		}
		return nil
	}
	f.preparer().Prepare(context.Background())
	if c := f.conversion(); c.Partition != "" || c.Phase != state.ConversionPreparing || !f.dev.Exists("/var/lib/paddock/encrypt/plan.json") {
		t.Fatalf("the fixture recorded the plan: %+v", c)
	}
	f.store.saveErr = nil
	if got := f.preparer().Prepare(context.Background()); got != encrypt.Prepared {
		t.Fatalf("rerun outcome %v", got)
	}
	plan, err := encrypt.ReadPlan(f.dev.layout)
	if err != nil || plan == nil {
		t.Fatal(err)
	}
	c := f.conversion()
	if c.Partition != partition || c.LUKSUUID == "" || c.LUKSUUID != plan.LUKSUUID || c.Mapping != plan.Mapping ||
		c.Layout != plan.Layout || c.DataBytes != plan.DataBytes {
		t.Fatalf("conversion %+v, plan %+v", c, plan)
	}
	if r := f.server.requests; len(r) != 1 || r[0].HasHeaderFields() {
		t.Fatalf("escrows %+v", r)
	}
	var prepared []any
	for _, e := range f.store.events {
		if e.typ == protocol.EventDiskConversionPrepared {
			prepared = append(prepared, e.data["volume"])
		}
	}
	if len(prepared) != 1 || prepared[0] != plan.LUKSUUID {
		t.Fatalf("disk.conversion_prepared volumes %v, want %s", prepared, plan.LUKSUUID)
	}
}

// TestIsLUKSWithoutPartition: invariant I1 — a conversion without a partition in the state is answered from plan.json:
// without a plan nothing is LUKS, with one its partition is checked, and an unreadable plan is unknown.
func TestIsLUKSWithoutPartition(t *testing.T) {
	f := newFixture(t)
	if luks, ok := encrypt.IsLUKS(context.Background(), f.dev, f.dev.layout, encrypt.Disk{}); luks || !ok {
		t.Fatalf("no plan: %v %v", luks, ok)
	}
	f.dev.Write("/var/lib/paddock/encrypt/plan.json", `{"conversion_id":"`+conversionID+`","partition":"`+partition+`"}`)
	f.dev.set(func(d *device) { d.luks = true })
	if luks, ok := encrypt.IsLUKS(context.Background(), f.dev, f.dev.layout, encrypt.Disk{}); !luks || !ok {
		t.Fatalf("plan with a LUKS partition: %v %v", luks, ok)
	}
	for name, content := range map[string]string{"unreadable": "{", "no partition": `{"conversion_id":"` + conversionID + `"}`} {
		f.dev.Write("/var/lib/paddock/encrypt/plan.json", content)
		if _, ok := encrypt.IsLUKS(context.Background(), f.dev, f.dev.layout, encrypt.Disk{}); ok {
			t.Fatalf("%s plan: answered", name)
		}
	}
}

// TestStateChangeWithItsEvent: Review 2, minor-4 — the phase change of step 9, of a failure and of an abort is saved
// with its event in one call: an agent that stops right after the change has still emitted it, and a save that fails
// changes nothing and emits nothing.
func TestStateChangeWithItsEvent(t *testing.T) {
	stopAfter := func(phase string) func(c *state.DiskConversion) bool {
		return func(c *state.DiskConversion) bool { return c.Phase == phase }
	}
	f := newFixture(t)
	f.store.goneAfter = stopAfter(state.ConversionPrepared)
	f.preparer().Prepare(context.Background())
	if types := f.store.types(); len(types) != 1 || types[0] != protocol.EventDiskConversionPrepared {
		t.Fatalf("prepared: events %v", types)
	}

	f = newFixture(t)
	f.server.statuses = []string{escrow.StatusFailed}
	f.store.goneAfter = stopAfter(state.ConversionFailed)
	f.preparer().Prepare(context.Background())
	if types := f.store.types(); len(types) != 1 || types[0] != protocol.EventDiskConversionFailed {
		t.Fatalf("failed: events %v", types)
	}

	f = preparedFixture(t)
	f.store.goneAfter = stopAfter(state.ConversionCancelled)
	if aborted, _ := encrypt.Abort(context.Background(), f.dev, f.dev.layout, f.store, "", encrypt.ByAdmin, false, nil); !aborted {
		t.Fatal("not aborted")
	}
	if types := f.store.types(); len(types) != 1 || types[0] != protocol.EventDiskConversionAborted {
		t.Fatalf("aborted: events %v", types)
	}

	f = preparedFixture(t)
	f.store.saveErr = func(*state.DiskConversion) error { return errors.New("disk full") }
	if aborted, reason := encrypt.Abort(context.Background(), f.dev, f.dev.layout, f.store, "", encrypt.ByAdmin, false, nil); aborted ||
		reason != encrypt.ReasonNotAbortable {
		t.Fatalf("save failed: %v %s", aborted, reason)
	}
	if c := f.conversion(); c.Phase != state.ConversionPrepared || len(f.store.events) != 0 || f.moduleGone() {
		t.Fatalf("save failed: %+v, events %v", c, f.store.types())
	}
}

// TestPrepareRecordsModuleWritten: step 7 records ModuleWritten before the first module file exists, so that a
// cleanup from then on verifies every initrd (invariant I3).
func TestPrepareRecordsModuleWritten(t *testing.T) {
	f := newFixture(t)
	f.store.beforeUpdate = func(c *state.DiskConversion) {
		if f.dev.Exists(encrypt.ModuleDir) && !c.ModuleWritten {
			t.Error("a module file exists before ModuleWritten was recorded")
		}
	}
	if got := f.preparer().Prepare(context.Background()); got != encrypt.Prepared || !f.conversion().ModuleWritten {
		t.Fatalf("outcome %v, %+v", got, f.conversion())
	}
}

// stoppedBeforePrepared is a fixture whose preparation stopped before step 9: the module is written and every initrd
// carries it and the key, the phase is still preparing.
func stoppedBeforePrepared(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	p := f.preparer()
	n := 0
	p.Hold = func(context.Context) error {
		if n++; n == 9 {
			return errors.New("agent stopped")
		}
		return nil
	}
	if got := p.Prepare(context.Background()); got != encrypt.Stopped || !f.dev.initrdCarriesModule(olderKernel) {
		t.Fatalf("outcome %v", got)
	}
	// The marker an agent before plan M8e amendment 2026-10-22 (item 22) armed at step 5.
	f.dev.Write("/var/lib/paddock/disk-setup-pending", "")
	return f
}

// TestPrepareRerunFailureKeepsCleanup: Review 3, major-1 — a rerun that fails before step 7 after step 7 completed in
// an earlier run records CleanupPending: the initrds still carry the module and the key (invariant I3).
func TestPrepareRerunFailureKeepsCleanup(t *testing.T) {
	f := stoppedBeforePrepared(t)
	_ = f.store.Update(func(c *state.DiskConversion, _ *state.LUKS) { c.TransientErrors = encrypt.TransientRetries })
	f.dev.set(func(d *device) { d.dpkgExit = 2 })
	if got := f.preparer().Prepare(context.Background()); got != encrypt.Failed {
		t.Fatalf("outcome %v", got)
	}
	c := f.conversion()
	if c.Phase != state.ConversionFailed || !c.CleanupPending || !f.dev.Exists("/var/lib/paddock/install-passphrase") ||
		!f.dev.initrdCarriesModule(runningKernel) {
		t.Fatalf("conversion %+v", c)
	}
}

// TestPrepareFailureOnLUKSPartition: Review 3, major-2 — a failing rerun never cleans up a partition that is LUKS
// (invariants I1 and I2): a partition that became LUKS while the failing step ran stops the preparation for the
// adoption without recording a failure; a header that became uncheckable records the failure with CleanupPending and
// keeps the key, the plan and the module.
func TestPrepareFailureOnLUKSPartition(t *testing.T) {
	for name, set := range map[string]func(d *device){
		"LUKS":    func(d *device) { d.incomplete, d.afterDracut = true, func(d *device) { d.luks = true } },
		"unknown": func(d *device) { d.incomplete, d.afterDracut = true, func(d *device) { d.luksExit = 4 } },
	} {
		f := stoppedBeforePrepared(t)
		f.dev.set(set)
		_ = f.store.Update(func(c *state.DiskConversion, _ *state.LUKS) { c.CleanupError = "an earlier reason" })
		got := f.preparer().Prepare(context.Background())
		c := f.conversion()
		for _, p := range append([]string{encrypt.ModuleDir, encrypt.ModuleConf}, leftovers...) {
			if !f.dev.Exists(p) {
				t.Errorf("%s: %s removed", name, p)
			}
		}
		if name == "LUKS" {
			if got != encrypt.Stopped || c.Phase != state.ConversionPreparing || len(f.store.events) != 0 {
				t.Fatalf("%s: outcome %v, %+v, events %v", name, got, c, f.store.types())
			}
			continue
		}
		if got != encrypt.Failed || c.Phase != state.ConversionFailed || !c.CleanupPending || c.CleanupError != "" {
			t.Fatalf("%s: outcome %v, %+v", name, got, c)
		}
	}
}

// TestPrepareFailureNotSaved: Review 3, major-3 — a failure whose save failed is not recorded: the preparation stops
// (the worker queues it again at the next full pass), stays preparing and cleans nothing up.
func TestPrepareFailureNotSaved(t *testing.T) {
	f := newFixture(t)
	f.dev.set(func(d *device) { d.incomplete = true })
	p := f.preparer()
	n := 0
	p.Hold = func(context.Context) error {
		if n++; n == 8 {
			f.store.saveErr = func(*state.DiskConversion) error { return errors.New("disk full") }
		}
		return nil
	}
	if got := p.Prepare(context.Background()); got != encrypt.Stopped {
		t.Fatalf("outcome %v", got)
	}
	if c := f.conversion(); c.Phase != state.ConversionPreparing || len(f.store.events) != 0 || f.moduleGone() {
		t.Fatalf("conversion %+v, events %v", c, f.store.types())
	}
}

// TestPrepareTransientToolError: Review 3, minor-5 — a tool error outside the closed set on a rerun (dpkg cannot
// answer) stops the preparation for a retry at the next full pass; it fails only once TransientRetries are used up.
func TestPrepareTransientToolError(t *testing.T) {
	f := stoppedBeforePrepared(t)
	f.dev.set(func(d *device) { d.dpkgExit = 2 })
	for i := 1; i <= encrypt.TransientRetries; i++ {
		if got := f.preparer().Prepare(context.Background()); got != encrypt.Stopped {
			t.Fatalf("retry %d: outcome %v", i, got)
		}
		if c := f.conversion(); c.Phase != state.ConversionPreparing || c.TransientErrors != i || len(f.store.events) != 0 {
			t.Fatalf("retry %d: %+v", i, c)
		}
	}
	if got := f.preparer().Prepare(context.Background()); got != encrypt.Failed {
		t.Fatalf("outcome %v", got)
	}
	if c := f.conversion(); c.Phase != state.ConversionFailed || !strings.HasPrefix(c.FailureReason, "dpkg-query dracut: exit 2") {
		t.Fatalf("conversion %+v", c)
	}

	f = stoppedBeforePrepared(t)
	f.dev.set(func(d *device) { d.dpkgExit = 2 })
	if got := f.preparer().Prepare(context.Background()); got != encrypt.Stopped {
		t.Fatalf("outcome %v", got)
	}
	f.dev.set(func(d *device) { d.dpkgExit = 0 })
	if got := f.preparer().Prepare(context.Background()); got != encrypt.Prepared {
		t.Fatalf("after the passing error: outcome %v %+v", got, f.conversion())
	}
}

// TestPrepareTestHooks: only a dev build marks the initrd for the test delays of the init script (plan M8e decision 19).
func TestPrepareTestHooks(t *testing.T) {
	for _, dev := range []bool{false, true} {
		f := newFixture(t)
		p := f.preparer()
		p.TestHooks = dev
		if got := p.Prepare(context.Background()); got != encrypt.Prepared {
			t.Fatalf("dev %v: outcome %v, conversion %+v", dev, got, f.conversion())
		}
		if f.dev.Exists("/var/lib/paddock/encrypt/test-hooks") != dev {
			t.Fatalf("dev %v: test-hooks written %v", dev, !dev)
		}
		if dev && (f.read("/var/lib/paddock/encrypt/test-hooks") != "" || f.mode("/var/lib/paddock/encrypt/test-hooks") != 0o600) {
			t.Fatal("test-hooks is not an empty root-only file")
		}
	}
}

// TestPrepareStopsOnConvertedPartition: PDK-367 — no step runs while the planned partition is LUKS or its header cannot
// be checked (invariants I1 and I2): the rerun stops before it rewrites the disk setup, rebuilds the initrds or records
// prepared, and the worker's adoption takes over.
func TestPrepareStopsOnConvertedPartition(t *testing.T) {
	for name, set := range map[string]func(d *device){
		"LUKS":    func(d *device) { d.luks = true },
		"unknown": func(d *device) { d.luksExit = 4 },
	} {
		f := stoppedBeforePrepared(t)
		if err := os.Remove(f.dev.Path("/var/lib/paddock/disk-setup-pending")); err != nil {
			t.Fatal(err)
		}
		rebuilds := f.longCalls("dracut -f --regenerate-all")
		f.dev.set(set)
		if got := f.preparer().Prepare(context.Background()); got != encrypt.Stopped {
			t.Fatalf("%s: outcome %v", name, got)
		}
		c := f.conversion()
		if c.Phase != state.ConversionPreparing || len(f.store.events) != 0 || f.longCalls("dracut -f --regenerate-all") != rebuilds ||
			f.dev.Exists("/var/lib/paddock/disk-setup-pending") {
			t.Fatalf("%s: a step ran: %+v, events %v", name, c, f.store.types())
		}
	}
}

// TestPrepareAbortDuringUnsavedFailure: PDK-367 — an abort requested while a step failed whose failure could not be
// saved runs (decision 27) instead of being answered not_abortable by the worker.
func TestPrepareAbortDuringUnsavedFailure(t *testing.T) {
	f := newFixture(t)
	failed := false
	f.dev.set(func(d *device) {
		d.incomplete = true
		d.afterDracut = func(*device) {
			f.store.mu.Lock()
			defer f.store.mu.Unlock()
			if f.store.saveErr != nil {
				return // the cleanup's rebuild
			}
			f.store.c.AbortRequested = true
			f.store.saveErr = func(*state.DiskConversion) error {
				if failed {
					return nil
				}
				failed = true
				return errors.New("disk full")
			}
		}
	})
	if got := f.preparer().Prepare(context.Background()); got != encrypt.Aborted {
		t.Fatalf("outcome %v, %+v", got, f.conversion())
	}
	if c := f.conversion(); !failed || c.Phase != state.ConversionCancelled || c.AbortRequested {
		t.Fatalf("conversion %+v", c)
	}
	if types := f.store.types(); len(types) != 1 || types[0] != protocol.EventDiskConversionAborted {
		t.Fatalf("events %v", types)
	}
}

// TestPrepareAbortDuringTransientError: PDK-366 — an abort requested while a step ended on a transient tool error
// (dpkg cannot answer at step 6) runs instead of the retry.
func TestPrepareAbortDuringTransientError(t *testing.T) {
	f := newFixture(t)
	p := f.preparer()
	n := 0
	p.Hold = func(context.Context) error {
		if n++; n == 6 {
			f.dev.set(func(d *device) { d.dpkgExit = 2 })
			f.store.beforeUpdate = func(c *state.DiskConversion) {
				if c.TransientErrors == 0 && c.Phase == state.ConversionPreparing {
					c.AbortRequested = true
				}
			}
		}
		return nil
	}
	if got := p.Prepare(context.Background()); got != encrypt.Aborted {
		t.Fatalf("outcome %v, %+v", got, f.conversion())
	}
	c := f.conversion()
	if c.Phase != state.ConversionCancelled || c.AbortRequested || c.TransientErrors != 1 {
		t.Fatalf("conversion %+v", c)
	}
	if types := f.store.types(); len(types) != 1 || types[0] != protocol.EventDiskConversionAborted {
		t.Fatalf("events %v", types)
	}
}
