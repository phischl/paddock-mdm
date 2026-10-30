package encrypt

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/phischl/paddock-mdm/agent/internal/paths"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// Who asked for an abort (event disk.conversion_aborted, param by).
const (
	ByAdmin    = "admin"
	ByOperator = "operator"
)

// Refusals of an abort (command.EncryptDiskAbortResult.Reason).
const (
	ReasonUnknownConversion = "unknown_conversion"
	ReasonNotAbortable      = "not_abortable"
)

// Store is the agent state a preparation, an abort or a cleanup reads and changes. The agent's run loop owns the
// state, so an implementation may hand every call over to it.
type Store interface {
	// Conversion returns a copy of the conversion; false without one.
	Conversion() (state.DiskConversion, bool)
	// Update applies fn to the conversion and the LUKS state and saves the state; it fails without a conversion.
	Update(fn func(c *state.DiskConversion, l *state.LUKS)) error
	// Transition is Update for a change that emits a device event: fn returns the event (nil for none), which is spooled
	// in the same call on the owner of the state once the state is saved. When the save fails, the state stays as it
	// was and nothing is emitted, so a phase change and its event are never recorded apart.
	Transition(fn func(c *state.DiskConversion, l *state.LUKS) *Event) error
}

// Event is a device event a state change emits.
type Event struct {
	Type string
	Data map[string]any
}

// Abort abandons a conversion before its restart (plan M8e decisions 14 and 27): the phase becomes cancelled, the
// event disk.conversion_aborted{by} is emitted once, and the cleanup of invariant I3 runs (Cleanup; CleanupPending
// stays set until it is done and is retried at every full pass). id "" accepts the device's conversion whatever its
// ID. It refuses with unknown_conversion and not_abortable: a phase other than prepared (preparing only when
// preparing is true, the conversion worker's own abort) or a partition that is LUKS already (invariant I1: the device
// never undoes an initialised header). Before the cleanup the initrds are disarmed (Disarm); report receives its
// outcome (nil: ReportNeutralizeFailed for a failure).
func Abort(ctx context.Context, sys Host, l paths.Layout, store Store, id, by string, preparing bool,
	report NeutralizeReport) (aborted bool, reason string) {
	c, ok := store.Conversion()
	if !ok || (id != "" && c.ID != id) {
		return false, ReasonUnknownConversion
	}
	if c.Phase != state.ConversionPrepared && (!preparing || c.Phase != state.ConversionPreparing) {
		return false, ReasonNotAbortable
	}
	if luksOrUnknown(ctx, sys, l, DiskOf(c)) {
		return false, ReasonNotAbortable
	}
	if err := store.Transition(func(c *state.DiskConversion, _ *state.LUKS) *Event {
		c.Phase, c.AbortRequested, c.CleanupPending, c.CleanupError, c.Notified = state.ConversionCancelled, false, true, "", nil
		c.PackagesBusySince = nil
		return &Event{protocol.EventDiskConversionAborted, map[string]any{"conversion_id": c.ID, "by": by}}
	}); err != nil {
		slog.ErrorContext(ctx, "recording the abort of the in-place encryption failed", "error", err)
		return false, ReasonNotAbortable
	}
	slog.InfoContext(ctx, "in-place encryption aborted", "conversion_id", c.ID, "by", by)
	neutralize(ctx, sys, l, store, report)
	// Synchronous even while supervisor-upgrade.json exists (plan M8e item 18, amendment 2026-10-28, PDK-378): the
	// initrds are built into temporary files, so a rollback restart killing this leaves only those and CleanupPending,
	// which the worker completes once the upgrade is over.
	_, _ = RunCleanup(ctx, sys, l, store) // logged; a later full pass retries
	return true, ""
}

// NeutralizeReport receives the outcome of a Disarm: nil after one that succeeded or had nothing to do. The agent
// reports a failure once per reason and start (review 2 of PDK-482, X3).
type NeutralizeReport func(ctx context.Context, err error)

// neutralize disarms the initrds of an aborted or failed conversion before the cleanup rebuilds them, which can fail,
// be killed or wait for dpkg's locks (Disarm; plan M8e item 18, amendment 2026-10-30, PDK-482 and PDK-579). The
// outcome goes to report, a failure without one to disk.conversion_neutralize_failed; the cleanup runs regardless.
func neutralize(ctx context.Context, sys Host, l paths.Layout, store Store, report NeutralizeReport) {
	err := Disarm(ctx, sys, l, store)
	switch {
	case report != nil:
		report(ctx, err)
	case err != nil:
		_ = ReportNeutralizeFailed(ctx, store, err)
	}
}

// moduleFilesPresent reports whether the module directory or its dracut configuration exists.
func moduleFilesPresent(l paths.Layout) bool {
	for _, p := range []string{l.Join(ModuleConf), l.Join(ModuleDir)} {
		if _, err := os.Lstat(p); err == nil {
			return true
		}
	}
	return false
}

// RunCleanup runs Cleanup and clears CleanupPending once it is done, and reports whether it did and why not
// (ErrPackagesBusy: a package run held dpkg's locks); the reason is logged at warning level and a later full pass
// retries (invariant I3). The caller has checked that the partition is not LUKS (invariant I1).
func RunCleanup(ctx context.Context, sys Host, l paths.Layout, store Store) (done bool, err error) {
	c, ok := store.Conversion()
	done, orphans, err := Cleanup(ctx, sys, l, !ok || c.ModuleWritten)
	if len(orphans) > 0 {
		if uerr := store.Update(func(c *state.DiskConversion, _ *state.LUKS) { c.InitrdIssue = IssueOrphanInitrdRemoved }); uerr != nil {
			slog.ErrorContext(ctx, "recording the removed orphan initrds failed", "error", uerr)
		}
	}
	if !done {
		slog.WarnContext(ctx, "cleanup of the in-place encryption unfinished; retrying later", "reason", err)
		reason := ""
		if err != nil {
			reason = firstLine(err.Error())
		}
		var hardlinked *KeyMaterialHardlinkedError
		var shared *KeySharedBootableError
		if uerr := store.Update(func(c *state.DiskConversion, _ *state.LUKS) {
			c.CleanupError = reason
			switch {
			case errors.As(err, &shared):
				c.InitrdIssue, c.BootSpaceNeeded, c.BootSpaceFree, c.InitrdIssueKernel = IssueKeyMaterialSharedBootable, 0, 0, shared.Kernel
			case errors.As(err, &hardlinked):
				c.InitrdIssue, c.BootSpaceNeeded, c.BootSpaceFree, c.InitrdIssueKernel = IssueKeyMaterialHardlinked, 0, 0, ""
			case c.InitrdIssue == IssueKeyMaterialHardlinked || c.InitrdIssue == IssueKeyMaterialSharedBootable:
				c.InitrdIssue, c.InitrdIssueKernel = "", ""
			}
		}); uerr != nil {
			slog.ErrorContext(ctx, "recording the reason of the unfinished cleanup failed", "error", uerr)
		}
		return false, err
	}
	if err := store.Update(func(c *state.DiskConversion, _ *state.LUKS) {
		c.CleanupPending, c.CleanupError = false, ""
		// orphan_initrd_removed stays until the conversion ends (amendment item 19(g)); every other issue is over.
		if c.InitrdIssue != IssueOrphanInitrdRemoved {
			c.InitrdIssue = ""
		}
		c.BootSpaceNeeded, c.BootSpaceFree, c.InitrdIssueKernel = 0, 0, ""
	}); err != nil {
		slog.ErrorContext(ctx, "recording the finished cleanup failed", "error", err)
		return false, err
	}
	return true, nil
}

// Cleanup removes what a preparation left, in the binding order of plan M8e decision 14 (review round 4, X1) under
// invariant I3: (1) only the module directory and its dracut configuration; (2) every bootable kernel's initrd rebuilt
// into a temporary file, verified without the module and renamed into place (rebuildInitrds); (3) the
// initrd of every installed kernel must show no paddock-encrypt; (4) only then the conversion key, plan.json, plan.env,
// test-hooks and the two disk-setup files. done is true once (4) ran. While (2) or (3) fails the key and the plan stay:
// an initrd that still carries the module converts the disk at the next boot, which then needs them (I2 adoption).
// (2) and (3) are skipped only when step 7 never started (moduleWritten false and no module file found at (1)): no
// initrd can carry the module then. Otherwise (3) always runs, because the dpkg status of dracut cannot tell what an
// initrd carries: on 24.04 dracut and lsinitrd stay in dracut-core when dracut goes to rc, and another initramfs tool
// rebuilds only the newest kernel's image. Steps (1) to (4) hold dpkg's locks (Host.LockPackages; busy: the next full
// pass retries), so that no kernel package rebuilds an initrd with the module after (3). (2) runs while dpkg reports
// dracut installed; with any other status the
// initrds are only verified. While dpkg cannot tell (an error, or an upgrade under way) or no tool can list an
// initrd, nothing after (1) runs.
func Cleanup(ctx context.Context, sys Host, l paths.Layout, moduleWritten bool) (done bool, orphans []string, err error) {
	unlock, err := sys.LockPackages()
	if err != nil {
		return false, nil, err
	}
	defer unlock()
	// The configuration first: without the module directory it would fail every dracut run (dracut exits on a module
	// it cannot find), a kernel package's included.
	for _, p := range []string{l.Join(ModuleConf), l.Join(ModuleDir)} {
		if _, err := os.Lstat(p); err == nil {
			moduleWritten = true
		}
		if err := os.RemoveAll(p); err != nil {
			return false, orphans, err
		}
	}
	if moduleWritten {
		installed, err := dracutInstalled(ctx, sys)
		if err != nil {
			return false, orphans, err
		}
		if installed {
			listers := initrdListers
			if err := rebuildInitrds(ctx, sys, l, func(initrd string) error {
				out, err := listInitrd(ctx, sys, &listers, initrd)
				if err == nil && carriesModule(out) {
					err = fmt.Errorf("it carries %s", moduleName)
				}
				return err
			}); err != nil {
				return false, orphans, err
			}
		}
		carrying, unreadable, err := initrdsWithModule(ctx, sys, l)
		if err != nil {
			return false, orphans, err
		}
		// One pass over both, so that names of one file are removed together (amendment item 19, rule B).
		if carrying, orphans, err = removeOrphans(ctx, l, append(carrying, slices.Sorted(maps.Keys(unreadable))...)); err != nil {
			return false, orphans, err
		}
		for _, v := range orphans {
			if lerr, ok := unreadable[v]; ok {
				slog.WarnContext(ctx, "removed an unreadable initrd of no kernel", "file", "/boot/initrd.img-"+v, "listing", lerr)
			}
		}
		if len(carrying) > 0 {
			return false, orphans, fmt.Errorf("the initrd of %s still carries %s", strings.Join(carrying, ", "), moduleName)
		}
	}
	if err := removeTemps(l); err != nil {
		return false, orphans, err
	}
	if left, _ := filepath.Glob(l.Join(tempInitrd("*"))); len(left) > 0 {
		return false, orphans, fmt.Errorf("temporary initrds left in /boot: %s", strings.Join(left, ", "))
	}
	if err := shred(l.InstallPassphrase()); err != nil {
		return false, orphans, err
	}
	for _, p := range []string{l.EncryptPlan(), l.EncryptPlanEnv(), l.EncryptTestHooks(), l.EncryptDir(), l.DiskSetupConfig(),
		l.DiskSetupPending()} {
		if err := os.RemoveAll(p); err != nil {
			return false, orphans, err
		}
	}
	return true, orphans, nil
}

// removeOrphans removes, from the kernels whose initrd carries the module, the initrds of kernels dracut can never
// rebuild (no /lib/modules/<v>/modules.dep, so no boot either): they would keep the conversion key on the unencrypted
// /boot for good (amendment 2026-10-21, item 19(g)). Each is overwritten before it is unlinked. It returns the kernels
// that still carry the module and the orphans removed.
func removeOrphans(ctx context.Context, l paths.Layout, carrying []string) (still, orphans []string, err error) {
	bootable := bootableKernels(l)
	var names []string
	for _, v := range carrying {
		if slices.Contains(bootable, v) {
			still = append(still, v)
			continue
		}
		slog.WarnContext(ctx, "removing the initrd of a kernel without modules: it carries the conversion key", "kernel", v)
		names = append(names, l.Join("/boot/initrd.img-"+v))
	}
	removed, err := removeInitrdNames(ctx, l, names)
	for _, name := range names {
		v := strings.TrimPrefix(filepath.Base(name), "initrd.img-")
		if slices.Contains(removed, name) {
			orphans = append(orphans, v)
		} else {
			// Kept: a symlink to a file Paddock does not list, or a file rule B keeps (amendment item 19).
			still = append(still, v)
		}
	}
	return still, orphans, err
}

// initrdListers list the files of an initrd: dracut's (dracut-core), else initramfs-tools' (initramfs-tools-core).
var initrdListers = []string{"lsinitrd", "lsinitramfs"}

// initrdMarkers are what the listing of an initrd carrying the conversion shows: the module (lsinitrd names it; its
// unit is named after it), the key and the plan.
var initrdMarkers = []string{moduleName, "etc/paddock/encrypt-key", "etc/paddock/encrypt-plan.env"}

// carriesModule reports whether an lsinitrd listing shows a marker. The "Arguments:" line is dracut's command line
// (build-parameter.txt), which names the module when it was omitted with --omit, and is no content (review 2 of
// PDK-245, B2).
func carriesModule(listing string) bool {
	for line := range strings.Lines(listing) {
		if strings.HasPrefix(strings.TrimSpace(line), "Arguments:") {
			continue
		}
		if slices.ContainsFunc(initrdMarkers, func(m string) bool { return strings.Contains(line, m) }) {
			return true
		}
	}
	return false
}

// initrdsWithModule returns the kernel versions whose initrd lists the module, the key or the plan. The installed
// kernels are every <v> with /boot/vmlinuz-<v> or /lib/modules/<v> — every GRUB entry (plan M8e §14.10); a kernel
// without an initrd has none that could carry anything. It fails when an initrd exists and no lister is installed or
// a listing fails: an initrd that was not read is no initrd without the module.
func initrdsWithModule(ctx context.Context, sys System, l paths.Layout) (carrying []string, unreadable map[string]error, err error) {
	listers := initrdListers
	for _, v := range installedKernels(l) {
		initrd := l.Join("/boot/initrd.img-" + v)
		if _, err := os.Stat(initrd); errors.Is(err, os.ErrNotExist) {
			continue
		}
		out, err := listInitrd(ctx, sys, &listers, initrd)
		if err != nil {
			// A stray file no kernel boots (a remnant, a truncated build) is an orphan even unread (item 19(i)); a
			// bootable kernel's initrd that cannot be read stays an error.
			if stray(l, v) && !errors.Is(err, errNoLister) {
				if unreadable == nil {
					unreadable = map[string]error{}
				}
				unreadable[v] = err
				continue
			}
			return nil, nil, err
		}
		if carriesModule(out) {
			carrying = append(carrying, v)
		}
	}
	return carrying, unreadable, nil
}

// stray reports whether v has no kernel image (vmlinuz, vmlinux, kernel, or a kept vmlinuz-<v>.old), no modules.dep
// and no modules.dep.bin: no boot entry uses its initrd.
func stray(l paths.Layout, v string) bool {
	for _, p := range []string{"/boot/vmlinuz-" + v, "/boot/vmlinux-" + v, "/boot/kernel-" + v, "/boot/vmlinuz-" + v + ".old",
		"/lib/modules/" + v + "/modules.dep", "/lib/modules/" + v + "/modules.dep.bin"} {
		if _, err := os.Stat(l.Join(p)); err == nil {
			return false
		}
	}
	return true
}

// listInitrd lists initrd with the first of listers that is installed; listers not installed are dropped from it.
func listInitrd(ctx context.Context, sys System, listers *[]string, initrd string) (string, error) {
	for len(*listers) > 0 {
		name := (*listers)[0]
		out, stderr, exit, err := sys.Command(ctx, name, initrd)
		if errors.Is(err, exec.ErrNotFound) {
			*listers = (*listers)[1:]
			continue
		}
		if err == nil && exit != 0 {
			// initramfs-tools' lister stops at the segment a neutralized initrd ends with (PDK-482); such an initrd
			// carries the cancelled plan at initrdPlanPath, a marker, whatever its main archive holds.
			if neutralized(initrd) {
				return initrdPlanPath + "\n", nil
			}
			err = fmt.Errorf("%s %s: exit %d: %s", name, initrd, exit, firstLine(stderr))
		}
		return out, err
	}
	return "", fmt.Errorf("%w: %s (%s)", errNoLister, initrd, strings.Join(initrdListers, ", "))
}

// errNoLister is no tool to list an initrd: nothing is known about any initrd then, not even a stray one.
var errNoLister = errors.New("no tool to list an initrd")

// installedKernels lists the kernel versions of /boot/vmlinuz-*, /lib/modules/* and the regular files
// /boot/initrd.img-*, without duplicates.
func installedKernels(l paths.Layout) []string {
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	images, _ := filepath.Glob(l.Join("/boot/vmlinuz-*"))
	for _, img := range images {
		add(strings.TrimPrefix(filepath.Base(img), "vmlinuz-"))
	}
	entries, _ := os.ReadDir(l.Join("/lib/modules"))
	for _, e := range entries {
		if e.IsDir() {
			add(e.Name())
		}
	}
	// An initrd of a kernel removed without its initrd still carries what it carries (amendment 2026-10-21, item
	// 19(i)); symlinks such as initrd.img-<v> pointing elsewhere are no initrd of their own.
	initrds, _ := filepath.Glob(l.Join("/boot/initrd.img-*"))
	for _, f := range initrds {
		if info, err := os.Lstat(f); err == nil && info.Mode().IsRegular() {
			add(strings.TrimPrefix(filepath.Base(f), "initrd.img-"))
		}
	}
	return out
}

// luksOrUnknown reports whether the conversion's partition carries a LUKS header or the disk could not tell: nothing
// of the unlock path is removed on a guess (invariant I1).
func luksOrUnknown(ctx context.Context, sys System, l paths.Layout, d Disk) bool {
	luks, ok := IsLUKS(ctx, sys, l, d)
	return luks || !ok
}

// Disk names the conversion's partition and what the conversion would make of it: the mapping and the LUKS UUID.
type Disk struct {
	Partition, Mapping, LUKSUUID string
}

// DiskOf is the Disk of a conversion state.
func DiskOf(c state.DiskConversion) Disk {
	return Disk{Partition: c.Partition, Mapping: c.Mapping, LUKSUUID: c.LUKSUUID}
}

// IsLUKS reports whether the conversion's partition carries a LUKS header; ok is false when the disk does not tell for
// sure. LUKS is cryptsetup isLuks exiting 0. "Not LUKS" — on which a cleanup may remove the unlock path (invariants
// I1 and I3) — needs positive evidence on all counts (amendment 2026-10-21, item 13): the conversion's mapping is not
// active, no /dev/disk/by-uuid/<luks uuid> exists, blkid names exactly one device with the PARTUUID (a cloned disk
// plugged in makes the link ambiguous), and isLuks exits exactly 1 on the partition. Anything else is unknown. Without
// a partition, a mapping or a LUKS UUID in d the plan supplies them; without plan.json and a partition no conversion
// was ever planned and nothing is LUKS; a plan that cannot be read or lacks them is unknown.
func IsLUKS(ctx context.Context, sys System, l paths.Layout, d Disk) (luks, ok bool) {
	if d.Partition == "" || d.Mapping == "" || d.LUKSUUID == "" {
		plan, err := ReadPlan(l)
		switch {
		case err == nil && plan == nil && d.Partition == "":
			return false, true
		case err == nil && plan != nil:
			d.Partition, d.Mapping, d.LUKSUUID = cmp.Or(d.Partition, plan.Partition), cmp.Or(d.Mapping, plan.Mapping),
				cmp.Or(d.LUKSUUID, plan.LUKSUUID)
		}
	}
	// isLuks exits 1 for a device it cannot open as well (agent/internal/luks/crypttab.go): only a partition that
	// exists makes exit 1 mean "not LUKS" — a by-partuuid link udev has not created yet is no answer.
	if d.Partition == "" {
		return false, false
	}
	if exists, err := sys.Stat(l.Join(d.Partition)); err != nil || !exists {
		return false, false
	}
	_, _, exit, err := sys.Command(ctx, "cryptsetup", "isLuks", d.Partition)
	switch {
	case err != nil || (exit != 0 && exit != 1):
		return false, false
	case exit == 0:
		return true, true
	}
	if d.Mapping == "" || d.LUKSUUID == "" {
		return false, false
	}
	for _, p := range []string{"/dev/mapper/" + d.Mapping, "/dev/disk/by-uuid/" + d.LUKSUUID} {
		if exists, err := sys.Stat(l.Join(p)); err != nil || exists {
			return false, false
		}
	}
	partUUID := strings.TrimPrefix(d.Partition, "/dev/disk/by-partuuid/")
	if partUUID == d.Partition || partUUID == "" {
		return false, false
	}
	out, _, exit, err := sys.Command(ctx, "blkid", "-o", "device", "-t", "PARTUUID="+partUUID)
	if err != nil || exit != 0 || len(strings.Fields(out)) != 1 {
		return false, false
	}
	return false, true
}
