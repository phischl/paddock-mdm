package encrypt

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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
// never undoes an initialised header).
func Abort(ctx context.Context, sys Host, l paths.Layout, store Store, id, by string, preparing bool) (aborted bool, reason string) {
	c, ok := store.Conversion()
	if !ok || (id != "" && c.ID != id) {
		return false, ReasonUnknownConversion
	}
	if c.Phase != state.ConversionPrepared && (!preparing || c.Phase != state.ConversionPreparing) {
		return false, ReasonNotAbortable
	}
	if luksOrUnknown(ctx, sys, l, c.Partition) {
		return false, ReasonNotAbortable
	}
	if err := store.Transition(func(c *state.DiskConversion, _ *state.LUKS) *Event {
		c.Phase, c.AbortRequested, c.CleanupPending, c.Notified = state.ConversionCancelled, false, true, nil
		return &Event{protocol.EventDiskConversionAborted, map[string]any{"conversion_id": c.ID, "by": by}}
	}); err != nil {
		slog.ErrorContext(ctx, "recording the abort of the in-place encryption failed", "error", err)
		return false, ReasonNotAbortable
	}
	slog.InfoContext(ctx, "in-place encryption aborted", "conversion_id", c.ID, "by", by)
	RunCleanup(ctx, sys, l, store)
	return true, ""
}

// RunCleanup runs Cleanup and clears CleanupPending once it is done; a failure is logged and the next full pass
// retries (invariant I3). The caller has checked that the partition is not LUKS (invariant I1).
func RunCleanup(ctx context.Context, sys Host, l paths.Layout, store Store) {
	c, ok := store.Conversion()
	done, err := Cleanup(ctx, sys, l, !ok || c.ModuleWritten)
	if !done {
		slog.WarnContext(ctx, "cleanup of the in-place encryption unfinished; retrying at the next full pass", "error", err)
		return
	}
	if err := store.Update(func(c *state.DiskConversion, _ *state.LUKS) { c.CleanupPending = false }); err != nil {
		slog.ErrorContext(ctx, "recording the finished cleanup failed", "error", err)
	}
}

// Cleanup removes what a preparation left, in the binding order of plan M8e decision 14 (review round 4, X1) under
// invariant I3: (1) only the module directory and its dracut configuration; (2) dracut -f --regenerate-all; (3) the
// initrd of every installed kernel must show no paddock-encrypt; (4) only then the conversion key, plan.json, plan.env,
// test-hooks and the two disk-setup files. done is true once (4) ran. While (2) or (3) fails the key and the plan stay:
// an initrd that still carries the module converts the disk at the next boot, which then needs them (I2 adoption).
// (2) and (3) are skipped only when step 7 never started (moduleWritten false and no module file found at (1)): no
// initrd can carry the module then. Otherwise (3) always runs, because the dpkg status of dracut cannot tell what an
// initrd carries: on 24.04 dracut and lsinitrd stay in dracut-core when dracut goes to rc, and another initramfs tool
// rebuilds only the newest kernel's image. (2) runs while dpkg reports dracut installed; with any other status the
// initrds are only verified. While dpkg cannot tell (an error, or an upgrade under way) or no tool can list an
// initrd, nothing after (1) runs.
func Cleanup(ctx context.Context, sys Host, l paths.Layout, moduleWritten bool) (done bool, err error) {
	for _, p := range []string{l.Join(ModuleDir), l.Join(ModuleConf)} {
		if _, err := os.Lstat(p); err == nil {
			moduleWritten = true
		}
		if err := os.RemoveAll(p); err != nil {
			return false, err
		}
	}
	if moduleWritten {
		installed, err := dracutInstalled(ctx, sys)
		if err != nil {
			return false, err
		}
		if installed {
			if err := regenerate(ctx, sys); err != nil {
				return false, err
			}
		}
		carrying, err := initrdsWithModule(ctx, sys, l)
		if err != nil {
			return false, err
		}
		if len(carrying) > 0 {
			return false, fmt.Errorf("the initrd of %s still carries %s", strings.Join(carrying, ", "), moduleName)
		}
	}
	if err := shred(l.InstallPassphrase()); err != nil {
		return false, err
	}
	for _, p := range []string{l.EncryptPlan(), l.EncryptPlanEnv(), l.EncryptTestHooks(), l.EncryptDir(), l.DiskSetupConfig(),
		l.DiskSetupPending()} {
		if err := os.RemoveAll(p); err != nil {
			return false, err
		}
	}
	return true, nil
}

// initrdListers list the files of an initrd: dracut's (dracut-core), else initramfs-tools' (initramfs-tools-core).
var initrdListers = []string{"lsinitrd", "lsinitramfs"}

// initrdMarkers are what the listing of an initrd carrying the conversion shows: the module (lsinitrd names it; its
// unit is named after it), the key and the plan.
var initrdMarkers = []string{moduleName, "etc/paddock/encrypt-key", "etc/paddock/encrypt-plan.env"}

// initrdsWithModule returns the kernel versions whose initrd lists the module, the key or the plan. The installed
// kernels are every <v> with /boot/vmlinuz-<v> or /lib/modules/<v> — every GRUB entry (plan M8e §14.10); a kernel
// without an initrd has none that could carry anything. It fails when an initrd exists and no lister is installed or
// a listing fails: an initrd that was not read is no initrd without the module.
func initrdsWithModule(ctx context.Context, sys System, l paths.Layout) ([]string, error) {
	var carrying []string
	listers := initrdListers
	for _, v := range installedKernels(l) {
		initrd := l.Join("/boot/initrd.img-" + v)
		if _, err := os.Stat(initrd); errors.Is(err, os.ErrNotExist) {
			continue
		}
		out, err := listInitrd(ctx, sys, &listers, initrd)
		if err != nil {
			return nil, err
		}
		if slices.ContainsFunc(initrdMarkers, func(m string) bool { return strings.Contains(out, m) }) {
			carrying = append(carrying, v)
		}
	}
	return carrying, nil
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
			err = fmt.Errorf("%s %s: exit %d: %s", name, initrd, exit, firstLine(stderr))
		}
		return out, err
	}
	return "", fmt.Errorf("no tool to list %s (%s)", initrd, strings.Join(initrdListers, ", "))
}

// installedKernels lists the kernel versions of /boot/vmlinuz-* and /lib/modules/*, without duplicates.
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
	return out
}

// luksOrUnknown reports whether partition carries a LUKS header or cryptsetup could not tell: nothing of the unlock
// path is removed on a guess (invariant I1).
func luksOrUnknown(ctx context.Context, sys System, l paths.Layout, partition string) bool {
	luks, ok := IsLUKS(ctx, sys, l, partition)
	return luks || !ok
}

// IsLUKS reports whether the conversion's partition carries a LUKS header (cryptsetup isLuks); ok is false when
// cryptsetup could not tell. Without a partition in the state the answer comes from plan.json, which step 2 writes
// before the state: without plan.json no partition was ever planned and nothing is LUKS; a plan that cannot be read
// or names no partition is unknown (invariant I1).
func IsLUKS(ctx context.Context, sys System, l paths.Layout, partition string) (luks, ok bool) {
	if partition == "" {
		plan, err := ReadPlan(l)
		switch {
		case err == nil && plan == nil:
			return false, true
		case err != nil || plan.Partition == "":
			return false, false
		}
		partition = plan.Partition
	}
	// isLuks exits 1 for a device it cannot open as well (agent/internal/luks/crypttab.go): only a partition that
	// exists makes exit 1 mean "not LUKS" — a by-partuuid link udev has not created yet is no answer.
	if exists, err := sys.Stat(l.Join(partition)); err != nil || !exists {
		return false, false
	}
	_, _, exit, err := sys.Command(ctx, "cryptsetup", "isLuks", partition)
	if err != nil || (exit != 0 && exit != 1) {
		return false, false
	}
	return exit == 0, true
}

// shred overwrites a key file with zeros and flushes them before it removes it; a missing file is no error.
func shred(path string) error {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0) //nolint:gosec // a key path of the agent layout
	if err != nil {
		return err
	}
	_, werr := f.Write(make([]byte, info.Size()))
	if werr == nil {
		werr = f.Sync()
	}
	if err := errors.Join(werr, f.Close()); err != nil {
		return err
	}
	return os.Remove(path)
}
