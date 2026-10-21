package encrypt

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/fsutil"
	"github.com/phischl/paddock-mdm/agent/internal/luks"
	"github.com/phischl/paddock-mdm/agent/internal/paths"
)

// crypttabPath is the host's crypttab, which dracut copies into the initrd (plan M8e decision 20).
const crypttabPath = "/etc/crypttab"

// RegenerateInitrd replaces the module's unlock path of a converted disk by the TPM keyslot (plan M8e decision 20 as
// amended on 2026-10-21, items 7, 8, 14, 16 and 19), in the order of invariant I1 — no working initrd is ever
// replaced by one that was not verified: (1) /etc/crypttab gains "<mapping> UUID=<luks uuid> none luks,tpm2-device=auto"
// unless a line names the volume; (2) one kernel after the other, a new initrd is built without the module into a
// temporary file next to the current one (when /boot has room for it) and verified — the crypttab line for the
// volume, systemd-cryptsetup and the TPM2 libraries, nothing of paddock-encrypt — and, under dpkg's locks and only
// when that kernel's current initrd did not change since its build started (a kernel package's own dracut run),
// renamed into place and verified once more; (3) under the locks, when no kernel was added or removed and every
// initrd passes the verification again, the module's configuration and directory, test-hooks and plan.json are
// removed, plan.env last. The builds run without the locks, so that apt waits at most for a rename and its checks.
// While a step fails, or ctx ends (a revocation hand-over), the initrds not replaced yet keep the module and the key,
// nothing leaves the host, and the caller retries later; a replaced one unlocks through the TPM. plan.json goes only
// with removePlan: the background helper of a conversion still encrypting reads it (decision 21), so it then stays
// until the conversion is cleared. The caller has checked that a TPM keyslot exists. The conversion key stays: the
// luks reconciler removes it once the regeneration is recorded (decision 3).
func RegenerateInitrd(ctx context.Context, sys Host, l paths.Layout, mapping, luksUUID string, removePlan bool) error {
	if !envValue.MatchString(mapping) || !envValue.MatchString(luksUUID) {
		return fmt.Errorf("no valid mapping %q or LUKS UUID %q", mapping, luksUUID)
	}
	if err := addCrypttabLine(l, mapping, luksUUID); err != nil {
		return err
	}
	kernels := bootableKernels(l)
	if len(kernels) == 0 {
		return ErrNoBootableKernel
	}
	if err := checkBuildable(l, kernels); err != nil {
		return err
	}
	// A package run holding the locks now would make the builds below useless: probe them first (they are taken
	// again for each rename). Under the probe, temporary files a killed run left go (item 19(j)).
	probe, err := sys.LockPackages()
	if err != nil {
		return err
	}
	err = removeTemps(l)
	probe()
	if err != nil {
		return err
	}
	verify := func(initrd string) error { return verifyInitrd(ctx, sys, initrd, luksUUID) }
	for _, v := range kernels {
		before := stampOf(l, v)
		tmp, err := buildInitrd(ctx, sys, l, v, []string{"--omit", moduleName}, verify)
		if err != nil {
			return err
		}
		if err := replaceInitrd(ctx, sys, l, v, tmp, before, luksUUID); err != nil {
			return err
		}
	}
	unlock, err := sys.LockPackages()
	if err != nil {
		return err
	}
	defer unlock()
	if now := bootableKernels(l); !slices.Equal(now, kernels) {
		return fmt.Errorf("the installed kernels changed during the rebuild (%v, now %v)", kernels, now)
	}
	for _, v := range kernels {
		if err := verifyInitrd(context.WithoutCancel(ctx), sys, l.Join("/boot/initrd.img-"+v), luksUUID); err != nil {
			return fmt.Errorf("the initrd of %s: %w", v, err)
		}
	}
	if err := removeTemps(l); err != nil {
		return err
	}
	files := []string{l.Join(ModuleConf), l.Join(ModuleDir), l.EncryptTestHooks()}
	if removePlan {
		files = append(files, l.EncryptPlan())
	}
	for _, p := range append(files, l.EncryptPlanEnv()) {
		if err := os.RemoveAll(p); err != nil {
			return err
		}
	}
	return nil
}

// replaceInitrd renames tmp over kernel v's initrd under dpkg's locks, when the current one is unchanged since before
// (its stamp) and ctx did not end, and verifies the result; a failure removes tmp (discardTemp).
func replaceInitrd(ctx context.Context, sys Host, l paths.Layout, v, tmp string, before initrdStamp, luksUUID string) error {
	unlock, err := sys.LockPackages()
	if err != nil {
		discardTemp(ctx, l, tmp)
		return err
	}
	defer unlock()
	// Deferred after unlock, so it runs before it: the removal holds the locks.
	defer discardTemp(ctx, l, tmp)
	if stampOf(l, v) != before {
		return fmt.Errorf("the initrd of %s changed during the rebuild", v)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(tmp, l.Join("/boot/initrd.img-"+v)); err != nil {
		return err
	}
	if err := fsutil.SyncDir(l.Join("/boot")); err != nil {
		return err
	}
	if err := verifyInitrd(context.WithoutCancel(ctx), sys, l.Join("/boot/initrd.img-"+v), luksUUID); err != nil {
		return fmt.Errorf("the initrd of %s: %w", v, err)
	}
	return nil
}

// ErrNoBootableKernel is an initrd rebuild that found no kernel dracut --regenerate-all would build: the step stays
// pending and is retried with its backoff (health: initrd_issue no_bootable_kernel; amendment 2026-10-21, item 19).
var ErrNoBootableKernel = errors.New("no bootable kernel to build an initrd for")

// BootSpaceError is an initrd build that /boot has no room for (amendment 2026-10-21, item 19): Needed bytes are 1.5
// times the kernel's current initrd (else the largest one) plus 32 MiB; a build that ran out of space reports the
// same. The step stays pending and is retried with its backoff; no initrd changed.
type BootSpaceError struct {
	Needed, Free int64
}

func (e *BootSpaceError) Error() string {
	return fmt.Sprintf("/boot has %d bytes free, a new initrd needs %d", e.Free, e.Needed)
}

// bootSpaceMargin is what a new initrd needs on top of 1.5 times the size of the one it replaces.
const bootSpaceMargin = 32 << 20

// bootSpaceNeeded is the room a new initrd of kernel v needs in /boot.
func bootSpaceNeeded(l paths.Layout, v string) int64 {
	size := int64(0)
	if info, err := os.Stat(l.Join("/boot/initrd.img-" + v)); err == nil {
		size = info.Size()
	} else {
		images, _ := filepath.Glob(l.Join("/boot/initrd.img-*"))
		for _, img := range images {
			if info, err := os.Stat(img); err == nil {
				size = max(size, info.Size())
			}
		}
	}
	return size + size/2 + bootSpaceMargin
}

// buildInitrd builds kernel v's new initrd into its temporary file (dracut -f [args] <file> <v>), when /boot has room
// for it, and checks it with verify; it returns the file, readable by root only. On any failure the file is removed
// and the current initrd is untouched (amendment 2026-10-21, item 19): at most one temporary initrd exists at a time.
func buildInitrd(ctx context.Context, sys Host, l paths.Layout, v string, args []string, verify func(initrd string) error) (string, error) {
	tmp := l.Join(tempInitrd(v))
	// A temporary file of this kernel a killed run left is no room taken (review 9, m7); it may carry the key (item 19,
	// rule B).
	if _, err := removeInitrdNames(ctx, l, []string{tmp}); err != nil {
		return "", err
	}
	needed := bootSpaceNeeded(l, v)
	free, err := sys.FreeBytes(l.Join("/boot"))
	if err != nil {
		return "", err
	}
	if free < needed {
		return "", &BootSpaceError{Needed: needed, Free: free}
	}
	ok := false
	defer func() {
		if !ok {
			discardTemp(ctx, l, tmp)
		}
	}()
	// dracut writes through whatever is at tmp: right before it runs, nothing may be there (Review 12 of PDK-245, M10).
	if err := clearTemp(ctx, l, tmp); err != nil {
		return "", err
	}
	// --no-uefi: a host configured with uefi=yes would make the output a unified kernel image, which GRUB cannot load
	// as an initrd (amendment 2026-10-21, item 19).
	cmd := append(append([]string{"-f", "--no-uefi"}, args...), tmp, v)
	_, stderr, exit, err := sys.CommandWithin(ctx, LongTimeout, nil, "dracut", cmd...)
	if err == nil && exit != 0 {
		if strings.Contains(stderr, "No space left on device") {
			free, _ := sys.FreeBytes(l.Join("/boot"))
			return "", &BootSpaceError{Needed: needed, Free: free}
		}
		err = fmt.Errorf("dracut %s: exit %d: %s", v, exit, firstLine(stderr))
	}
	if err != nil {
		return "", err
	}
	if err := notPE(tmp); err != nil {
		return "", fmt.Errorf("the new initrd of %s: %w", v, err)
	}
	if err := verify(tmp); err != nil {
		return "", fmt.Errorf("the new initrd of %s: %w", v, err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		if errors.Is(err, syscall.ENOSPC) {
			return "", &BootSpaceError{Needed: needed, Free: free}
		}
		return "", err
	}
	ok = true
	return tmp, nil
}

// notPE fails for a file that starts with the PE signature "MZ": a unified kernel image, not an initrd.
func notPE(path string) error {
	f, err := os.Open(path) //nolint:gosec // a temporary initrd of the layout
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	head := make([]byte, 2)
	if n, _ := f.Read(head); n == 2 && string(head) == "MZ" {
		return errors.New("it is a unified kernel image (PE), not an initrd")
	}
	return nil
}

// removeTemps removes every temporary initrd of tempInitrd's pattern by the rules of removeInitrdNames (they may carry
// the conversion key); the caller holds dpkg's locks.
func removeTemps(l paths.Layout) error {
	stale, err := filepath.Glob(l.Join(tempInitrd("*")))
	if err != nil {
		return err
	}
	_, err = removeInitrdNames(context.Background(), l, stale)
	return err
}

// discardTemp removes a temporary initrd that did not go into place by the rules of removeInitrdNames: one that failed
// its check may carry the conversion key (Review 12 of PDK-245, M9). A file it cannot remove is left to removeTemps.
func discardTemp(ctx context.Context, l paths.Layout, tmp string) {
	if _, err := removeInitrdNames(ctx, l, []string{tmp}); err != nil {
		slog.WarnContext(ctx, "a temporary initrd stays until the next removal of temporary initrds", "file", tmp, "error", err)
	}
}

// clearTemp removes whatever is at the temporary path tmp by the rules of removeInitrdNames and checks that nothing is
// left there.
func clearTemp(ctx context.Context, l paths.Layout, tmp string) error {
	if _, err := os.Lstat(tmp); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if _, err := removeInitrdNames(ctx, l, []string{tmp}); err != nil {
		return err
	}
	if _, err := os.Lstat(tmp); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s is still there before the build: %v", tmp, err)
	}
	return nil
}

// rebuildInitrds rebuilds the initrd of every bootable kernel, one kernel after the other: build into the temporary
// file, check it with verify, rename it into place (amendment 2026-10-21, items 18 and 19). A dracut killed halfway
// (the agent stopped, a supervisor rollback) or a full /boot leaves at most one temporary file, never a half-written
// initrd; an initrd not rebuilt yet stays as it was. It succeeds only when every kernel got its verified initrd and no
// kernel was added or removed meanwhile. The caller holds dpkg's locks.
func rebuildInitrds(ctx context.Context, sys Host, l paths.Layout, verify func(initrd string) error) error {
	kernels := bootableKernels(l)
	if len(kernels) == 0 {
		return ErrNoBootableKernel
	}
	if err := checkBuildable(l, kernels); err != nil {
		return err
	}
	// Temporary files a killed run left — also of a kernel removed since, which no build below would replace — carry
	// the conversion key on the unencrypted /boot (amendment 2026-10-21, item 19).
	if err := removeTemps(l); err != nil {
		return err
	}
	defer func() { _ = removeTemps(l) }()
	for _, v := range kernels {
		tmp, err := buildInitrd(ctx, sys, l, v, nil, verify)
		if err != nil {
			return err
		}
		if err := os.Rename(tmp, l.Join("/boot/initrd.img-"+v)); err != nil {
			discardTemp(ctx, l, tmp)
			return err
		}
		if err := fsutil.SyncDir(l.Join("/boot")); err != nil {
			return err
		}
	}
	if now := bootableKernels(l); !slices.Equal(now, kernels) {
		return fmt.Errorf("the installed kernels changed during the rebuild (%v, now %v)", kernels, now)
	}
	return nil
}

// tempInitrd is the temporary file a new initrd of kernel v is built into, next to the current one.
func tempInitrd(v string) string { return "/boot/.initrd.img-" + v + ".paddock" }

// RemoveStaleTemps removes, under dpkg's locks, temporary initrds a regeneration left when the agent was killed
// (PDK-375): only files of tempInitrd's pattern, never another file of /boot. ErrPackagesBusy leaves them for later.
func RemoveStaleTemps(sys Host, l paths.Layout) error {
	stale, err := filepath.Glob(l.Join(tempInitrd("*")))
	if err != nil || len(stale) == 0 {
		return err
	}
	unlock, err := sys.LockPackages()
	if err != nil {
		return err
	}
	defer unlock()
	return removeTemps(l)
}

// initrdStamp identifies the content of a current initrd: a kernel package's dracut run in between changes it.
type initrdStamp struct {
	exists  bool
	size    int64
	modTime time.Time
}

func stampOf(l paths.Layout, v string) initrdStamp {
	info, err := os.Stat(l.Join("/boot/initrd.img-" + v))
	if err != nil {
		return initrdStamp{}
	}
	return initrdStamp{exists: true, size: info.Size(), modTime: info.ModTime()}
}

// KernelNotBuildableError is a bootable kernel without /lib/modules/<v>/modules.dep (modules.dep.bin only): dracut
// cannot build its initrd, so no rebuild runs; the step stays pending with its backoff and the kernel's initrd stays
// (amendment 2026-10-21, item 19(k); health: initrd_issue kernel_not_buildable with the version).
type KernelNotBuildableError struct{ Version string }

func (e *KernelNotBuildableError) Error() string {
	return "kernel " + e.Version + " has no modules.dep: its initrd cannot be built"
}

// checkBuildable fails for the first of kernels without modules.dep, before anything is built.
func checkBuildable(l paths.Layout, kernels []string) error {
	for _, v := range kernels {
		if _, err := os.Stat(l.Join("/lib/modules/" + v + "/modules.dep")); err != nil {
			return &KernelNotBuildableError{Version: v}
		}
	}
	return nil
}

// bootableKernels are the kernels that boot with an initrd: /lib/modules/<v> with modules.dep or modules.dep.bin
// (amendment 2026-10-21, items 15 and 19(k)). They are protected from the orphan rule; a rebuild also needs them
// buildable (modules.dep, checkBuildable). A leftover initrd, or a module directory without either file, of a removed
// kernel is neither built nor required to pass; the I3 check of a cleanup still reads every initrd it finds
// (installedKernels).
func bootableKernels(l paths.Layout) []string {
	var kernels []string
	for _, v := range installedKernels(l) {
		_, dep := os.Stat(l.Join("/lib/modules/" + v + "/modules.dep"))
		_, bin := os.Stat(l.Join("/lib/modules/" + v + "/modules.dep.bin"))
		if dep == nil || bin == nil {
			kernels = append(kernels, v)
		}
	}
	return kernels
}

// moduleFiles are the files the module puts into an initrd (plan M8e §6.4); a regenerated initrd lists none of them.
var moduleFiles = []string{"etc/paddock/encrypt-key", "etc/paddock/encrypt-plan.env",
	"usr/lib/systemd/system/paddock-encrypt-init.service", "usr/libexec/paddock/encrypt-init.sh", "etc/paddock/encrypt-test"}

// verifyInitrd checks an initrd built for the TPM unlock by exact names: dracut's module list (lsinitrd -m) has no
// paddock-encrypt, its files include etc/crypttab with a line for the volume, systemd-cryptsetup and a TPM2 library
// (libtss2-*), and none of the module's files. lsinitrd's header — "Arguments:" names the omitted module — is never
// read as content (review 2 of PDK-245, B2).
func verifyInitrd(ctx context.Context, sys System, initrd, luksUUID string) error {
	mods, err := lsinitrd(ctx, sys, "-m", initrd)
	if err != nil {
		return err
	}
	if slices.Contains(dracutModules(mods), moduleName) {
		return fmt.Errorf("it carries the dracut module %s", moduleName)
	}
	listing, err := lsinitrd(ctx, sys, initrd)
	if err != nil {
		return err
	}
	files := initrdFileNames(listing)
	for _, f := range moduleFiles {
		if files[f] {
			return fmt.Errorf("it carries %s", f)
		}
	}
	tpm, cryptsetup := false, false
	for f := range files {
		base := path.Base(f)
		cryptsetup = cryptsetup || base == "systemd-cryptsetup"
		tpm = tpm || strings.HasPrefix(base, "libtss2-")
	}
	switch {
	case !files["etc/crypttab"]:
		return errors.New("it has no etc/crypttab")
	case !cryptsetup:
		return errors.New("it lacks systemd-cryptsetup")
	case !tpm:
		return errors.New("it lacks the TPM2 libraries")
	}
	crypttab, err := lsinitrd(ctx, sys, "-f", "etc/crypttab", initrd)
	if err != nil {
		return err
	}
	if !opensVolume(crypttab, luksUUID) {
		return fmt.Errorf("its crypttab does not open %s", luksUUID)
	}
	return nil
}

// lsinitrd runs lsinitrd with args.
func lsinitrd(ctx context.Context, sys System, args ...string) (string, error) {
	out, stderr, exit, err := sys.Command(ctx, "lsinitrd", args...)
	if err == nil && exit != 0 {
		err = fmt.Errorf("lsinitrd %s: exit %d: %s", strings.Join(args, " "), exit, firstLine(stderr))
	}
	return out, err
}

// dracutModules are the module names of lsinitrd -m: the lines after "dracut modules:" up to the next rule or blank.
func dracutModules(out string) []string {
	var mods []string
	in := false
	for line := range strings.Lines(out) {
		line = strings.TrimSpace(line)
		switch {
		case line == "dracut modules:":
			in = true
		case in && (line == "" || strings.HasPrefix(line, "===")):
			return mods
		case in:
			mods = append(mods, line)
		}
	}
	return mods
}

// initrdFileNames are the paths of lsinitrd's ls -l lines (a symlink by its own name).
func initrdFileNames(out string) map[string]bool {
	names := map[string]bool{}
	for line := range strings.Lines(out) {
		f := strings.Fields(line)
		if len(f) < 9 || len(f[0]) != 10 || !strings.ContainsRune("-dlcbps", rune(f[0][0])) {
			continue
		}
		names[f[8]] = true
	}
	return names
}

// addCrypttabLine appends the converted volume's line to /etc/crypttab unless a line names its UUID already (as
// UUID=<uuid> or /dev/disk/by-uuid/<uuid>): a second line for the same volume would make systemd open it twice.
func addCrypttabLine(l paths.Layout, mapping, luksUUID string) error {
	path := l.Join(crypttabPath)
	raw, err := os.ReadFile(path) //nolint:gosec // the crypttab of the layout
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if opensVolume(string(raw), luksUUID) {
		return nil
	}
	content := string(raw)
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	content += mapping + " UUID=" + luksUUID + " none luks,tpm2-device=auto\n"
	return fsutil.WriteFile(path, []byte(content), 0o644, 0o755)
}

// opensVolume reports whether a crypttab has a line for the volume (its source names the UUID).
func opensVolume(crypttab, luksUUID string) bool {
	for line := range strings.Lines(crypttab) {
		if f := strings.Fields(line); len(f) >= 2 && !strings.HasPrefix(f[0], "#") && strings.Contains(f[1], luksUUID) {
			return true
		}
	}
	return false
}

// HasTPMKeyslot reports whether the metadata carries the keyslot that replaces the module's key file at boot: tpm2+pin
// or tpm2 (plan M8e decision 20).
func HasTPMKeyslot(md luks.Metadata) bool {
	return md.Has(luks.KindTPM2PIN) || md.Has(luks.KindTPM2)
}

// RearmDiskSetup re-creates the marker of the boot PIN dialogue when it is missing (plan M8e decision 52): a converted
// device whose user skipped the PIN asks again at every boot until a TPM keyslot exists. It reports whether it wrote
// the marker.
func RearmDiskSetup(l paths.Layout) (bool, error) {
	if _, err := os.Stat(l.DiskSetupPending()); err == nil || !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	return true, fsutil.WriteFile(l.DiskSetupPending(), nil, 0o600, 0o700)
}

// LUKSTools runs the LUKS tools of luks.Dump through sys (the environment is the tool's own).
func LUKSTools(sys System) luks.Tools { return luksTools{sys} }

type luksTools struct{ sys System }

func (t luksTools) Command(ctx context.Context, _ []string, name string, args ...string) (string, string, int, error) {
	return t.sys.Command(ctx, name, args...)
}
