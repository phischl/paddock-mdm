package encrypt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/phischl/paddock-mdm/agent/internal/fsutil"
	"github.com/phischl/paddock-mdm/agent/internal/paths"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// cancelledPlan replaces the plan of the init step in a neutralized initrd: without PADDOCK_PART_UUID and with no
// known layout, check_plan of paddock-encrypt-init.sh fails and the step reports plan_invalid before it looks at the
// disk, so the device boots unencrypted (plan M8e item 18, amendment 2026-10-30, PDK-482).
const cancelledPlan = "# Paddock: this in-place encryption was cancelled (plan M8e amendment 2026-10-30)\nPADDOCK_LAYOUT=cancelled\n"

// initrdPlanPath is where module-setup.sh installs the plan in the initrd (no leading slash, as cpio names it).
const initrdPlanPath = "etc/paddock/encrypt-plan.env"

// cpioFile is one regular file of a newc archive.
type cpioFile struct {
	Name  string
	Mode  uint32 // permission bits; the file type is added by cpioNewc
	Ino   uint32
	Mtime uint32
	Data  []byte
}

// cpioNewc returns an uncompressed cpio archive in the "new ASCII" format (magic 070701) as the kernel's initramfs
// unpacker reads it (Documentation/driver-api/early-userspace/buffer-format.rst): per file a 110-byte header of
// thirteen 8-digit hex fields, the name with its NUL, padded to a multiple of 4, the data, padded to a multiple of 4;
// then the entry TRAILER!!!. Files are owned by root and have one link, so the unpacker does no hard-link matching.
func cpioNewc(files []cpioFile) []byte {
	var b bytes.Buffer
	entry := func(name string, mode, ino, nlink, mtime uint32, data []byte) {
		fmt.Fprintf(&b, "070701%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X",
			ino, mode, 0, 0, nlink, mtime, len(data), 0, 0, 0, 0, len(name)+1, 0)
		b.WriteString(name)
		b.WriteByte(0)
		pad4(&b)
		b.Write(data)
		pad4(&b)
	}
	for _, f := range files {
		entry(f.Name, syscall.S_IFREG|f.Mode, f.Ino, 1, f.Mtime, f.Data)
	}
	entry("TRAILER!!!", 0, 0, 1, 0, nil)
	return b.Bytes()
}

func pad4(b *bytes.Buffer) {
	for b.Len()%4 != 0 {
		b.WriteByte(0)
	}
}

// neutralizeSegment is the override appended to an initrd: one regular file at initrdPlanPath with cancelledPlan,
// mode 0600 like the plan module-setup.sh installs. The kernel unpacks concatenated archives in order into the same
// rootfs and opens a regular file that exists with O_TRUNC, so this later copy replaces the earlier one
// (init/initramfs.c, do_name). Fixed inode and mtime keep the segment identical, which makes the append idempotent.
var neutralizeSegment = cpioNewc([]cpioFile{{Name: initrdPlanPath, Mode: 0o600, Ino: 0x50444B01, Data: []byte(cancelledPlan)}})

// segmentAt is what is appended to an initrd of size bytes: zeros up to the next multiple of 4 — the unpacker skips
// zeros and reads a cpio header only at an offset aligned to 4 — then neutralizeSegment.
func segmentAt(size int64) []byte {
	pad := (4 - size%4) % 4
	return append(make([]byte, pad), neutralizeSegment...)
}

// NeutralizeInitrds appends to the initrd of every installed kernel that carries the init step the uncompressed cpio
// segment that overrides the step's plan with an invalid one (neutralizeSegment), so that a restart before the cleanup
// finished boots the device unencrypted (plan M8e item 18, amendment 2026-10-30, PDK-482). Per kernel the current
// initrd is listed (an initrd whose listing shows no marker of the module is left alone: the segment would only make
// initramfs-tools' lister fail on it), copied into its temporary file (the cleanup's names, tempInitrd; the ".next"
// one when a bootable kernel's link refers to the first, rule B (0)), the segment is appended, the file is fsynced and
// renamed over the initrd's name, and /boot is fsynced: no initrd is written in place and no file a bootable link
// points to is written or unlinked. An initrd that changed meanwhile (a kernel package's dracut run, checked by its
// stamp right before the rename) is left as it is. A copy that does not fit is a BootSpaceError; a failed copy is
// removed by rule B. Every kernel is tried; the errors are joined. dpkg's locks are held when they are free, but not
// required: the window this closes includes a cleanup that waits for them.
func NeutralizeInitrds(ctx context.Context, sys Host, l paths.Layout) error {
	defer lockPackagesIfFree(ctx, sys)()
	return neutralizeAll(ctx, sys, l)
}

// Disarm stops a cancelled or failed conversion whose cleanup is pending from converting the disk at a restart (plan
// M8e item 18, amendment 2026-10-30, PDK-482 and PDK-579): it removes the module directory and its dracut
// configuration, as step (1) of Cleanup does, so that no later dracut run (a kernel package's) builds the init step
// into an initrd again, and neutralizes every initrd that carries it (neutralizeAll). It runs at the abort or the
// recorded failure (a preparation failing once step 7 wrote the module, a failed or skipped init step), at every
// cleanup retry of the worker and once at the agent's start, which catch an initrd a dracut run already under way at
// the abort built and a kill between recording the phase and the neutralization. plan.env and the key stay: a disk that
// converted anyway is adopted (invariant I2) and RestoreModule reinstalls the module for it (ModuleMissing).
// ModuleWritten is recorded before a module file is removed, so that the cleanup still rebuilds the initrds. Nothing
// happens for another phase, without CleanupPending, or before step 7 wrote the module. The caller has checked that the
// partition is not LUKS (invariant I1). A failure is logged at error level and returned.
func Disarm(ctx context.Context, sys Host, l paths.Layout, store Store) error {
	c, ok := store.Conversion()
	if !ok || c.Phase != state.ConversionCancelled && c.Phase != state.ConversionFailed || !c.CleanupPending {
		return nil
	}
	present := moduleFilesPresent(l)
	if !c.ModuleWritten && !present {
		return nil
	}
	err := func() error {
		if present && !c.ModuleWritten {
			if err := store.Update(func(c *state.DiskConversion, _ *state.LUKS) { c.ModuleWritten = true }); err != nil {
				return fmt.Errorf("record that the module was written: %w", err)
			}
		}
		defer lockPackagesIfFree(ctx, sys)()
		var errs []error
		// The configuration first, as in Cleanup: a dracut run between the two removals then omits the module rather
		// than failing on a configured module it cannot find.
		for _, p := range []string{l.Join(ModuleConf), l.Join(ModuleDir)} {
			if err := os.RemoveAll(p); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(append(errs, neutralizeAll(ctx, sys, l))...)
	}()
	if err != nil {
		slog.ErrorContext(ctx, "the initrds of the cancelled or failed in-place encryption were not neutralized; "+
			"a restart before the cleanup finished may still encrypt the disk", "conversion_id", c.ID, "error", err)
	}
	return err
}

// ReportNeutralizeFailed emits disk.conversion_neutralize_failed for err, a failed Disarm or NeutralizeInitrds; a
// failure to record the event is logged and returned.
func ReportNeutralizeFailed(ctx context.Context, store Store, err error) error {
	if terr := store.Transition(func(c *state.DiskConversion, _ *state.LUKS) *Event {
		return &Event{protocol.EventDiskConversionNeutralizeFailed, map[string]any{"conversion_id": c.ID,
			"reason": NeutralizeReason(err)}}
	}); terr != nil {
		slog.ErrorContext(ctx, "reporting the failed neutralization failed", "error", terr)
		return terr
	}
	return nil
}

// lockPackagesIfFree takes dpkg's locks when they are free and returns their release (a no-op without them).
func lockPackagesIfFree(ctx context.Context, sys Host) func() {
	unlock, err := sys.LockPackages()
	if err != nil {
		slog.WarnContext(ctx, "neutralizing the initrds without dpkg's locks", "error", err)
		return func() {}
	}
	return unlock
}

// neutralizeAll neutralizes the initrd of every installed kernel (installedKernels: a kernel GRUB lists without
// modules.dep boots its initrd as well) and joins the errors.
func neutralizeAll(ctx context.Context, sys Host, l paths.Layout) error {
	listers := initrdListers
	var errs []error
	for _, v := range installedKernels(l) {
		if err := neutralizeInitrd(ctx, sys, l, &listers, v); err != nil {
			errs = append(errs, fmt.Errorf("the initrd of %s: %w", v, err))
		}
	}
	return errors.Join(errs...)
}

// neutralizeInitrd appends the segment to kernel v's initrd through its temporary file; an initrd that is missing,
// ends with the segment already or lists no marker of the module is left alone. An initrd that cannot be listed is
// neutralized all the same: the segment only adds the invalid plan, and a restart must not encrypt on a guess.
func neutralizeInitrd(ctx context.Context, sys Host, l paths.Layout, listers *[]string, v string) error {
	name := l.Join("/boot/initrd.img-" + v)
	info, err := os.Stat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is no regular file", name)
	}
	// The stamp of what is listed and copied: any write to the initrd from here on (a kernel package's dracut run)
	// changes it.
	before := initrdStamp{exists: true, size: info.Size(), modTime: info.ModTime()}
	if done, err := endsWithSegment(name, info.Size()); err != nil || done {
		return err
	}
	out, err := listInitrd(ctx, sys, listers, name)
	if err == nil && !carriesModule(out) {
		return nil
	}
	if err != nil {
		slog.WarnContext(ctx, "the initrd cannot be listed; neutralizing it all the same", "file", name, "error", err)
	}
	if err := checkAppendable(name, info.Size()); err != nil {
		return err
	}
	seg := segmentAt(info.Size())
	needed := info.Size() + int64(len(seg)) + bootSpaceMargin
	free, err := sys.FreeBytes(l.Join("/boot"))
	if err != nil {
		return err
	}
	if free < needed {
		return &BootSpaceError{Needed: needed, Free: free}
	}
	tmp := l.Join(tempInitrd(v))
	if linkedTemps(l)[tmp] {
		tmp = l.Join(tempInitrd(v + ".next"))
	}
	if err := clearTemp(ctx, l, tmp); err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			discardTemp(ctx, l, tmp)
		}
	}()
	if err := copyWithSegment(name, tmp, info.Size(), seg); err != nil {
		return bootSpaceOr(err, sys, l, needed)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Right before the rename: without dpkg's locks a kernel package's dracut can replace the initrd at any time. What
	// remains is the gap between this stat and the rename (plan M8e amendment 2026-10-30).
	if stampOf(l, v) != before {
		return errors.New("it changed while it was copied")
	}
	if err := os.Rename(tmp, name); err != nil {
		return err
	}
	ok = true
	return fsutil.SyncDir(l.Join("/boot"))
}

// freeBytes is the part of Host bootSpaceOr asks.
type freeBytes interface {
	FreeBytes(dir string) (int64, error)
}

// appendableCompressions are the compressions of an initrd's main archive after which the kernel is known to unpack an
// appended archive (review 2 of PDK-482, X2): their decompressors report where the compressed stream ends, so the
// unpacker goes on with what follows. Any other compression (lz4's legacy format has no end marker) is refused.
var appendableCompressions = []struct {
	name  string
	magic string
}{{"zstd", "\x28\xb5\x2f\xfd"}, {"gzip", "\x1f\x8b"}, {"xz", "\xfd7zXZ\x00"}}

// refusedCompressions name the other compressions the kernel can unpack, for the error.
var refusedCompressions = []struct {
	name  string
	magic string
}{{"lz4", "\x02\x21\x4c\x18"}, {"bzip2", "BZh"}, {"lzo", "\x89LZO"}, {"lzma", "\x5d\x00\x00"}}

// checkAppendable fails unless the segment can follow the initrd at name (size bytes): it skips the uncompressed newc
// archives at its start (an early microcode archive) and the zeros between archives, as the kernel's unpacker does
// (init/initramfs.c, unpack_to_rootfs), then reads the magic of the main archive. An initrd that is uncompressed to its
// end is appendable as well.
func checkAppendable(name string, size int64) error {
	f, err := os.Open(name) //nolint:gosec // an initrd of the layout, read only
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	off, err := skipUncompressed(f, size)
	if err != nil {
		return err
	}
	if off >= size {
		return nil
	}
	head := make([]byte, 6)
	n, err := f.ReadAt(head, off)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	head = head[:n]
	for _, c := range appendableCompressions {
		if bytes.HasPrefix(head, []byte(c.magic)) {
			return nil
		}
	}
	for _, c := range refusedCompressions {
		if bytes.HasPrefix(head, []byte(c.magic)) {
			return fmt.Errorf("its main archive is %s-compressed; the kernel may not read an archive appended to it", c.name)
		}
	}
	return fmt.Errorf("its main archive has an unknown compression (%x); the kernel may not read an archive appended to it", head)
}

// skipUncompressed returns the offset after the uncompressed newc archives and the zeros at the start of r (size
// bytes).
func skipUncompressed(r io.ReaderAt, size int64) (int64, error) {
	var off int64
	b := make([]byte, 1)
	for off < size {
		if _, err := r.ReadAt(b, off); err != nil {
			return 0, err
		}
		switch b[0] {
		case 0:
			off++
		case '0':
			end, err := skipNewc(r, size, off)
			if err != nil {
				return 0, err
			}
			off = end
		default:
			return off, nil
		}
	}
	return off, nil
}

// skipNewc returns the offset after the newc archive at off in r (size bytes), its TRAILER!!! entry included.
func skipNewc(r io.ReaderAt, size, off int64) (int64, error) {
	align := func(n int64) int64 { return (n + 3) &^ 3 }
	hdr := make([]byte, 110)
	for {
		if off+110 > size {
			return 0, fmt.Errorf("truncated cpio archive at %d", off)
		}
		if _, err := r.ReadAt(hdr, off); err != nil {
			return 0, err
		}
		if m := string(hdr[:6]); m != "070701" && m != "070702" {
			return 0, fmt.Errorf("no newc archive at %d", off)
		}
		field := func(i int) (int64, error) {
			return strconv.ParseInt(string(hdr[6+8*i:14+8*i]), 16, 64)
		}
		fileSize, err := field(6)
		if err != nil {
			return 0, fmt.Errorf("cpio header at %d: %w", off, err)
		}
		nameSize, err := field(11)
		if err != nil {
			return 0, fmt.Errorf("cpio header at %d: %w", off, err)
		}
		if nameSize < 1 || off+110+nameSize > size {
			return 0, fmt.Errorf("truncated cpio archive at %d", off)
		}
		nameBuf := make([]byte, nameSize-1)
		if _, err := r.ReadAt(nameBuf, off+110); err != nil {
			return 0, err
		}
		next := align(align(off+110+nameSize) + fileSize)
		if string(nameBuf) == "TRAILER!!!" {
			return min(next, size), nil
		}
		if next > size {
			return 0, fmt.Errorf("truncated cpio archive at %d", off)
		}
		off = next
	}
}

// bootSpaceOr is a BootSpaceError for an ENOSPC copy of needed bytes into /boot, else err.
func bootSpaceOr(err error, sys freeBytes, l paths.Layout, needed int64) error {
	if !errors.Is(err, syscall.ENOSPC) {
		return err
	}
	free, _ := sys.FreeBytes(l.Join("/boot"))
	return &BootSpaceError{Needed: needed, Free: free}
}

// endsWithSegment reports whether the initrd at name (size bytes) ends with neutralizeSegment.
func endsWithSegment(name string, size int64) (bool, error) {
	n := int64(len(neutralizeSegment))
	if size < n {
		return false, nil
	}
	f, err := os.Open(name) //nolint:gosec // an initrd of the layout, read only
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	tail := make([]byte, n)
	if _, err := f.ReadAt(tail, size-n); err != nil {
		return false, err
	}
	return bytes.Equal(tail, neutralizeSegment), nil
}

// neutralized reports whether the regular file at name ends with neutralizeSegment.
func neutralized(name string) bool {
	info, err := os.Stat(name)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	done, err := endsWithSegment(name, info.Size())
	return err == nil && done
}

// copyWithSegment writes the size bytes of src, then seg, into the new file dst (root only, never through a link) and
// fsyncs it.
func copyWithSegment(src, dst string, size int64, seg []byte) (err error) {
	in, err := os.Open(src) //nolint:gosec // an initrd of the layout, read only
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600) //nolint:gosec // the temporary initrd of the layout
	if err != nil {
		return err
	}
	defer func() {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
	}()
	if err := writeWithSegment(out, in, size, seg); err != nil {
		return err
	}
	return out.Sync()
}

// writeWithSegment writes the first size bytes of in, then seg, to out.
func writeWithSegment(out io.Writer, in io.Reader, size int64, seg []byte) error {
	n, err := io.Copy(out, io.LimitReader(in, size))
	if err != nil {
		return err
	}
	if n != size {
		return fmt.Errorf("it shrank while it was copied (%d of %d bytes)", n, size)
	}
	_, err = out.Write(seg)
	return err
}

// NeutralizeReason is the reason of disk.conversion_neutralize_failed, from the first of the joined errors (the first
// kernel that failed): boot_space_low for a /boot without room, else the first line of that error.
func NeutralizeReason(err error) string {
	for {
		j, ok := err.(interface{ Unwrap() []error })
		if !ok || len(j.Unwrap()) == 0 {
			break
		}
		err = j.Unwrap()[0]
	}
	var space *BootSpaceError
	if errors.As(err, &space) {
		return IssueBootSpaceLow
	}
	return strings.TrimSpace(firstLine(err.Error()))
}
