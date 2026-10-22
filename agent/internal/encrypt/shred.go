package encrypt

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/phischl/paddock-mdm/agent/internal/paths"
)

// shred overwrites a file of pure key material (the conversion key) with zeros through a handle opened without
// following a symlink, flushes it and removes the name (amendment 2026-10-21, item 19, rule A). A shared inode is
// overwritten all the same: no bootable file shares a key file, so zeroing it erases the key under every name. Anything
// but a regular file is not written to and fails closed; O_NONBLOCK keeps a FIFO at the path from blocking the open. A
// missing file is no error.
func shred(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // a key path of the agent layout
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open %s without following a link: %w", path, err)
	}
	info, err := f.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = fmt.Errorf("%s is no regular file; it is not overwritten", path)
	}
	if err != nil {
		_ = f.Close()
		return err
	}
	if n := links(info); n > 1 {
		slog.Warn("the key file has further hard links; zeroing it erases the key under every name", "file", path, "links", n)
	}
	if err := errors.Join(zero(f, info.Size(), fsTypeOf(f)), f.Close()); err != nil {
		return err
	}
	return os.Remove(path)
}

// zeroChunk bounds the buffer of zero: a huge or sparse file is never held in memory at once.
const zeroChunk = 1 << 20

// btrfsMagic is the statfs type of btrfs.
const btrfsMagic = 0x9123683e

// Whences of lseek(2) that os does not name.
const (
	seekData = 3
	seekHole = 4
)

// zeroTarget is the open file zero overwrites (*os.File).
type zeroTarget interface {
	Name() string
	Seek(offset int64, whence int) (int64, error)
	WriteAt(b []byte, off int64) (int, error)
	Truncate(size int64) error
	Sync() error
}

// zero overwrites the data of the first size bytes of f with zeros before the caller unlinks it (amendment
// 2026-10-21, item 19; residual risk RR-71). Only allocated ranges are written (SEEK_DATA/SEEK_HOLE), in chunks of
// zeroChunk, so that overwriting allocates nothing and cannot fill /boot. On btrfs (fsType) nothing is written:
// copy-on-write would allocate new blocks and leave the old ones as they are. A failed write empties the file, so that
// no partly overwritten file keeps taking room; the caller unlinks it all the same. It fails only when the file could
// not be emptied.
func zero(f zeroTarget, size, fsType int64) error {
	if fsType == btrfsMagic {
		slog.Warn("not overwritten on a copy-on-write file system; only unlinked", "file", f.Name())
		return nil
	}
	if err := zeroData(f, size); err != nil {
		slog.Warn("overwriting failed; the file is emptied and unlinked", "file", f.Name(), "error", err)
		if terr := f.Truncate(0); terr != nil {
			return fmt.Errorf("empty %s after a failed overwrite: %w", f.Name(), errors.Join(err, terr))
		}
	}
	return nil
}

// zeroData writes zeros over the allocated ranges of f's first size bytes and flushes them; without SEEK_DATA support
// every byte counts as allocated.
func zeroData(f zeroTarget, size int64) error {
	buf := make([]byte, min(size, zeroChunk))
	for off := int64(0); off < size; {
		start, err := f.Seek(off, seekData)
		if errors.Is(err, syscall.ENXIO) {
			break
		}
		if err != nil {
			start = off
		}
		end, err := f.Seek(start, seekHole)
		if err != nil {
			end = size
		}
		for end = min(end, size); start < end; {
			n, err := f.WriteAt(buf[:min(end-start, zeroChunk)], start)
			if err != nil {
				return err
			}
			start += int64(n)
		}
		off = max(end, off+1)
	}
	return f.Sync()
}

// fsTypeOf is the statfs type of the file system f is on (0 when unknown).
func fsTypeOf(f *os.File) int64 {
	var st syscall.Statfs_t
	if err := syscall.Fstatfs(int(f.Fd()), &st); err != nil { //nolint:gosec // a file descriptor fits an int
		return 0
	}
	return int64(st.Type) //nolint:unconvert // Type's width differs between platforms
}

// links is the hard link count of info (1 when the platform does not say).
func links(info os.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink)
	}
	return 1
}

// inode identifies a file.
type inode struct{ dev, ino uint64 }

func inodeOf(info os.FileInfo) (inode, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return inode{}, false
	}
	return inode{dev: uint64(st.Dev), ino: st.Ino}, true //nolint:unconvert,gosec // Dev's type differs between platforms
}

// KeyMaterialHardlinkedError is an initrd-type file that may carry the conversion key with a hard link outside the
// names Paddock lists: it is neither overwritten nor unlinked, and the step stays pending (amendment 2026-10-21, item
// 19, rule B; health initrd_issue key_material_hardlinked).
type KeyMaterialHardlinkedError struct {
	Path  string
	Inode uint64
	Links uint64
}

func (e *KeyMaterialHardlinkedError) Error() string {
	return fmt.Sprintf("%s (inode %d) has %d hard links, some outside /boot/initrd.img-*: not removed", e.Path, e.Inode, e.Links)
}

// KeySharedBootableError is a file that may carry the conversion key and that a bootable kernel's initrd name links to
// (a symlink): it is neither overwritten nor unlinked, so that the kernel keeps booting; it goes once that kernel's
// verified rebuild replaces the link (amendment 2026-10-21, item 19, rule B; health initrd_issue
// key_material_shared_bootable with initrd_issue_kernel).
type KeySharedBootableError struct {
	Path   string
	Kernel string
}

func (e *KeySharedBootableError) Error() string {
	return fmt.Sprintf("%s is linked from the initrd of bootable kernel %s: not removed", e.Path, e.Kernel)
}

// removeInitrdNames removes initrd-type files (orphans, strays, temporary initrds) by their inode (amendment
// 2026-10-21, item 19, rule B). The names Paddock lists are every regular /boot/initrd.img-* and
// /boot/.initrd.img-*.paddock; a /boot/initrd.img-* symlink to a regular file is a reference to that file (a dangling
// one is ignored). For each file that names point to:
//   - A bootable kernel's symlink refers to it: nothing is written or unlinked, KeySharedBootableError.
//   - It has links outside the listed names: nothing is written or unlinked, KeyMaterialHardlinkedError.
//   - Another listed name (a bootable kernel's initrd) shares it: only the names to remove are unlinked, nothing is
//     written; that kernel's own verified rebuild replaces the file.
//   - Every listed name is to be removed: the file is overwritten once (through a handle that does not follow a link,
//     re-checked there) and every name is unlinked.
//
// A /boot/initrd.img-* symlink to remove goes with the file it refers to; one to a file outside the listed names stays.
// A temporary name that is a symlink or a FIFO is unlinked without any write; a directory there is an error. Every
// file is handled and the errors are joined. It returns the names removed.
func removeInitrdNames(ctx context.Context, l paths.Layout, names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	bootable := bootableKernels(l)
	listed := map[inode][]string{}
	refs := map[inode][]string{}
	nlink := map[inode]uint64{}
	initrds, _ := filepath.Glob(l.Join("/boot/initrd.img-*"))
	temps, _ := filepath.Glob(l.Join(tempInitrd("*")))
	for _, name := range append(initrds, temps...) {
		info, err := os.Lstat(name)
		switch {
		case err != nil:
		case info.Mode().IsRegular():
			if id, ok := inodeOf(info); ok {
				listed[id] = append(listed[id], name)
				nlink[id] = links(info)
			}
		case info.Mode()&os.ModeSymlink != 0 && !isTemp(name):
			if target, err := os.Stat(name); err == nil && target.Mode().IsRegular() {
				if id, ok := inodeOf(target); ok {
					refs[id] = append(refs[id], name)
				}
			}
		}
	}
	remove := map[inode][]string{}
	var order []inode
	var removed []string
	var errs []error
	for _, name := range names {
		info, err := os.Lstat(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		var id inode
		switch {
		case info.Mode().IsRegular():
			id, _ = inodeOf(info)
		case isTemp(name) && info.IsDir():
			errs = append(errs, fmt.Errorf("%s is a directory; not removed", name))
			continue
		case isTemp(name):
			// Its target is no Paddock file to write to, but the name must not stay: dracut would write through it.
			if err := os.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
				continue
			}
			removed = append(removed, name)
			continue
		default:
			target, err := os.Stat(name)
			var ok bool
			if err == nil && target.Mode().IsRegular() {
				id, ok = inodeOf(target)
			}
			if _, known := listed[id]; !ok || !known {
				// A symlink to a file Paddock does not list, or no symlink at all: never through it.
				continue
			}
		}
		if _, seen := remove[id]; !seen {
			order = append(order, id)
		}
		remove[id] = append(remove[id], name)
	}
	for _, id := range order {
		gone, err := removeFile(ctx, id, remove[id], listed[id], refs[id], nlink[id], bootable)
		removed = append(removed, gone...)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return removed, errors.Join(errs...)
}

// removeFile applies removeInitrdNames' rules to one file: names are its names to remove (regular names and
// symlinks), all its listed regular names, refs the /boot/initrd.img-* symlinks to it.
func removeFile(ctx context.Context, id inode, names, all, refs []string, nlink uint64, bootable []string) ([]string, error) {
	if len(all) == 0 {
		// Created or replaced after the listing (a package run outside dpkg's locks): the next pass sees it whole.
		return nil, fmt.Errorf("%s changed while the initrds were listed; not removed", names[0])
	}
	for _, ref := range refs {
		if v := strings.TrimPrefix(filepath.Base(ref), "initrd.img-"); slices.Contains(bootable, v) && !slices.Contains(names, ref) {
			slog.WarnContext(ctx, "an initrd that may carry the conversion key is the target of a bootable kernel's initrd; it stays",
				"file", all[0], "kernel", v)
			return nil, &KeySharedBootableError{Path: all[0], Kernel: v}
		}
	}
	if uint64(len(all)) < nlink {
		slog.WarnContext(ctx, "an initrd that may carry the conversion key has hard links Paddock does not know; it stays",
			"file", all[0], "inode", id.ino, "links", nlink)
		return nil, &KeyMaterialHardlinkedError{Path: all[0], Inode: id.ino, Links: nlink}
	}
	if slices.ContainsFunc(all, func(n string) bool { return !slices.Contains(names, n) }) {
		slog.WarnContext(ctx, "an initrd shares its file with another kernel's initrd; only its name is removed", "file", names[0],
			"inode", id.ino, "links", nlink)
	} else if err := zeroInitrd(all[0], id, nlink); err != nil {
		return nil, err
	}
	var removed []string
	for _, name := range names {
		if err := os.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, err
		}
		removed = append(removed, name)
	}
	return removed, nil
}

// isTemp reports whether name is a temporary initrd's (tempInitrd).
func isTemp(name string) bool {
	base := filepath.Base(name)
	return strings.HasPrefix(base, ".initrd.img-") && strings.HasSuffix(base, ".paddock")
}

// zeroInitrd overwrites an initrd through a handle that does not follow a link, when it is still the regular file with
// the inode and link count the caller saw.
func zeroInitrd(path string, id inode, nlink uint64) error {
	f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // an initrd of the layout
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err == nil {
		if got, ok := inodeOf(info); !ok || got != id || !info.Mode().IsRegular() || links(info) != nlink {
			err = fmt.Errorf("%s changed while it was removed; not overwritten", path)
		}
	}
	if err == nil {
		err = zero(f, info.Size(), fsTypeOf(f))
	}
	return errors.Join(err, f.Close())
}
