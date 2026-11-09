package fsutil

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// ErrParentNotTrusted means a parent directory of a path is a symlink, not a directory, not owned by root (or the
// agent's own user) or writable by group or others (plan M12h decision 12, ADR 0051 AG-1). Its text is the status
// message of a refused resource.
var ErrParentNotTrusted = errors.New("parent_not_trusted")

// dirFlags open a path component without following it: a symlink fails with ENOTDIR (O_DIRECTORY) or ELOOP.
const dirFlags = unix.O_PATH | unix.O_NOFOLLOW | unix.O_DIRECTORY | unix.O_CLOEXEC

// stickyAllowed reports whether dir is one of the world-writable sticky system directories a path may pass through.
func stickyAllowed(dir string) bool { return dir == "/tmp" || dir == "/var/tmp" }

// checkDir applies the parent rule to one directory. euid is trusted besides root: the agent runs as root, so this
// is root in production; a test tree belongs to the test's own user, who could change it anyway.
func checkDir(dir string, uid, mode uint32, euid int) error {
	if mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("%s: %w", dir, ErrParentNotTrusted)
	}
	owned := uid == 0 || int64(uid) == int64(euid)
	if mode&0o022 != 0 {
		if stickyAllowed(dir) && mode&unix.S_ISVTX != 0 && uid == 0 {
			return nil
		}
		return fmt.Errorf("%s: %w", dir, ErrParentNotTrusted)
	}
	if !owned {
		return fmt.Errorf("%s: %w", dir, ErrParentNotTrusted)
	}
	return nil
}

func trusted(fd int, dir string) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return &fs.PathError{Op: "stat", Path: dir, Err: err}
	}
	return checkDir(dir, st.Uid, st.Mode, os.Geteuid())
}

// openDir opens dir component by component from "/" and checks every component, "/" included. Missing components are
// created with dirMode (exactly, regardless of the umask; owned by root:root when running as root) if create is set.
// The result is an O_PATH descriptor the caller closes.
func openDir(dir string, create bool, dirMode fs.FileMode) (int, error) {
	fd, err := unix.Open("/", dirFlags, 0)
	if err != nil {
		return -1, &fs.PathError{Op: "open", Path: "/", Err: err}
	}
	if err := trusted(fd, "/"); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	cur := "/"
	for name := range strings.SplitSeq(strings.TrimPrefix(dir, "/"), "/") {
		if name == "" {
			continue
		}
		cur = filepath.Join(cur, name)
		next, err := unix.Openat(fd, name, dirFlags, 0)
		if errors.Is(err, unix.ENOENT) && create {
			if err = mkdirAt(fd, name, dirMode); err == nil {
				next, err = unix.Openat(fd, name, dirFlags, 0)
			}
		}
		_ = unix.Close(fd)
		switch {
		case errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP):
			return -1, fmt.Errorf("%s: %w", cur, ErrParentNotTrusted)
		case err != nil:
			return -1, &fs.PathError{Op: "open", Path: cur, Err: err}
		}
		fd = next
		if err := trusted(fd, cur); err != nil {
			_ = unix.Close(fd)
			return -1, err
		}
	}
	return fd, nil
}

// mkdirAt creates name below the trusted directory parent; nobody but root can swap it between the calls.
func mkdirAt(parent int, name string, mode fs.FileMode) error {
	if err := unix.Mkdirat(parent, name, uint32(mode.Perm())); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return nil
		}
		return err
	}
	if err := unix.Fchmodat(parent, name, uint32(mode.Perm()), 0); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		// A setgid parent would hand its group to the new directory (plan M2b decision 10: parents root:root).
		return unix.Fchownat(parent, name, 0, 0, unix.AT_SYMLINK_NOFOLLOW)
	}
	return nil
}

// openParent opens the parent directory of the absolute path and returns it with the final name.
func openParent(path string, create bool, dirMode fs.FileMode) (int, string, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean == "/" {
		return -1, "", &fs.PathError{Op: "open", Path: path, Err: unix.EINVAL}
	}
	fd, err := openDir(filepath.Dir(clean), create, dirMode)
	return fd, filepath.Base(clean), err
}

// syncAt fsyncs the directory fd refers to (an O_PATH descriptor cannot be synced itself).
func syncAt(fd int) error {
	d, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(d) }()
	return unix.Fsync(d)
}

// WriteFileOwned atomically replaces path with data, owned by uid and gid (-1 = unchanged) and with mode set before
// the rename, so the file never appears with the wrong owner or mode. Every parent directory must pass the parent
// rule (ErrParentNotTrusted otherwise); missing ones are created with dirMode. The temporary file, the rename and
// the directory sync happen relative to the final directory's descriptor, so a parent swapped after the check is
// never followed.
func WriteFileOwned(path string, data []byte, mode, dirMode fs.FileMode, uid, gid int) error {
	dirfd, base, err := openParent(path, true, dirMode)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer func() { _ = unix.Close(dirfd) }()
	var tmp string
	var fd int
	for range 10 {
		tmp = "." + base + ".tmp-" + rand.Text()
		fd, err = unix.Openat(dirfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if !errors.Is(err, unix.EEXIST) {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("write %s: %w", path, &fs.PathError{Op: "create", Path: tmp, Err: err})
	}
	renamed := false
	defer func() {
		if !renamed {
			_ = unix.Unlinkat(dirfd, tmp, 0)
		}
	}()
	f := os.NewFile(uintptr(fd), tmp)
	if err := writeSync(f, data, mode, uid, gid); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := unix.Renameat(dirfd, tmp, dirfd, base); err != nil {
		return fmt.Errorf("write %s: %w", path, &os.LinkError{Op: "rename", Old: tmp, New: base, Err: err})
	}
	renamed = true
	return syncAt(dirfd)
}

// Rename renames oldPath to newPath relative to their checked parent directories and syncs the new one.
func Rename(oldPath, newPath string) error {
	oldfd, oldBase, err := openParent(oldPath, false, 0)
	if err != nil {
		return fmt.Errorf("rename %s: %w", oldPath, err)
	}
	defer func() { _ = unix.Close(oldfd) }()
	newfd, newBase, err := openParent(newPath, false, 0)
	if err != nil {
		return fmt.Errorf("rename %s: %w", newPath, err)
	}
	defer func() { _ = unix.Close(newfd) }()
	if err := unix.Renameat(oldfd, oldBase, newfd, newBase); err != nil {
		return &os.LinkError{Op: "rename", Old: oldPath, New: newPath, Err: err}
	}
	return syncAt(newfd)
}

// Remove deletes path (a file, or an empty directory like os.Remove) relative to its checked parent directory. A
// missing file or parent is an error that matches fs.ErrNotExist.
func Remove(path string) error {
	fd, base, err := openParent(path, false, 0)
	if err != nil {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	defer func() { _ = unix.Close(fd) }()
	err = unix.Unlinkat(fd, base, 0)
	if errors.Is(err, unix.EISDIR) {
		err = unix.Unlinkat(fd, base, unix.AT_REMOVEDIR)
	}
	if err != nil {
		return &fs.PathError{Op: "remove", Path: path, Err: err}
	}
	return nil
}
