package fsutil

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestMain pins the umask to the 022 of a systemd service: under a user umask of 002, t.TempDir would be
// group-writable, which the parent rule refuses.
func TestMain(m *testing.M) {
	syscall.Umask(0o022)
	os.Exit(m.Run())
}

func mkdir(t *testing.T, path string, mode fs.FileMode) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestWriteFileOwnedTrustedChain(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "etc", "app", "conf.d", "a.conf")
	if err := WriteFileOwned(target, []byte("v=1\n"), 0o640, 0o755, -1, -1); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "v=1\n" {
		t.Fatalf("content %q, %v", data, err)
	}
	if fi, _ := os.Stat(target); fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	for _, dir := range []string{filepath.Join(root, "etc"), filepath.Join(root, "etc", "app"), filepath.Dir(target)} {
		if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o755 {
			t.Fatalf("created %s with %v", dir, fi.Mode().Perm())
		}
	}
	if err := WriteFileOwned(target, []byte("v=2\n"), 0o600, 0o755, -1, -1); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Dir(target))
	if len(entries) != 1 {
		t.Fatalf("temporary files left: %v", entries)
	}
}

// TestWriteFileOwnedCreatesExactDirMode: a umask never loosens or tightens the mode of a created parent.
func TestWriteFileOwnedCreatesExactDirMode(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileOwned(filepath.Join(root, "d", "f"), nil, 0o644, 0o755, -1, -1); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Join(root, "d")); fi.Mode().Perm() != 0o755 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
}

func TestWriteFileOwnedRefusesSymlinkParent(t *testing.T) {
	root := t.TempDir()
	victim := filepath.Join(root, "sudoers.d")
	mkdir(t, victim, 0o755)
	mkdir(t, filepath.Join(root, "opt", "app"), 0o755)
	if err := os.Symlink(victim, filepath.Join(root, "opt", "app", "conf")); err != nil {
		t.Fatal(err)
	}
	err := WriteFileOwned(filepath.Join(root, "opt", "app", "conf", "x"), []byte("x"), 0o644, 0o755, -1, -1)
	if !errors.Is(err, ErrParentNotTrusted) {
		t.Fatalf("err %v, want ErrParentNotTrusted", err)
	}
	if entries, _ := os.ReadDir(victim); len(entries) != 0 {
		t.Fatalf("written through the symlink: %v", entries)
	}
}

func TestWriteFileOwnedRefusesWritableParent(t *testing.T) {
	for _, mode := range []fs.FileMode{0o775, 0o757, 0o777} {
		root := t.TempDir()
		dir := filepath.Join(root, "opt", "app")
		mkdir(t, dir, mode)
		err := WriteFileOwned(filepath.Join(dir, "sub", "x"), []byte("x"), 0o644, 0o755, -1, -1)
		if !errors.Is(err, ErrParentNotTrusted) {
			t.Fatalf("mode %v: err %v, want ErrParentNotTrusted", mode, err)
		}
		if _, err := os.Stat(filepath.Join(dir, "sub")); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("mode %v: directory created below an untrusted parent", mode)
		}
	}
}

func TestWriteFileOwnedRefusesFileAsParent(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileOwned(filepath.Join(root, "f", "x"), nil, 0o644, 0o755, -1, -1); !errors.Is(err, ErrParentNotTrusted) {
		t.Fatalf("err %v", err)
	}
}

func TestCheckDir(t *testing.T) {
	const dir, sticky = unix.S_IFDIR, unix.S_IFDIR | unix.S_ISVTX
	for _, c := range []struct {
		name           string
		path           string
		uid, gid, mode uint32
		euid           int
		acl            bool
		ok             bool
	}{
		{"root 0755", "/etc/app", 0, 0, dir | 0o755, 0, false, true},
		{"root 0700", "/etc/app", 0, 0, dir | 0o700, 1000, false, true},
		{"own user", "/srv/test", 1000, 1000, dir | 0o755, 1000, false, true},
		{"service user", "/opt/app", 999, 0, dir | 0o755, 0, false, false},
		{"service user, agent not root", "/opt/app", 999, 0, dir | 0o755, 1000, false, false},
		{"group-writable root, group adm", "/var/log", 0, 4, dir | 0o775, 0, false, false},
		{"other-writable root", "/opt/app", 0, 0, dir | 0o757, 0, false, false},
		{"/tmp sticky", "/tmp", 0, 0, sticky | 0o777, 0, false, true},
		{"/var/tmp sticky", "/var/tmp", 0, 0, sticky | 0o777, 0, false, true},
		{"/tmp not sticky", "/tmp", 0, 0, dir | 0o777, 0, false, false},
		{"/tmp sticky, not root", "/tmp", 1000, 1000, sticky | 0o777, 1000, false, false},
		{"sticky outside the allow list", "/srv/drop", 0, 0, sticky | 0o777, 0, false, false},
		{"below /tmp", "/tmp/x", 0, 0, sticky | 0o777, 0, false, false},
		{"symlink", "/opt/app", 0, 0, unix.S_IFLNK | 0o777, 0, false, false},
		{"regular file", "/opt/app", 0, 0, unix.S_IFREG | 0o755, 0, false, false},
		{"group-writable root:root (AccountsService on 26.04)", "/var/lib/AccountsService", 0, 0, dir | 0o775, 0, false, true},
		{"group-writable, root group, own user", "/srv/test", 1000, 0, dir | 0o775, 1000, false, true},
		{"group-writable, root group, service user", "/opt/app", 999, 0, dir | 0o775, 0, false, false},
		{"group-writable root, group of a user", "/opt/app", 0, 1000, dir | 0o775, 0, false, false},
		{"world-writable root:root", "/opt/app", 0, 0, dir | 0o777, 0, false, false},
		{"setgid group-writable root:root", "/opt/app", 0, 0, dir | unix.S_ISGID | 0o775, 0, false, true},
		{"group-writable root:root with access ACL", "/opt/app", 0, 0, dir | 0o775, 0, true, false},
		{"group-writable, root group, own user, access ACL", "/srv/test", 1000, 0, dir | 0o775, 1000, true, false},
		{"root 0755 with access ACL (mask without write)", "/opt/app", 0, 0, dir | 0o755, 0, true, true},
	} {
		err := checkDir(c.path, c.uid, c.gid, c.mode, c.euid, c.acl)
		if (err == nil) != c.ok || (err != nil && !errors.Is(err, ErrParentNotTrusted)) {
			t.Errorf("%s: %v, want ok=%v", c.name, err, c.ok)
		}
	}
}

// aclXattr encodes a POSIX access ACL in the kernel's xattr format (version 2, entries of tag, perm, id).
func aclXattr(entries ...[3]uint32) []byte {
	b := []byte{2, 0, 0, 0}
	for _, e := range entries {
		b = append(b, byte(e[0]), byte(e[0]>>8), byte(e[1]), byte(e[1]>>8),
			byte(e[2]), byte(e[2]>>8), byte(e[2]>>16), byte(e[2]>>24))
	}
	return b
}

func TestAccessACL(t *testing.T) {
	dir := t.TempDir()
	fd, err := unix.Open(dir, dirFlags, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if has, err := accessACL(fd); err != nil || has {
		t.Fatalf("plain directory: acl=%v, %v", has, err)
	}
	const undef = 0xffffffff
	// user::rwx user:<uid+1>:rwx group::r-x mask::rwx other::r-x, the shape `setfacl -m u:x:rwx` leaves on 0755.
	acl := aclXattr([3]uint32{0x01, 7, undef}, [3]uint32{0x02, 7, uint32(os.Getuid() + 1)},
		[3]uint32{0x04, 5, undef}, [3]uint32{0x10, 7, undef}, [3]uint32{0x20, 5, undef})
	if err := unix.Setxattr(dir, "system.posix_acl_access", acl, 0); err != nil {
		if errors.Is(err, unix.ENOTSUP) {
			t.Skipf("file system without POSIX ACLs: %v", err)
		}
		t.Fatal(err)
	}
	has, err := accessACL(fd)
	if err != nil || !has {
		t.Fatalf("directory with ACL: acl=%v, %v", has, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		t.Fatal(err)
	}
	if st.Mode&0o020 == 0 {
		t.Fatalf("mode %o: the ACL mask should show as group write", st.Mode)
	}
	if err := checkDir(dir, st.Uid, 0, st.Mode, os.Geteuid(), has); !errors.Is(err, ErrParentNotTrusted) {
		t.Fatalf("gid 0 parent with a named-user write ACL trusted: %v", err)
	}
}

func TestRename(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "etc")
	mkdir(t, dir, 0o755)
	if err := os.WriteFile(filepath.Join(dir, "a.tmp"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Rename(filepath.Join(dir, "a.tmp"), filepath.Join(dir, "a")); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(dir, "a")); err != nil || string(data) != "a" {
		t.Fatalf("renamed %q, %v", data, err)
	}
	victim := filepath.Join(root, "victim")
	mkdir(t, victim, 0o755)
	if err := os.Symlink(victim, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := Rename(filepath.Join(dir, "a"), filepath.Join(root, "link", "a")); !errors.Is(err, ErrParentNotTrusted) {
		t.Fatalf("rename into a symlinked parent: %v", err)
	}
	if err := Rename(filepath.Join(root, "link", "b"), filepath.Join(dir, "b")); !errors.Is(err, ErrParentNotTrusted) {
		t.Fatalf("rename out of a symlinked parent: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "a")); err != nil {
		t.Fatalf("refused rename moved the file: %v", err)
	}
}

func TestRemove(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "etc")
	mkdir(t, filepath.Join(dir, "empty"), 0o755)
	if err := os.WriteFile(filepath.Join(dir, "a"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Remove(filepath.Join(dir, "a")); err != nil {
		t.Fatal(err)
	}
	if err := Remove(filepath.Join(dir, "empty")); err != nil {
		t.Fatalf("empty directory: %v", err)
	}
	if err := Remove(filepath.Join(dir, "a")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
	if err := Remove(filepath.Join(root, "missing", "a")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing parent: %v", err)
	}

	victim := filepath.Join(root, "victim")
	mkdir(t, victim, 0o755)
	if err := os.WriteFile(filepath.Join(victim, "keep"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := Remove(filepath.Join(root, "link", "keep")); !errors.Is(err, ErrParentNotTrusted) {
		t.Fatalf("symlinked parent: %v", err)
	}
	gw := filepath.Join(root, "gw")
	mkdir(t, gw, 0o775)
	if err := os.WriteFile(filepath.Join(gw, "keep"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Remove(filepath.Join(gw, "keep")); !errors.Is(err, ErrParentNotTrusted) {
		t.Fatalf("group-writable parent: %v", err)
	}
	for _, p := range []string{filepath.Join(victim, "keep"), filepath.Join(gw, "keep")} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("refused remove deleted %s: %v", p, err)
		}
	}
}

func TestRelativePathRefused(t *testing.T) {
	if err := WriteFileOwned("etc/x", nil, 0o644, 0o755, -1, -1); err == nil {
		t.Fatal("relative path accepted")
	}
}
