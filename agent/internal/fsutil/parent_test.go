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
		name      string
		path      string
		uid, mode uint32
		euid      int
		ok        bool
	}{
		{"root 0755", "/etc/app", 0, dir | 0o755, 0, true},
		{"root 0700", "/etc/app", 0, dir | 0o700, 1000, true},
		{"own user", "/srv/test", 1000, dir | 0o755, 1000, true},
		{"service user", "/opt/app", 999, dir | 0o755, 0, false},
		{"service user, agent not root", "/opt/app", 999, dir | 0o755, 1000, false},
		{"group-writable root", "/var/log", 0, dir | 0o775, 0, false},
		{"other-writable root", "/opt/app", 0, dir | 0o757, 0, false},
		{"/tmp sticky", "/tmp", 0, sticky | 0o777, 0, true},
		{"/var/tmp sticky", "/var/tmp", 0, sticky | 0o777, 0, true},
		{"/tmp not sticky", "/tmp", 0, dir | 0o777, 0, false},
		{"/tmp sticky, not root", "/tmp", 1000, sticky | 0o777, 1000, false},
		{"sticky outside the allow list", "/srv/drop", 0, sticky | 0o777, 0, false},
		{"below /tmp", "/tmp/x", 0, sticky | 0o777, 0, false},
		{"symlink", "/opt/app", 0, unix.S_IFLNK | 0o777, 0, false},
		{"regular file", "/opt/app", 0, unix.S_IFREG | 0o755, 0, false},
	} {
		err := checkDir(c.path, c.uid, c.mode, c.euid)
		if (err == nil) != c.ok || (err != nil && !errors.Is(err, ErrParentNotTrusted)) {
			t.Errorf("%s: %v, want ok=%v", c.name, err, c.ok)
		}
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
