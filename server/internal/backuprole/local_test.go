package backuprole

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveLocal(t *testing.T) {
	owner := uint32(os.Getuid())
	root := t.TempDir()
	if err := os.Chmod(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "nas", "a"), 0o750); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "nas", "sub")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := resolveLocal(root, "nas/a", owner)
	if err != nil || got != filepath.Join(root, "nas", "a") {
		t.Fatalf("ResolveLocal = %q, %v", got, err)
	}
	for name, sub := range map[string]string{
		"absolute": "/etc", "dotdot": "nas/../..", "empty": "", "symlink first": "link", "symlink inner": "nas/sub/x",
		"symlink last": "nas/sub", "missing": "nope", "file": "file",
	} {
		if _, err := resolveLocal(root, sub, owner); err == nil {
			t.Errorf("%s: %q accepted", name, sub)
		} else if !errors.Is(err, ErrLocalPath) {
			t.Errorf("%s: error %v is not ErrLocalPath", name, err)
		}
	}
	if _, err := resolveLocal(filepath.Join(root, "link"), "x", owner); err == nil {
		t.Error("a symlinked root was accepted")
	}
	if _, err := resolveLocal("relative", "x", owner); err == nil {
		t.Error("a relative root was accepted")
	}
}

func TestResolveLocalRoot(t *testing.T) {
	for _, root := range []string{"/", "/srv", "/srv/", "/srv//x", "/srv/x/../y"} {
		if got, err := ResolveLocal(root, "etc"); err == nil || !errors.Is(err, ErrLocalPath) {
			t.Errorf("root %q: %q, %v; want ErrLocalPath", root, got, err)
		}
	}
}

// TestResolveLocalParents covers the swap after the check: the kernel resolves the bind mount again on every start,
// so a parent that is not the owner's or that others can write must be refused.
func TestResolveLocalParents(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "nas", "a"), 0o750); err != nil {
		t.Fatal(err)
	}
	owner := uint32(os.Getuid())
	if _, err := resolveLocal(root, "nas/a", owner); err != nil {
		t.Fatalf("private parents: %v", err)
	}
	if _, err := resolveLocal(root, "nas/a", owner+1); err == nil {
		t.Error("parents of another owner were accepted")
	}
	// the leaf is the mount source itself and may belong to anyone
	if _, err := resolveLocal(root, "nas", owner+1); err == nil {
		t.Error("the root of another owner was accepted")
	}
	if err := os.Chmod(filepath.Join(root, "nas"), 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveLocal(root, "nas/a", owner); err == nil {
		t.Error("a group-writable parent was accepted")
	}
	if _, err := resolveLocal(root, "nas", owner); err != nil {
		t.Errorf("a group-writable leaf: %v", err)
	}
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveLocal(root, "nas", owner); err == nil {
		t.Error("a world-writable root was accepted")
	}
	if _, err := ResolveLocal(t.TempDir(), "x"); os.Getuid() != 0 && err == nil {
		t.Error("the exported resolver accepted parents that are not root's")
	}
}
