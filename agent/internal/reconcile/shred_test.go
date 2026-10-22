package reconcile_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
)

// TestShredNeverFollowsSymlink: amendment 2026-10-21 of plan M8e, item 19 — the install passphrase is overwritten
// through a handle that does not follow a link: a symlink at its path is not written through and its target stays.
func TestShredNeverFollowsSymlink(t *testing.T) {
	dir := t.TempDir()
	target, key := filepath.Join(dir, "other"), filepath.Join(dir, "install-passphrase")
	if err := os.WriteFile(target, []byte("someone else's file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, key); err != nil {
		t.Fatal(err)
	}
	if err := reconcile.Shred(key); err == nil {
		t.Fatal("shredded through a symlink")
	}
	if raw, _ := os.ReadFile(target); string(raw) != "someone else's file" { //nolint:gosec // a test path
		t.Fatalf("target %q", raw)
	}

	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(dir, "copy")
	if err := os.Link(key, copyPath); err != nil {
		t.Fatal(err)
	}
	if err := reconcile.Shred(key); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(copyPath); string(raw) != "\x00\x00\x00\x00\x00\x00" { //nolint:gosec // a test path
		t.Fatalf("not overwritten: %q", raw)
	}
}
