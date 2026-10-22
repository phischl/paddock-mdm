package encrypt

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/paths"
)

// TestRemoveUnlistedFile: adversarial review of 71fee35e, low 3 — a regular name whose file the listing did not see
// (created or replaced in between) is not removed and fails closed, without a crash.
func TestRemoveUnlistedFile(t *testing.T) {
	l := paths.Layout{Root: t.TempDir()}
	if err := os.MkdirAll(l.Join("/boot"), 0o700); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(l.Root, "boot", "late-initrd")
	if err := os.WriteFile(name, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	removed, err := removeInitrdNames(context.Background(), l, []string{name})
	if raw, _ := os.ReadFile(name); err == nil || len(removed) != 0 || string(raw) != "key" { //nolint:gosec // a test path
		t.Fatalf("removed %v, err %v", removed, err)
	}
}

func blocks(t *testing.T, f *os.File) int64 {
	t.Helper()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	return info.Sys().(*syscall.Stat_t).Blocks
}

// TestZeroSparseAllocatesNothing: adversarial review of 71fee35e, medium 1 — overwriting a sparse file of 2 GiB writes
// its data only: it takes no more room afterwards than before, and the data reads as zeros.
func TestZeroSparseAllocatesNothing(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "initrd"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteAt([]byte(strings.Repeat("k", 8192)), 1<<30); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(2 << 30); err != nil {
		t.Fatal(err)
	}
	before := blocks(t, f)
	if err := zero(f, 2<<30, 0); err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 8192)
	if _, err := f.ReadAt(raw, 1<<30); err != nil || strings.Trim(string(raw), "\x00") != "" {
		t.Fatalf("data not overwritten: %v", err)
	}
	if after := blocks(t, f); after > before {
		t.Fatalf("the overwrite allocated room: %d blocks before, %d after", before, after)
	}
}

// failingFile fails every write after the first (no space left mid-write) and counts the writes.
type failingFile struct {
	*os.File
	writes int
}

func (f *failingFile) WriteAt(b []byte, off int64) (int, error) {
	f.writes++
	if f.writes > 1 {
		return 0, syscall.ENOSPC
	}
	return f.File.WriteAt(b, off)
}

// TestZeroFailedWriteEmpties: adversarial review of 71fee35e, medium 1 — a write that fails midway (ENOSPC) leaves no
// partly overwritten file taking room: it is emptied, and the caller unlinks it.
func TestZeroFailedWriteEmpties(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "initrd"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write([]byte(strings.Repeat("k", 3<<20))); err != nil {
		t.Fatal(err)
	}
	ff := &failingFile{File: f}
	if err := zero(ff, 3<<20, 0); err != nil || ff.writes != 2 {
		t.Fatalf("zero: %v after %d writes", err, ff.writes)
	}
	if info, err := f.Stat(); err != nil || info.Size() != 0 || blocks(t, f) != 0 {
		t.Fatalf("not emptied: %v", err)
	}
}

// TestZeroOnBtrfs: adversarial review of 71fee35e, medium 1 — on btrfs nothing is written (copy-on-write would
// allocate new blocks and keep the old ones); the caller only unlinks.
func TestZeroOnBtrfs(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "initrd"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write([]byte("key")); err != nil {
		t.Fatal(err)
	}
	ff := &failingFile{File: f}
	if err := zero(ff, 3, btrfsMagic); err != nil || ff.writes != 0 {
		t.Fatalf("zero: %v after %d writes", err, ff.writes)
	}
}
