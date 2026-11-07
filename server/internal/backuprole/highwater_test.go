package backuprole

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func readHighWater(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // a test file
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestRoundRecordsHighWater: every successful round raises the high-water file to the highest device.bundle_seq and
// never lowers it (decisions-alpha9 item 68).
func TestRoundRecordsHighWater(t *testing.T) {
	f := newFixture(t)
	f.engine.cfg.HighWaterFile = filepath.Join(t.TempDir(), "high-water")
	f.confirmKey()
	f.store.highWater = 1000003
	f.round(t)
	if got := readHighWater(t, f.engine.cfg.HighWaterFile); got != "1000003\n" {
		t.Fatalf("after the first round: %q, want 1000003", got)
	}
	f.store.highWater = 1000007
	f.round(t)
	if got := readHighWater(t, f.engine.cfg.HighWaterFile); got != "1000007\n" {
		t.Fatalf("after a compile: %q, want 1000007", got)
	}
	// A restore to an earlier point lowers the database's highest; the file keeps what devices may have applied.
	f.store.highWater = 5
	f.round(t)
	if got := readHighWater(t, f.engine.cfg.HighWaterFile); got != "1000007\n" {
		t.Fatalf("after a lower read: %q, want 1000007 kept", got)
	}
	fi, err := os.Stat(f.engine.cfg.HighWaterFile)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("mode %04o, want 0644 (the restore scripts read it)", fi.Mode().Perm())
	}
	if m, _ := filepath.Glob(filepath.Join(filepath.Dir(f.engine.cfg.HighWaterFile), ".high-water-*")); len(m) != 0 {
		t.Errorf("temporary files left: %v", m)
	}
}

// TestRoundHighWaterOnlyAfterSuccess: a round without a confirmed key or one that fails writes no file; a failed read
// of the sequence only warns and leaves the file as it was.
func TestRoundHighWaterOnlyAfterSuccess(t *testing.T) {
	f := newFixture(t)
	file := filepath.Join(t.TempDir(), "high-water")
	f.engine.cfg.HighWaterFile = file
	f.store.highWater = 42
	f.round(t)
	if got := readHighWater(t, file); got != "" {
		t.Fatalf("a round without a key wrote %q", got)
	}

	f.confirmKey()
	if err := os.RemoveAll(f.cfg.RepoDir); err != nil {
		t.Fatal(err)
	}
	if err := f.engine.Round(context.Background()); err == nil {
		t.Fatal("a round without its repository succeeded")
	}
	if got := readHighWater(t, file); got != "" {
		t.Fatalf("a failed round wrote %q", got)
	}

	if err := os.MkdirAll(f.cfg.RepoDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("7\n"), 0o644); err != nil { //nolint:gosec // a test file
		t.Fatal(err)
	}
	f.store.highWaterErr = errors.New("database down")
	f.round(t)
	if got := readHighWater(t, file); got != "7\n" {
		t.Fatalf("a failed read changed the file to %q", got)
	}
}

// TestRoundWithoutHighWaterFile: without a configured file the role writes none.
func TestRoundWithoutHighWaterFile(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	f.store.highWater = 9
	f.store.highWaterErr = errors.New("must not be read")
	f.round(t)
}

// TestRaiseHighWater: the file is raised, never lowered; content that is no number counts as 0, as in bundle-seq.sh.
func TestRaiseHighWater(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "high-water")
	for _, c := range []struct {
		before string
		v      int64
		want   string
	}{
		{"", 3, "3\n"},
		{"3\n", 2, "3\n"},
		{"3\n", 3, "3\n"},
		{"3\n", 2000001, "2000001\n"},
		{"garbage\n", 4, "4\n"},
		{"-9\n", 1, "1\n"},
	} {
		_ = os.Remove(file)
		if c.before != "" {
			if err := os.WriteFile(file, []byte(c.before), 0o644); err != nil { //nolint:gosec // a test file
				t.Fatal(err)
			}
		}
		if err := raiseHighWater(file, c.v); err != nil {
			t.Fatalf("%q + %d: %v", c.before, c.v, err)
		}
		if got := readHighWater(t, file); got != c.want {
			t.Errorf("%q + %d: %q, want %q", c.before, c.v, got, c.want)
		}
	}
	if err := raiseHighWater(filepath.Join(dir, "missing", "high-water"), 1); err == nil {
		t.Error("a missing directory is no error")
	}
}
