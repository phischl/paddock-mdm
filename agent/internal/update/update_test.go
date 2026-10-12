package update

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/fsutil"
	"github.com/phischl/paddock-mdm/agent/internal/paths"
)

func stageFiles(t *testing.T, l paths.Layout, names ...string) {
	t.Helper()
	for _, n := range names {
		if err := fsutil.WriteFile(filepath.Join(l.Staging(), n), []byte("x"), 0o600, 0o700); err != nil {
			t.Fatal(err)
		}
	}
}

func stagingEntries(t *testing.T, l paths.Layout) []string {
	t.Helper()
	entries, err := os.ReadDir(l.Staging())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestSweepRemovesReleasesWithoutRequest(t *testing.T) {
	l := paths.Layout{Root: t.TempDir()}
	stageFiles(t, l, "9.1.0/paddockd", "9.1.0/paddockd.minisig", "9.2.0/paddockd", ".request.json.tmp-1")
	if err := Sweep(l); err != nil {
		t.Fatal(err)
	}
	if left := stagingEntries(t, l); len(left) != 0 {
		t.Fatalf("left in staging: %v", left)
	}
}

func TestSweepKeepsEverythingWhileRequested(t *testing.T) {
	l := paths.Layout{Root: t.TempDir()}
	stageFiles(t, l, "9.1.0/paddockd", "9.0.0/paddockd", "request.json")
	if err := Sweep(l); err != nil {
		t.Fatal(err)
	}
	if left := stagingEntries(t, l); !slices.Equal(left, []string{"9.0.0", "9.1.0", "request.json"}) {
		t.Fatalf("left in staging: %v", left)
	}
}

func TestSweepWithoutStagingDirectory(t *testing.T) {
	if err := Sweep(paths.Layout{Root: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
}
