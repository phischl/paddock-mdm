package uninstall

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestDiscard (PDK-341): the preparation of a removal that does not run goes, and with it the directory below /root
// once it is empty; a summary of an earlier removal keeps the directory.
func TestDiscard(t *testing.T) {
	for name, tc := range map[string]struct {
		summary bool
		dirKept bool
	}{
		"empty afterwards": {summary: false, dirKept: false},
		"summary kept":     {summary: true, dirKept: true},
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "root", "paddock-uninstall")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			plan, bin, summary := filepath.Join(dir, "plan.json"), filepath.Join(dir, "paddockd"), filepath.Join(dir, "result.json")
			for _, f := range []string{plan, bin} {
				if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.summary {
				if err := os.WriteFile(summary, []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			Discard(context.Background(), plan, bin)
			for _, f := range []string{plan, bin} {
				if _, err := os.Stat(f); !os.IsNotExist(err) {
					t.Fatalf("%s kept: %v", f, err)
				}
			}
			if _, err := os.Stat(dir); (err == nil) != tc.dirKept {
				t.Fatalf("directory kept %v, want %v", err == nil, tc.dirKept)
			}
			if _, err := os.Stat(summary); tc.summary && err != nil {
				t.Fatalf("summary removed: %v", err)
			}
		})
	}
}

// TestDiscardMissing: a preparation that is already gone is no error and leaves nothing behind.
func TestDiscardMissing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "paddock-uninstall")
	Discard(context.Background(), filepath.Join(dir, "plan.json"), filepath.Join(dir, "paddockd"))
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("directory: %v", err)
	}
}
