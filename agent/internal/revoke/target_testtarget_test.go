//go:build paddock_revoke_testtarget

package revoke

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestTestTarget: a test build erases only the device named in the override, whatever /etc/crypttab lists (plan
// M4c.1 decision 1), and writes the would-reboot marker instead of rebooting.
func TestTestTarget(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/paddock"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, TestTargetFile), []byte("/dev/loop7\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, CrypttabFile), []byte("data /dev/vdb none luks\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	o := OS{Root: root}
	if tg, err := o.Targets(context.Background()); err != nil || !slices.Equal(tg.Devices, []string{"/dev/loop7"}) || len(tg.Unresolved) != 0 {
		t.Fatalf("test target %+v %v", tg, err)
	}
	if err := o.Reboot(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, WouldRebootFile)); err != nil {
		t.Fatalf("would-reboot marker: %v", err)
	}
}
