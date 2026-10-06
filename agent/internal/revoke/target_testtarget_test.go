//go:build paddock_revoke_testtarget

package revoke

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestTestTarget: a test build erases the device named in the override and writes the would-reboot marker instead of
// rebooting.
func TestTestTarget(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/paddock"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, TestTargetFile), []byte("/dev/loop7\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	o := OS{Root: root}
	if dev, err := o.RootDevice(context.Background()); err != nil || dev != "/dev/loop7" {
		t.Fatalf("test target %q %v", dev, err)
	}
	if err := o.Reboot(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, WouldRebootFile)); err != nil {
		t.Fatalf("would-reboot marker: %v", err)
	}
}
