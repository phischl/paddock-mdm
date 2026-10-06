//go:build !paddock_revoke_testtarget

package revoke

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestReleaseRefusesTestTarget (plan M4c decision 13): a binary built without paddock_revoke_testtarget refuses every
// token while /etc/paddock/revoke-test-target exists, whatever it names.
func TestReleaseRefusesTestTarget(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/paddock"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, TestTargetFile), []byte("/dev/loop0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var refusal *Refusal
	if _, err := (OS{Root: root}).RootDevice(context.Background()); !errors.As(err, &refusal) || refusal.Reason != ReasonTestTarget {
		t.Fatalf("release build with a test target: %v", err)
	}
}
