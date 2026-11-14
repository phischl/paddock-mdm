package uninstall

import (
	"os"
	"syscall"
	"testing"
)

// TestMain pins the umask to the 022 of a systemd service: under a user umask of 002, t.TempDir and the fixtures'
// directories would be group-writable, which the parent rule (fsutil.ErrParentNotTrusted) refuses.
func TestMain(m *testing.M) {
	syscall.Umask(0o022)
	os.Exit(m.Run())
}
