package revoke

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/fsutil"
	"github.com/phischl/paddock-mdm/agent/internal/luks"
)

// Files of the test target override (plan M4c decision 13): only a binary built with the tag
// paddock_revoke_testtarget erases the LUKS device named in TestTargetFile and writes WouldRebootFile instead of
// rebooting; a release binary refuses every token while TestTargetFile exists.
const (
	TestTargetFile  = "/etc/paddock/revoke-test-target"
	WouldRebootFile = "/run/paddock/revoke-would-reboot"
)

// commandTimeout bounds loginctl and systemctl.
const commandTimeout = 30 * time.Second

// OS is the System of a real device. Root prefixes the files of paddock-revoke ("" or "/" on a device, a temporary
// directory in tests).
type OS struct {
	luks.OS
	Root string
}

func (o OS) path(p string) string { return filepath.Join("/", o.Root, p) }

// Loginctl implements System.
func (OS) Loginctl(ctx context.Context, args ...string) (string, int, error) {
	return command(ctx, "loginctl", args...)
}

// ReadFile implements System.
func (o OS) ReadFile(path string) ([]byte, error) { return os.ReadFile(o.path(path)) } //nolint:gosec // fixed paths of paddock-revoke

// WriteFile implements System: atomically, 0600 in a 0700 directory.
func (o OS) WriteFile(path string, data []byte) error {
	return fsutil.WriteFile(o.path(path), data, 0o600, 0o700)
}

func command(ctx context.Context, name string, args ...string) (string, int, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // fixed tools; arguments are UIDs and fixed flags
	// A killed loginctl or systemctl must not hold up the sequence with its pipes (plan M4c.1, review round 1).
	cmd.WaitDelay = 5 * time.Second
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return out.String(), exit.ExitCode(), nil
	}
	if err != nil {
		return "", -1, err
	}
	return out.String(), 0, nil
}
