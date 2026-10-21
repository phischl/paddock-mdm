package encrypt

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"
)

// System is what the in-place encryption reads and runs on the device: its tools (stdout is returned separately
// from stderr, which alone may appear in errors) and its files. OS implements it; tests fake it.
type System interface {
	Command(ctx context.Context, name string, args ...string) (stdout, stderr string, exit int, err error)
	ReadFile(path string) ([]byte, error)
	// Stat reports whether path exists.
	Stat(path string) (bool, error)
}

// commandTimeout bounds one tool run (plan M8e decision 1).
const commandTimeout = 2 * time.Minute

// waitDelay bounds how long a killed tool may keep its output pipes open, so that a stuck child cannot hold up its
// caller after the timeout.
const waitDelay = 5 * time.Second

// tools are the only commands OS runs (plan M8e decisions 1 and 32). They are run from PATH, never from below a
// mount that may be noexec (decision 29).
var tools = []string{"findmnt", "lsblk", "blkid", "lvm", "blockdev", "dumpe2fs", "systemctl", "dracut", "lsinitrd",
	"apt-get", "dpkg-query", "udevadm", "systemd-run", "cryptsetup", "nice"}

// OS is the System of a real device.
type OS struct{}

// Command implements System.
func (OS) Command(ctx context.Context, name string, args ...string) (string, string, int, error) {
	if !slices.Contains(tools, name) {
		return "", "", -1, errors.New("encrypt: not an encryption tool: " + name)
	}
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // fixed tools; arguments are device paths and flags
	cmd.WaitDelay = waitDelay
	// Tools must not talk to the supervisor's notification socket (systemd logs every such message as refused); the
	// C locale keeps the output the parsers read stable.
	cmd.Env = append(slices.DeleteFunc(os.Environ(), func(e string) bool {
		return strings.HasPrefix(e, "NOTIFY_SOCKET=") || strings.HasPrefix(e, "LC_ALL=")
	}), "LC_ALL=C")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return stdout.String(), stderr.String(), exit.ExitCode(), nil
	}
	if err != nil {
		return "", "", -1, err
	}
	return stdout.String(), stderr.String(), 0, nil
}

// ReadFile implements System.
func (OS) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path) //nolint:gosec // fixed paths below the layout root
}

// Stat implements System.
func (OS) Stat(path string) (bool, error) {
	_, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}
