package luks

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

// commandTimeout bounds one tool run; systemd-cryptenroll derives keys with Argon2 or PBKDF2 for seconds.
const commandTimeout = 2 * time.Minute

// waitDelay bounds how long a killed tool may keep its output pipes open, so that a stuck child cannot hold up its
// caller after the timeout (plan M4c.1, review round 1).
const waitDelay = 5 * time.Second

// tools are the only commands OS runs.
var tools = []string{"findmnt", "lsblk", "cryptsetup", "systemd-cryptenroll"}

// OS runs the tools of a real device.
type OS struct{}

// Command implements Tools.
func (OS) Command(ctx context.Context, env []string, name string, args ...string) (string, string, int, error) {
	if !slices.Contains(tools, name) {
		return "", "", -1, errors.New("luks: not a LUKS tool: " + name)
	}
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // fixed tools; arguments are device paths and flags
	cmd.WaitDelay = waitDelay
	// Tools must not talk to the supervisor's notification socket (systemd logs every such message as refused).
	cmd.Env = append(slices.DeleteFunc(os.Environ(), func(e string) bool { return strings.HasPrefix(e, "NOTIFY_SOCKET=") }), env...)
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
