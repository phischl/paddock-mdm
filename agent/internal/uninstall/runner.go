package uninstall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"time"
)

// RunOS runs a tool on the device non-interactively (DEBIAN_FRONTEND=noninteractive, the C locale) in a process
// group of its own and kills the group at timeout, so that no maintainer script outlives a run the helper gave up on.
func RunOS(ctx context.Context, timeout time.Duration, name string, args ...string) (string, int, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // fixed tools of the removal
	cmd.Env = append(slices.DeleteFunc(os.Environ(), func(e string) bool { return strings.HasPrefix(e, "NOTIFY_SOCKET=") }),
		"DEBIAN_FRONTEND=noninteractive", "LC_ALL=C")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 10 * time.Second
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if ctx.Err() != nil {
		return out.String(), -1, fmt.Errorf("%s: %w", name, ctx.Err())
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return out.String(), exit.ExitCode(), nil
	}
	if err != nil {
		return out.String(), -1, err
	}
	return out.String(), 0, nil
}
