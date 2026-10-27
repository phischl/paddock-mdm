package system

import (
	"context"
	"errors"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// rebootInhibitTimeout bounds how long a reboot waits for block inhibitors: the agent's first APT run (Himmelblau)
// takes about a minute, a slow mirror several.
const rebootInhibitTimeout = 15 * time.Minute

// rebootOutcome is how the guest answered `systemctl reboot`.
type rebootOutcome int

const (
	// rebootAccepted: the reboot is under way (or the connection broke as the guest went down; requireRebooted or
	// the caller's wait for the next boot proves it).
	rebootAccepted rebootOutcome = iota
	// rebootInhibited: logind refused the reboot for a block inhibitor (APT 3.2 holds one during dpkg, PDK-462).
	rebootInhibited
	// rebootFailed: refused for any other reason.
	rebootFailed
)

// classifyReboot decides on the answer to `sudo systemctl reboot` over SSH: out is its output, code the exit code of
// ssh (-1 when ssh was killed, e.g. by the context, as the guest went down), inhibitors the shutdown block inhibitors
// listed after a refusal.
func classifyReboot(out string, code int, inhibitors []string) rebootOutcome {
	switch {
	case code == 0, code == 255, code == -1:
		// ssh exits 255 when the guest drops the connection while shutting down.
		return rebootAccepted
	case strings.Contains(out, "inhibit"), len(inhibitors) > 0:
		return rebootInhibited
	default:
		return rebootFailed
	}
}

// shutdownBlockers returns the lines of `systemd-inhibit --list` that block a shutdown (WHAT includes shutdown, MODE
// is block). WHO and WHY may contain blanks, so the columns are anchored on the numeric UID and PID
// (WHO… UID USER PID COMM WHAT WHY… MODE).
func shutdownBlockers(list string) []string {
	numeric := func(s string) bool { _, err := strconv.Atoi(s); return err == nil }
	var lines []string
	for _, line := range strings.Split(list, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 7 || fields[len(fields)-1] != "block" {
			continue
		}
		for i := 1; i+4 < len(fields)-1; i++ {
			if numeric(fields[i]) && numeric(fields[i+2]) {
				if slices.Contains(strings.Split(fields[i+4], ":"), "shutdown") {
					lines = append(lines, strings.Join(fields, " "))
				}
				break
			}
		}
	}
	return lines
}

// sshExitCode is the exit code of an SSH call: 0 without error, -1 when ssh did not exit by itself.
func sshExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	return -1
}

// bootID is the guest's /proc/sys/kernel/random/boot_id, which changes with every boot.
func (v *VM) bootID(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, err := v.SSH(ctx, nil, "cat /proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatalf("%s: read the boot ID: %v: %s", v.Name, err, out)
	}
	return strings.TrimSpace(out)
}

// requestReboot asks the guest to reboot, retrying while a block inhibitor holds the shutdown off, and waits until
// SSH is gone; it returns the boot ID before the reboot for requireRebooted. It never overrides the inhibitors
// (systemctl -i): that would cut a package run in half.
func (v *VM) requestReboot(t *testing.T) string {
	t.Helper()
	before := v.bootID(t)
	deadline := time.Now().Add(rebootInhibitTimeout)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		out, err := v.SSH(ctx, nil, "sudo systemctl reboot")
		var blockers []string
		code := sshExitCode(err)
		if code > 0 && code != 255 {
			list, _ := v.SSH(ctx, nil, "systemd-inhibit --list --no-pager")
			blockers = shutdownBlockers(list)
		}
		cancel()
		switch classifyReboot(out, code, blockers) {
		case rebootAccepted:
			v.waitSSHDown(t)
			return before
		case rebootInhibited:
			if time.Now().After(deadline) {
				t.Fatalf("%s: reboot still inhibited after %s: %s; inhibitors: %q", v.Name, rebootInhibitTimeout,
					strings.TrimSpace(out), blockers)
			}
			t.Logf("%s: reboot inhibited, retrying: %s; inhibitors: %q", v.Name, strings.TrimSpace(out), blockers)
			time.Sleep(10 * time.Second)
		default:
			t.Fatalf("%s: sudo systemctl reboot failed: %v: %s", v.Name, err, out)
		}
	}
}

// requireRebooted fails the test unless the guest, answering SSH again, runs a boot other than before: an sshd
// restart during a refused reboot also takes SSH down for a moment (PDK-462).
func (v *VM) requireRebooted(t *testing.T, before string) {
	t.Helper()
	if after := v.bootID(t); after == before {
		t.Fatalf("%s did not reboot: boot ID %s unchanged", v.Name, before)
	}
}
