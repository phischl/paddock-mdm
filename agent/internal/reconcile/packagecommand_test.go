package reconcile_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
)

// TestPackageCommandKillsTheProcessGroup: a package run that exceeds its timeout is killed together with the
// processes it started (maintainer scripts), and the error says it timed out (plan M4b.1 step 6).
func TestPackageCommandKillsTheProcessGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	start := time.Now()
	_, _, err := reconcile.PackageCommand(context.Background(), time.Second, "sh", "-c",
		"sleep 300 & echo $! > "+pidFile+"; wait")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 15*time.Second {
		t.Fatalf("after %s: %v, want a timeout", time.Since(start), err)
	}
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
	deadline := time.Now().Add(5 * time.Second)
	for syscall.Kill(pid, 0) == nil {
		if time.Now().After(deadline) {
			t.Fatalf("child %d of the killed run still lives", pid)
		}
		time.Sleep(50 * time.Millisecond)
	}

	out, exit, err := reconcile.PackageCommand(context.Background(), time.Minute, "sh", "-c", "echo done; exit 3")
	if err != nil || exit != 3 || out != "done\n" {
		t.Fatalf("normal run: %q %d %v", out, exit, err)
	}
}

// TestPackageCommandRunsInTheCLocale (review 1): apt's output is parsed, so it must not be translated in the
// device's locale.
func TestPackageCommandRunsInTheCLocale(t *testing.T) {
	t.Setenv("LANG", "de_DE.UTF-8")
	t.Setenv("LC_ALL", "de_DE.UTF-8")
	out, exit, err := reconcile.PackageCommand(context.Background(), time.Minute, "sh", "-c", "echo $LC_ALL $DEBIAN_FRONTEND")
	if err != nil || exit != 0 || out != "C noninteractive\n" {
		t.Fatalf("%q %d %v", out, exit, err)
	}
}
