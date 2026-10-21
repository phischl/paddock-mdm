package encrypt

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestLockFiles: final adversarial review, minor 5 (amendment item 16) — dpkg's locks are taken once per process: a
// second section in this process is busy until the first released them, and then gets them.
func TestLockFiles(t *testing.T) {
	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "lock-frontend"), filepath.Join(dir, "lock")}
	unlock, err := lockFiles(paths)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockFiles(paths); !errors.Is(err, ErrPackagesBusy) {
		t.Fatalf("second section: %v", err)
	}
	unlock()
	unlock, err = lockFiles(paths)
	if err != nil {
		t.Fatalf("after the release: %v", err)
	}
	unlock()
}

// TestLockFilesHeldByAnotherProcess: a lock another process holds (apt) is busy, not an error.
func TestLockFilesHeldByAnotherProcess(t *testing.T) {
	if os.Getenv("PADDOCK_LOCK_HELPER") != "" {
		unlock, err := lockFiles([]string{os.Getenv("PADDOCK_LOCK_HELPER")})
		if err != nil {
			os.Exit(2)
		}
		defer unlock()
		_, _ = os.Stdout.WriteString("locked\n")
		buf := make([]byte, 1)
		_, _ = os.Stdin.Read(buf)
		return
	}
	path := filepath.Join(t.TempDir(), "lock-frontend")
	cmd := exec.Command(os.Args[0], "-test.run", "^TestLockFilesHeldByAnotherProcess$") //nolint:gosec // the test binary
	cmd.Env = append(os.Environ(), "PADDOCK_LOCK_HELPER="+path)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	}()
	buf := make([]byte, 7)
	if _, err := stdout.Read(buf); err != nil || string(buf[:6]) != "locked" {
		t.Fatalf("helper: %q %v", buf, err)
	}
	if _, err := lockFiles([]string{path}); !errors.Is(err, ErrPackagesBusy) {
		t.Fatalf("held by another process: %v", err)
	}
}
