package reconcile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

// errLockTimeout is a lock that another holder kept past the wait.
var errLockTimeout = errors.New("lock held past the wait")

// lockFile takes an exclusive flock on path, trying once at once and then until deadline fires; the lock lasts until
// the returned file is closed, and ends with the process.
func lockFile(ctx context.Context, path string, deadline <-chan time.Time) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // the shield lock of the agent layout
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			_ = f.Close()
			return nil, fmt.Errorf("flock %s: %w", path, err)
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, ctx.Err()
		case <-deadline:
			_ = f.Close()
			return nil, errLockTimeout
		case <-time.After(shieldPoll):
		}
	}
}

// FrontendLockBusy returns a probe that reports whether another process holds dpkg's frontend lock at path (a POSIX
// record lock, as dpkg and apt take it). It never takes the lock itself; a missing or unreadable file is not busy.
func FrontendLockBusy(path string) func() bool {
	return func() bool {
		f, err := os.Open(path) //nolint:gosec // dpkg's frontend lock below the agent layout's root
		if err != nil {
			return false
		}
		defer func() { _ = f.Close() }()
		lk := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: 0}
		if err := syscall.FcntlFlock(f.Fd(), syscall.F_GETLK, &lk); err != nil {
			return false
		}
		return lk.Type != syscall.F_UNLCK
	}
}
