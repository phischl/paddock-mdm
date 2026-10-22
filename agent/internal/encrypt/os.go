package encrypt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"syscall"
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

// tools are the only commands OS runs (plan M8e decisions 1 and 32). They are the system's tools from PATH; the
// conversion places no executable of its own below a mount that may be noexec (decision 29), and the one binary of
// its own it starts, the background helper, runs from the agent's slot only after the statfs check of decision 30.
var tools = []string{"findmnt", "lsblk", "blkid", "lvm", "blockdev", "dumpe2fs", "systemctl", "dracut", "lsinitrd",
	"lsinitramfs", "apt-get", "dpkg-query", "udevadm", "systemd-run", "cryptsetup", "nice", "modprobe", "loginctl",
	"getent"}

// Host is the device a preparation and a cleanup change (plan M8e decisions 13 and 14): System plus the long tool runs
// (apt-get install, dracut), which have their own bound and are killed with their process group.
type Host interface {
	System
	// CommandWithin runs a tool like Command, bounded by timeout, with env added to its environment.
	CommandWithin(ctx context.Context, timeout time.Duration, env []string, name string, args ...string) (stdout, stderr string,
		exit int, err error)
	// LockPackages takes dpkg's locks as apt does, without waiting; ErrPackagesBusy while apt or dpkg runs. The initrd
	// changes of a conversion hold them, so that a kernel package's own dracut run cannot overwrite a verified initrd
	// or rebuild one in the middle (amendment 2026-10-21, item 14).
	LockPackages() (unlock func(), err error)
	// FreeBytes is the space root may still use on the file system holding dir (a new initrd's room in /boot,
	// amendment 2026-10-21, item 19).
	FreeBytes(dir string) (int64, error)
}

// ErrPackagesBusy is a package run (apt, dpkg) holding dpkg's locks: the initrd change waits for the next full pass.
var ErrPackagesBusy = errors.New("a package run holds the dpkg lock")

// dpkgLocks are the locks apt takes, in its order: the frontend lock, then dpkg's own (held by dpkg run directly).
var dpkgLocks = []string{"/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock"}

// packagesMu guards dpkg's locks within this process: fcntl locks belong to the process, so a second section in
// another goroutine would get them as well and its close would release the first's.
var packagesMu sync.Mutex

// LockPackages implements Host with fcntl write locks, as apt and dpkg take them.
func (OS) LockPackages() (func(), error) { return lockFiles(dpkgLocks) }

// lockFiles takes fcntl write locks on paths in order, without waiting.
func lockFiles(paths []string) (func(), error) {
	if !packagesMu.TryLock() {
		return nil, ErrPackagesBusy
	}
	var held []*os.File
	unlock := func() {
		for _, f := range held {
			_ = f.Close() // closing the descriptor releases its fcntl lock
		}
		packagesMu.Unlock()
	}
	for _, path := range paths {
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o640) //nolint:gosec // dpkg's fixed lock files
		if err != nil {
			unlock()
			return nil, err
		}
		lock := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: 0}
		if err := syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, &lock); err != nil {
			_ = f.Close()
			unlock()
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EACCES) {
				return nil, ErrPackagesBusy
			}
			return nil, fmt.Errorf("lock %s: %w", path, err)
		}
		held = append(held, f)
	}
	return unlock, nil
}

// OS is the System of a real device.
type OS struct{}

// Command implements System.
func (o OS) Command(ctx context.Context, name string, args ...string) (string, string, int, error) {
	return o.CommandWithin(ctx, commandTimeout, nil, name, args...)
}

// CommandWithin implements Host. The tool runs in a process group of its own that is killed as a whole at the
// timeout: maintainer scripts of apt-get and dracut's helpers must not outlive a run the agent gave up on. A timeout
// is an error that wraps context.DeadlineExceeded.
func (OS) CommandWithin(ctx context.Context, timeout time.Duration, env []string, name string, args ...string) (string, string, int, error) {
	if !slices.Contains(tools, name) {
		return "", "", -1, errors.New("encrypt: not an encryption tool: " + name)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // fixed tools; arguments are device paths and flags
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = waitDelay
	// Tools must not talk to the supervisor's notification socket (systemd logs every such message as refused); the
	// C locale keeps the output the parsers read stable.
	cmd.Env = append(append(slices.DeleteFunc(os.Environ(), func(e string) bool {
		return strings.HasPrefix(e, "NOTIFY_SOCKET=") || strings.HasPrefix(e, "LC_ALL=")
	}), "LC_ALL=C"), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return stdout.String(), stderr.String(), -1, fmt.Errorf("%s: %w", name, ctx.Err())
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return stdout.String(), stderr.String(), exit.ExitCode(), nil
	}
	if err != nil {
		return "", "", -1, err
	}
	return stdout.String(), stderr.String(), 0, nil
}

// FreeBytes implements Host with statfs.
func (OS) FreeBytes(dir string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	// Bfree, not Bavail: the agent runs as root and may use the blocks reserved for root (amendment item 19).
	return int64(st.Bfree) * st.Bsize, nil //nolint:gosec // block counts of a real file system fit in int64
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
