package reconcile

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/paddock-mdm/paddock/agent/internal/fsutil"
)

// commandTimeout bounds every systemctl, timedatectl and dpkg-query call.
const commandTimeout = 2 * time.Minute

// OS is the System of a real device. Root prefixes every file path (tests use a temporary directory).
type OS struct{ Root string }

func (o OS) path(p string) string { return filepath.Join(o.Root, p) }

// ReadFile implements System.
func (o OS) ReadFile(path string) ([]byte, fs.FileInfo, error) {
	info, err := os.Lstat(o.path(path))
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, info, nil
	}
	data, err := os.ReadFile(o.path(path))
	if err != nil {
		return nil, nil, err
	}
	if data == nil {
		data = []byte{} // an empty regular file is not "not a regular file"
	}
	return data, info, nil
}

// WriteFileAtomic implements System.
func (o OS) WriteFileAtomic(path string, data []byte, mode fs.FileMode, uid, gid int) error {
	if err := o.mkdirs(filepath.Dir(path)); err != nil {
		return err
	}
	return fsutil.WriteFileOwned(o.path(path), data, mode, 0o755, uid, gid)
}

// mkdirs creates missing parent directories 0755, owned by root:root when running as root.
func (o OS) mkdirs(dir string) error {
	if _, err := os.Stat(o.path(dir)); err == nil || dir == "/" {
		return nil
	}
	if err := o.mkdirs(filepath.Dir(dir)); err != nil {
		return err
	}
	if err := os.Mkdir(o.path(dir), 0o755); err != nil && !errors.Is(err, fs.ErrExist) { //nolint:gosec // plan M2b decision 10: parents 0755 root:root
		return err
	}
	if os.Geteuid() == 0 {
		return os.Chown(o.path(dir), 0, 0)
	}
	return nil
}

// Remove implements System.
func (o OS) Remove(path string) error { return os.Remove(o.path(path)) }

// LookupUser implements System.
func (o OS) LookupUser(name string) (int, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(u.Uid)
}

// LookupGroup implements System.
func (o OS) LookupGroup(name string) (int, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(g.Gid)
}

// Owner implements System.
func (o OS) Owner(info fs.FileInfo) (int, int) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1, -1
	}
	return int(st.Uid), int(st.Gid)
}

// errTestRoot keeps an agent that runs below a test root away from the host's services.
var errTestRoot = errors.New("services are not managed below a test root")

func (o OS) testRoot() bool { return filepath.Clean(o.Root) != "/" }

// Systemctl implements System.
func (o OS) Systemctl(ctx context.Context, args ...string) (string, int, error) {
	if o.testRoot() {
		return "", -1, errTestRoot
	}
	return command(ctx, "systemctl", args...)
}

// Timedatectl implements System.
func (o OS) Timedatectl(ctx context.Context, args ...string) (string, int, error) {
	if o.testRoot() {
		return "", -1, errTestRoot
	}
	return command(ctx, "timedatectl", args...)
}

// PackageInstalled implements System.
func (o OS) PackageInstalled(name string) bool {
	if o.testRoot() {
		return false
	}
	out, exit, err := command(context.Background(), "dpkg-query", "--show", "--showformat=${db:Status-Status}", name)
	return err == nil && exit == 0 && strings.TrimSpace(out) == "installed"
}

// command runs a tool and returns its stdout and exit code; err is set only if it could not run.
func command(ctx context.Context, name string, args ...string) (string, int, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // fixed tools; arguments are policy-checked unit names
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return stdout.String() + stderr.String(), exit.ExitCode(), nil
	}
	if err != nil {
		return "", -1, err
	}
	return stdout.String(), 0, nil
}
