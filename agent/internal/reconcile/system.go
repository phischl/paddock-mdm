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
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/paddock-mdm/paddock/agent/internal/fsutil"
)

// commandTimeout bounds every call of systemctl, timedatectl, loginctl, getent, sudo, visudo, gpasswd and dpkg-query.
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

// PackageVersion implements System.
func (o OS) PackageVersion(name string) string {
	if !o.PackageInstalled(name) {
		return ""
	}
	out, exit, err := command(context.Background(), "dpkg-query", "--show", "--showformat=${Version}", name)
	if err != nil || exit != 0 {
		return ""
	}
	return strings.TrimSpace(out)
}

// aptTimeout bounds one apt-get run; apt itself waits up to 10 minutes for the dpkg lock (plan M3b risk R1).
const aptTimeout = 30 * time.Minute

// AptGet implements System.
func (o OS) AptGet(ctx context.Context, args ...string) (string, int, error) {
	if o.testRoot() {
		return "", -1, errTestRoot
	}
	return commandEnv(ctx, aptTimeout, []string{"DEBIAN_FRONTEND=noninteractive"}, "apt-get", args...)
}

// Loginctl implements System.
func (o OS) Loginctl(ctx context.Context, args ...string) (string, int, error) {
	if o.testRoot() {
		return "", -1, errTestRoot
	}
	return command(ctx, "loginctl", args...)
}

// Getent implements System. "--" keeps a key that starts with '-' from being read as an option (plan M4a step 0a).
func (o OS) Getent(ctx context.Context, database, key string) (string, int, error) {
	if o.testRoot() {
		return "", -1, errTestRoot
	}
	return command(ctx, "getent", database, "--", key)
}

// Visudo implements System.
func (o OS) Visudo(ctx context.Context, path string, args ...string) (string, int, error) {
	if o.testRoot() {
		return "", -1, errTestRoot
	}
	return command(ctx, path, args...)
}

// SudoVersion implements System.
func (o OS) SudoVersion(ctx context.Context, path string) (string, int, error) {
	if o.testRoot() {
		return "", -1, errTestRoot
	}
	return command(ctx, path, "--version")
}

// EvalSymlinks implements System.
func (o OS) EvalSymlinks(path string) (string, error) {
	if o.testRoot() {
		return "", errTestRoot
	}
	return filepath.EvalSymlinks(path)
}

// Dconf implements System.
func (o OS) Dconf(ctx context.Context, args ...string) (string, int, error) {
	if o.testRoot() {
		return "", -1, errTestRoot
	}
	return command(ctx, "dconf", args...)
}

// Gpasswd implements System.
func (o OS) Gpasswd(ctx context.Context, args ...string) (string, int, error) {
	if o.testRoot() {
		return "", -1, errTestRoot
	}
	return command(ctx, "gpasswd", args...)
}

// userTools are the account tools UserTool runs (the managed local administrator, plan M4a decision 15).
var userTools = []string{"useradd", "usermod", "passwd"}

// UserTool runs useradd, usermod or passwd; callers put "--" before the account name.
func (o OS) UserTool(ctx context.Context, tool string, args ...string) (string, int, error) {
	if o.testRoot() {
		return "", -1, errTestRoot
	}
	if !slices.Contains(userTools, tool) {
		return "", -1, errors.New("reconcile: not an account tool: " + tool)
	}
	return command(ctx, tool, args...)
}

// Chpasswd runs chpasswd with input ("name:password\n") on stdin, so the password never appears in a process
// list; the output never contains it. The crypt method makes chpasswd hash the password itself instead of going
// through PAM, where pam_himmelblau would handle it.
func (o OS) Chpasswd(ctx context.Context, input []byte) (string, int, error) {
	if o.testRoot() {
		return "", -1, errTestRoot
	}
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "chpasswd", "--crypt-method", "SHA512")
	cmd.Env = slices.DeleteFunc(os.Environ(), func(e string) bool { return strings.HasPrefix(e, "NOTIFY_SOCKET=") })
	cmd.Stdin = bytes.NewReader(input)
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return string(out), exit.ExitCode(), nil
	}
	if err != nil {
		return "", -1, err
	}
	return string(out), 0, nil
}

// Rename implements System.
func (o OS) Rename(oldPath, newPath string) error {
	if err := os.Rename(o.path(oldPath), o.path(newPath)); err != nil {
		return err
	}
	return fsutil.SyncDir(o.path(filepath.Dir(newPath)))
}

// ReadDir implements System.
func (o OS) ReadDir(path string) ([]string, error) {
	entries, err := os.ReadDir(o.path(path))
	if err != nil {
		return nil, err
	}
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name()
	}
	return names, nil
}

// command runs a tool and returns its stdout and exit code; err is set only if it could not run.
func command(ctx context.Context, name string, args ...string) (string, int, error) {
	return commandEnv(ctx, commandTimeout, nil, name, args...)
}

// commandEnv is command with a timeout and extra environment variables.
func commandEnv(ctx context.Context, timeout time.Duration, env []string, name string, args ...string) (string, int, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // fixed tools; arguments are policy-checked unit names
	// Tools must not talk to the supervisor's notification socket (systemd logs every such message as refused).
	cmd.Env = append(slices.DeleteFunc(os.Environ(), func(e string) bool { return strings.HasPrefix(e, "NOTIFY_SOCKET=") }), env...)
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
