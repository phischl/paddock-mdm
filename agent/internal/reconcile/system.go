package reconcile

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/fsutil"
	"github.com/phischl/paddock-mdm/agent/internal/sessions"
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

// WriteFileAtomic implements System. Missing parents are created 0755, owned by root:root when running as root (plan
// M2b decision 10); a parent that fails the parent rule refuses the write with ErrParentNotTrusted.
func (o OS) WriteFileAtomic(path string, data []byte, mode fs.FileMode, uid, gid int) error {
	return fsutil.WriteFileOwned(o.path(path), data, mode, 0o755, uid, gid)
}

// Remove implements System.
func (o OS) Remove(path string) error { return fsutil.Remove(o.path(path)) }

// LookupUser implements System from /etc/passwd, never through NSS: Himmelblau's NSS module answers for any user
// name with a synthetic entry (plan M5a step 0a), and os/user would ask NSS in a cgo build.
func (o OS) LookupUser(name string) (int, error) { return o.localID("/etc/passwd", name) }

// LookupGroup implements System from /etc/group, never through NSS.
func (o OS) LookupGroup(name string) (int, error) { return o.localID("/etc/group", name) }

// localID returns the numeric ID (third field) of name in a local account database.
func (o OS) localID(file, name string) (int, error) {
	data, _, err := o.ReadFile(file)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", file, err)
	}
	id, ok := sessions.LocalUIDs(data)[name]
	if !ok {
		return 0, fmt.Errorf("%s has no entry %s", file, name)
	}
	return id, nil
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

// Hostnamectl implements System.
func (o OS) Hostnamectl(ctx context.Context, args ...string) (string, int, error) {
	if o.testRoot() {
		return "", -1, errTestRoot
	}
	return command(ctx, "hostnamectl", args...)
}

// installedBuilds lists the architecture and version of every installed build of a package: one dpkg-query line per
// architecture, because a Multi-Arch package installed for two architectures would otherwise print its status twice
// on one line.
func (o OS) installedBuilds(name string) []packageBuild {
	if o.testRoot() {
		return nil
	}
	out, exit, err := command(context.Background(), "dpkg-query", "--show", "--showformat=${db:Status-Status} ${Architecture} ${Version}\n", name)
	if err != nil || exit != 0 {
		return nil
	}
	var builds []packageBuild
	for line := range strings.Lines(out) {
		if f := strings.Fields(line); len(f) == 3 && f[0] == "installed" {
			builds = append(builds, packageBuild{arch: f[1], version: f[2]})
		}
	}
	return builds
}

type packageBuild struct{ arch, version string }

// PackageInstalled implements System: a package installed for any architecture counts as installed (PDK-711).
func (o OS) PackageInstalled(name string) bool { return len(o.installedBuilds(name)) > 0 }

// PackageVersion implements System: the version of the native architecture's build, else of the first installed one.
func (o OS) PackageVersion(name string) string {
	builds := o.installedBuilds(name)
	if len(builds) == 0 {
		return ""
	}
	if len(builds) > 1 {
		native := o.nativeArchitecture()
		for _, b := range builds {
			if b.arch == native {
				return b.version
			}
		}
	}
	return builds[0].version
}

// PackageRemovalNames implements System: the plain name when the only installed build is the native (or an
// architecture-independent) one, else the name qualified with every installed architecture, native first. apt resolves
// a plain name to the native package, so it never removes a foreign build.
func (o OS) PackageRemovalNames(name string) []string {
	builds := o.installedBuilds(name)
	if len(builds) == 0 {
		return []string{name}
	}
	native := o.nativeArchitecture()
	if len(builds) == 1 && (builds[0].arch == native || builds[0].arch == "all") {
		return []string{name}
	}
	var names []string
	for _, b := range builds {
		if b.arch == native {
			names = slices.Insert(names, 0, name+":"+b.arch)
		} else {
			names = append(names, name+":"+b.arch)
		}
	}
	return names
}

func (o OS) nativeArchitecture() string {
	out, exit, err := command(context.Background(), "dpkg", "--print-architecture")
	if err != nil || exit != 0 {
		return ""
	}
	return strings.TrimSpace(out)
}

// PackageTimeout bounds one apt-get or dpkg run, including the 10 minutes apt waits for the dpkg lock (plan M3b risk
// R1); a run that takes longer is killed with its process group (plan M4b.1 step 6).
const PackageTimeout = 15 * time.Minute

// AptGet implements System.
func (o OS) AptGet(ctx context.Context, args ...string) (string, int, error) {
	if o.testRoot() {
		return "", -1, errTestRoot
	}
	return packageCommand(ctx, PackageTimeout, nil, "apt-get", args...)
}

// AptGetWithin runs apt-get like AptGet with another timeout (`paddockd updates run`, plan M5b decision 6).
func (o OS) AptGetWithin(ctx context.Context, timeout time.Duration, args ...string) (string, int, error) {
	if o.testRoot() {
		return "", -1, errTestRoot
	}
	return packageCommand(ctx, timeout, nil, "apt-get", args...)
}

// DpkgWithin runs dpkg like Dpkg with another timeout (`paddockd updates run`).
func (o OS) DpkgWithin(ctx context.Context, timeout time.Duration, args ...string) (string, int, error) {
	if o.testRoot() {
		return "", -1, errTestRoot
	}
	return packageCommand(ctx, timeout, nil, "dpkg", args...)
}

// AptCache implements System.
func (o OS) AptCache(ctx context.Context, args ...string) (string, int, error) {
	if o.testRoot() {
		return "", -1, errTestRoot
	}
	return command(ctx, "apt-cache", args...)
}

// AptMark implements System.
func (o OS) AptMark(ctx context.Context, args ...string) (string, int, error) {
	if o.testRoot() {
		return "", -1, errTestRoot
	}
	return command(ctx, "apt-mark", args...)
}

// Dpkg implements System.
func (o OS) Dpkg(ctx context.Context, args ...string) (string, int, error) {
	if o.testRoot() {
		return "", -1, errTestRoot
	}
	return packageCommand(ctx, PackageTimeout, nil, "dpkg", args...)
}

// Flatpak implements System.
func (o OS) Flatpak(ctx context.Context, args ...string) (string, int, error) {
	if o.testRoot() {
		return "", -1, errTestRoot
	}
	return packageCommand(ctx, PackageTimeout, nil, "flatpak", args...)
}

// SystemdRun implements System.
func (o OS) SystemdRun(ctx context.Context, args ...string) (string, int, error) {
	if o.testRoot() {
		return "", -1, errTestRoot
	}
	return packageCommand(ctx, PackageTimeout, nil, "systemd-run", args...)
}

// packageCommand runs a package tool non-interactively in a process group of its own and kills the whole group at
// timeout: maintainer scripts must not outlive a run the agent gave up on. A timeout is an error that wraps
// context.DeadlineExceeded.
func packageCommand(ctx context.Context, timeout time.Duration, stdin []byte, name string, args ...string) (string, int, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // fixed package tools and arguments
	// LC_ALL=C: the agent reads apt's output (the counts of an update run, "dpkg was interrupted"), which is
	// translated in the device's locale otherwise.
	cmd.Env = append(slices.DeleteFunc(os.Environ(), func(e string) bool { return strings.HasPrefix(e, "NOTIFY_SOCKET=") }),
		"DEBIAN_FRONTEND=noninteractive", "LC_ALL=C")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 10 * time.Second // children that inherited the output pipes are gone with the group
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	err := cmd.Run()
	if ctx.Err() != nil {
		return out.String(), -1, fmt.Errorf("%s: %w", name, ctx.Err())
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return out.String(), exit.ExitCode(), nil
	}
	if err != nil {
		return "", -1, err
	}
	return out.String(), 0, nil
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
	return fsutil.Rename(o.path(oldPath), o.path(newPath))
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

// OutputTimeout bounds every Output call; MaxOutput bounds what it keeps of a tool's stdout.
const (
	OutputTimeout = 30 * time.Second
	MaxOutput     = 16 << 20
)

// ErrOutputLimit means a tool printed more than MaxOutput bytes; Output returns the first MaxOutput.
var ErrOutputLimit = errors.New("the output exceeds its limit")

// ExitError is the non-zero exit of a tool run by Output.
type ExitError struct {
	Name string
	Code int
}

func (e *ExitError) Error() string { return fmt.Sprintf("%s: exit %d", e.Name, e.Code) }

// Output implements System.
func (o OS) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	if o.testRoot() {
		return nil, errTestRoot
	}
	ctx, cancel := context.WithTimeout(ctx, OutputTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // the fixed tools of the callers' closed lists
	cmd.Env = slices.DeleteFunc(os.Environ(), func(e string) bool { return strings.HasPrefix(e, "NOTIFY_SOCKET=") })
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	out, rerr := io.ReadAll(io.LimitReader(stdout, MaxOutput+1))
	if len(out) > MaxOutput {
		// The rest is not wanted: stopping the tool keeps a 7-day journal from running into the timeout.
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return out[:MaxOutput], ErrOutputLimit
	}
	werr := cmd.Wait()
	var exit *exec.ExitError
	switch {
	case ctx.Err() != nil:
		return out, fmt.Errorf("%s: %w", name, ctx.Err())
	case errors.As(werr, &exit):
		return out, &ExitError{Name: name, Code: exit.ExitCode()}
	case werr != nil:
		return out, werr
	case rerr != nil:
		return out, rerr
	}
	return out, nil
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
