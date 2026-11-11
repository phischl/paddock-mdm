// Package reconcile brings one bundle resource to its desired state (plan M2b decision 10). Every reconciler is
// idempotent; Plan never changes the system. All system access goes through the narrow System port, which unit
// tests fake.
package reconcile

import (
	"context"
	"errors"
	"io/fs"

	"github.com/phischl/paddock-mdm/agent/internal/fsutil"
	"github.com/phischl/paddock-mdm/pkg/bundle"
)

// Status is the outcome of Apply for one resource.
type Status string

// Outcomes.
const (
	OK      Status = "ok"
	Changed Status = "changed"
	Error   Status = "error"
)

// Result is the outcome of Apply for one resource.
type Result struct {
	ID      string
	Status  Status
	Message string
}

// Reconciler handles one resource type.
type Reconciler interface {
	Type() string // bundle.TypeFile | bundle.TypeSystemdUnit | bundle.TypeTime
	Plan(ctx context.Context, r bundle.Resource) (changes []string, err error)
	Apply(ctx context.Context, r bundle.Resource) Result
}

// System is the narrow OS port of the reconcilers.
type System interface {
	// ReadFile returns the content and Lstat information of path; data is nil if path is not a regular file.
	ReadFile(path string) ([]byte, fs.FileInfo, error)
	// WriteFileAtomic replaces path atomically with owner, group and mode set before the rename; missing parent
	// directories are created 0755 root:root.
	WriteFileAtomic(path string, data []byte, mode fs.FileMode, uid, gid int) error
	Remove(path string) error
	LookupUser(name string) (uid int, err error)
	LookupGroup(name string) (gid int, err error)
	// Owner returns the numeric owner and group of a file described by info.
	Owner(info fs.FileInfo) (uid, gid int)
	Systemctl(ctx context.Context, args ...string) (stdout string, exit int, err error)
	Timedatectl(ctx context.Context, args ...string) (stdout string, exit int, err error)
	// Hostnamectl runs hostnamectl (--json=short, hostname <name>; plan M8h decision 12).
	Hostnamectl(ctx context.Context, args ...string) (stdout string, exit int, err error)
	// PackageInstalled reports a package installed for any architecture.
	PackageInstalled(name string) bool
	// PackageVersion returns the version of an installed package (the native architecture's build when several are
	// installed), "" if it is not installed.
	PackageVersion(name string) string
	// PackageRemovalNames returns the apt-get arguments that remove every installed build of a package: the name, or
	// the name qualified with each architecture when a build other than the native one is installed.
	PackageRemovalNames(name string) []string
	// AptGet runs apt-get non-interactively (DEBIAN_FRONTEND=noninteractive); it may take minutes. A run killed at
	// PackageTimeout returns an error wrapping context.DeadlineExceeded.
	AptGet(ctx context.Context, args ...string) (output string, exit int, err error)
	// AptCache runs apt-cache (pkgnames <prefix>: the names of real packages that start with prefix, no regex).
	AptCache(ctx context.Context, args ...string) (stdout string, exit int, err error)
	// AptMark runs apt-mark (showhold, hold, unhold).
	AptMark(ctx context.Context, args ...string) (stdout string, exit int, err error)
	// Dpkg runs dpkg like AptGet, e.g. to finish an interrupted installation (--configure -a).
	Dpkg(ctx context.Context, args ...string) (output string, exit int, err error)
	// Flatpak runs flatpak like AptGet (plan M13b decision 10): in a process group of its own, killed at
	// PackageTimeout, stdout and stderr combined.
	Flatpak(ctx context.Context, args ...string) (output string, exit int, err error)
	// SystemdRun runs systemd-run like Flatpak: a command in a user's service manager (--machine=<uid>@.host --user
	// --pipe, plan M13b decision 10 and Q14).
	SystemdRun(ctx context.Context, args ...string) (output string, exit int, err error)
	// Loginctl runs loginctl.
	Loginctl(ctx context.Context, args ...string) (stdout string, exit int, err error)
	// Getent looks key up in an NSS database (passwd, group); exit 2 means not found.
	Getent(ctx context.Context, database, key string) (stdout string, exit int, err error)
	// Visudo runs the visudo binary at path (checks only: -c, -c -f <file>).
	Visudo(ctx context.Context, path string, args ...string) (output string, exit int, err error)
	// SudoVersion runs `<path> --version` of a sudo binary.
	SudoVersion(ctx context.Context, path string) (output string, exit int, err error)
	// EvalSymlinks resolves every symlink of path (alternatives included).
	EvalSymlinks(path string) (string, error)
	// Dconf runs dconf (update: compile the system databases).
	Dconf(ctx context.Context, args ...string) (output string, exit int, err error)
	// Gpasswd runs gpasswd (-d <user> <group>).
	Gpasswd(ctx context.Context, args ...string) (output string, exit int, err error)
	// Rename renames a file within the file system (rename(2)).
	Rename(oldPath, newPath string) error
	// ReadDir returns the names of the entries of a directory, sorted.
	ReadDir(path string) ([]string, error)
	// Output runs a read-only tool within OutputTimeout and returns its stdout: at most MaxOutput bytes, with
	// ErrOutputLimit when it printed more (the tool is stopped then); a non-zero exit returns the output with an
	// *ExitError (the diagnostics bundle, ADR 0048 decision 2).
	Output(ctx context.Context, name string, args ...string) ([]byte, error)
}

// Events forwards the device events of reconcilers to the agent (plan M3b decision 5); without Emit they are
// dropped.
type Events struct {
	Emit func(typ string, data any)
}

func (e *Events) emit(typ string, data any) {
	if e != nil && e.Emit != nil {
		e.Emit(typ, data)
	}
}

// ErrParentNotTrusted refuses a write or delete below a parent directory that is a symlink or that someone other
// than root can change (plan M12h decision 12); the resource fails with the message parent_not_trusted.
var ErrParentNotTrusted = fsutil.ErrParentNotTrusted

// ErrInvalidSpec refuses a resource whose spec fails the shared bundle contract (plan M12h decision 14); the resource
// fails with the message invalid_spec and nothing is written.
var ErrInvalidSpec = errors.New("invalid_spec")

// Message is the status message of a failed resource: the stable code of a refusal, else the error text.
func Message(err error) string {
	switch {
	case errors.Is(err, ErrParentNotTrusted):
		return ErrParentNotTrusted.Error()
	case errors.Is(err, ErrInvalidSpec):
		return ErrInvalidSpec.Error()
	}
	return err.Error()
}

func errorResult(id string, err error) Result {
	return Result{ID: id, Status: Error, Message: Message(err)}
}

// apply is the common shape of Apply: plan, and if there are changes, carry them out.
func apply(ctx context.Context, r bundle.Resource, plan func(context.Context, bundle.Resource) ([]string, error), do func(changes []string) error) Result {
	changes, err := plan(ctx, r)
	if err != nil {
		return errorResult(r.ID, err)
	}
	if len(changes) == 0 {
		return Result{ID: r.ID, Status: OK}
	}
	if err := do(changes); err != nil {
		return errorResult(r.ID, err)
	}
	return Result{ID: r.ID, Status: Changed}
}
