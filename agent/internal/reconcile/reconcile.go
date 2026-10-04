// Package reconcile brings one bundle resource to its desired state (plan M2b decision 10). Every reconciler is
// idempotent; Plan never changes the system. All system access goes through the narrow System port, which unit
// tests fake.
package reconcile

import (
	"context"
	"io/fs"

	"github.com/paddock-mdm/paddock/pkg/bundle"
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
	PackageInstalled(name string) bool
	// PackageVersion returns the version of an installed package, "" if it is not installed.
	PackageVersion(name string) string
	// AptGet runs apt-get non-interactively (DEBIAN_FRONTEND=noninteractive); it may take minutes.
	AptGet(ctx context.Context, args ...string) (output string, exit int, err error)
	// Loginctl runs loginctl.
	Loginctl(ctx context.Context, args ...string) (stdout string, exit int, err error)
	// Getent looks key up in an NSS database (passwd, group); exit 2 means not found.
	Getent(ctx context.Context, database, key string) (stdout string, exit int, err error)
	// Visudo runs visudo (checks only: -c, -c -f <file>).
	Visudo(ctx context.Context, args ...string) (output string, exit int, err error)
	// Gpasswd runs gpasswd (-d <user> <group>).
	Gpasswd(ctx context.Context, args ...string) (output string, exit int, err error)
	// Rename renames a file within the file system (rename(2)).
	Rename(oldPath, newPath string) error
	// ReadDir returns the names of the entries of a directory, sorted.
	ReadDir(path string) ([]string, error)
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

func errorResult(id string, err error) Result {
	return Result{ID: id, Status: Error, Message: err.Error()}
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
