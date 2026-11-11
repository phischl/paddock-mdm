package selfservice

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"slices"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/pkg/bundle"
)

// Files of the self-service. Only root reads them (0600 below the agent's 0700 state directory).
const (
	// StateFile records the completed self-service installs (plan M13b decision 11) and the pending software requests
	// (plan M13c decision 9); the queue lives in memory.
	StateFile = "/var/lib/paddock/state/selfservice.json"
	// RunningFile holds the operation that is running: one left at start was interrupted by a restart (F4).
	RunningFile = "/var/lib/paddock/state/selfservice-running.json"
)

// Install is one completed self-service install. UID and Username name the user of a user-scope install; a
// system-scope install belongs to the device, and Username is who asked for it.
type Install struct {
	EntryID     string    `json:"entry_id"`
	Package     string    `json:"package,omitempty"`
	FlatpakRef  string    `json:"flatpak_ref,omitempty"`
	Scope       string    `json:"scope"`
	Username    string    `json:"username"`
	UID         int       `json:"uid,omitempty"`
	InstalledAt time.Time `json:"installed_at"`
	Version     string    `json:"version,omitempty"`
}

// Record is the content of StateFile.
type Record struct {
	Installs []Install        `json:"installs"`
	Requests []PendingRequest `json:"requests,omitempty"`
}

// installedBy reports whether the install is pkg's, for uid when it is a user-scope one.
func (i Install) installedBy(pkg bundle.SoftwarePackage, uid int) bool {
	return i.EntryID == pkg.CatalogEntryID && i.Package == pkg.Package && i.FlatpakRef == pkg.FlatpakRef &&
		(i.Scope != bundle.SoftwareScopeUser || i.UID == uid)
}

// has reports whether self-service installed pkg (for uid when it is user scope).
func (r Record) has(pkg bundle.SoftwarePackage, uid int) bool {
	return slices.ContainsFunc(r.Installs, func(i Install) bool { return i.installedBy(pkg, uid) })
}

// loadRecord reads the record; a missing or unreadable one is empty: the self-service then offers no removal of
// earlier installs, it never blocks the device (design contract 8).
func loadRecord(sys reconcile.System) Record {
	data, _, err := sys.ReadFile(StateFile)
	if errors.Is(err, fs.ErrNotExist) {
		return Record{}
	}
	var r Record
	if err == nil {
		err = json.Unmarshal(data, &r)
	}
	if err != nil {
		slog.Warn("self-service record unreadable; starting with an empty one", "error", err)
		return Record{}
	}
	return r
}

func saveRecord(sys reconcile.System, r Record) error {
	if r.Installs == nil {
		r.Installs = []Install{}
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return sys.WriteFileAtomic(StateFile, data, 0o600, 0, 0)
}

// running is the content of RunningFile.
type running struct {
	ID         string    `json:"id"`
	UID        int       `json:"uid"`
	User       string    `json:"user"`
	EntryID    string    `json:"entry_id"`
	Package    string    `json:"package,omitempty"`
	FlatpakRef string    `json:"flatpak_ref,omitempty"`
	Scope      string    `json:"scope"`
	Action     string    `json:"action"`
	StartedAt  time.Time `json:"started_at"`
}
