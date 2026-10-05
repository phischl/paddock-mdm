// Package apply applies a verified bundle to the device (plan M2b decisions 9 and 10, M3b decision 6): resources in
// the order time → file → systemd_unit → login → sudo, each independently (an error does not stop the others), then
// the removal of files that left the bundle.
package apply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/paddock-mdm/paddock/agent/internal/reconcile"
	"github.com/paddock-mdm/paddock/pkg/bundle"
)

// SchemaVersions are the bundle schema versions this agent verifies and applies, reported in every check-in and used
// by the run loop and the self-test alike (plan M3b decision 4).
var SchemaVersions = []int{bundle.SchemaVersion, bundle.SchemaVersion2}

// order is the apply order of resource types: units may depend on files; sudo rights follow the login component
// that resolves their users.
var order = []string{bundle.TypeTime, bundle.TypeFile, bundle.TypeSystemdUnit, bundle.TypeLogin, bundle.TypeSudo}

// ResourceError is one entry of Report.Errors.
type ResourceError struct {
	ID      string `json:"id"`
	Message string `json:"message"`
}

// Report is the outcome of an apply; it is the data of the bundle.applied event.
type Report struct {
	Version int64           `json:"version"`
	Changed int             `json:"changed"`
	Errors  []ResourceError `json:"errors"`
	// ChangedIDs are the resources that changed (not part of the event).
	ChangedIDs []string `json:"-"`
}

// Planned is the plan of one resource.
type Planned struct {
	ID      string   `json:"id"`
	Changes []string `json:"changes,omitempty"`
	Error   string   `json:"error,omitempty"`
}

// Applier applies bundles with a set of reconcilers.
type Applier struct {
	recs  map[string]reconcile.Reconciler
	file  *reconcile.File
	login *reconcile.Login
}

// New creates an applier for sys; managed is the record of files Paddock wrote, events receives the device events
// of the reconcilers.
func New(sys reconcile.System, managed *reconcile.Managed, events *reconcile.Events) *Applier {
	file := &reconcile.File{Sys: sys, Managed: managed}
	login := &reconcile.Login{Sys: sys, Events: events}
	return &Applier{
		file:  file,
		login: login,
		recs: map[string]reconcile.Reconciler{
			bundle.TypeFile: file, bundle.TypeSystemdUnit: &reconcile.Unit{Sys: sys}, bundle.TypeTime: &reconcile.Time{Sys: sys},
			bundle.TypeLogin: login, bundle.TypeSudo: &reconcile.Sudo{Sys: sys, Events: events},
		},
	}
}

// sorted returns the resources of b in apply order, filtered by keep.
func sorted(b *bundle.Bundle, keep func(bundle.Resource) bool) []bundle.Resource {
	var out []bundle.Resource
	for _, typ := range order {
		for _, r := range b.Resources {
			if r.Type == typ && keep(r) {
				out = append(out, r)
			}
		}
	}
	for _, r := range b.Resources {
		if !slices.Contains(order, r.Type) && keep(r) {
			out = append(out, r) // reported as unsupported
		}
	}
	return out
}

func all(bundle.Resource) bool { return true }

// ErrUnknownResourceType rejects a bundle with a resource type this agent has no reconciler for (plan M3b decision
// 4): such a bundle is not applied at all, not partially.
var ErrUnknownResourceType = errors.New("unknown_resource_type")

// CheckTypes returns ErrUnknownResourceType if b has a resource of a type without reconciler.
func (a *Applier) CheckTypes(b *bundle.Bundle) error {
	for _, r := range b.Resources {
		if _, ok := a.recs[r.Type]; !ok {
			return fmt.Errorf("%w: %s", ErrUnknownResourceType, r.Type)
		}
	}
	return nil
}

// Apply applies every resource of b and removes managed files that are no longer part of it.
func (a *Applier) Apply(ctx context.Context, b *bundle.Bundle) Report {
	r := a.apply(ctx, b, all)
	a.removeStale(b, &r)
	return r
}

// ApplyResources applies only the resources with the given IDs (drift correction).
func (a *Applier) ApplyResources(ctx context.Context, b *bundle.Bundle, ids []string) Report {
	return a.apply(ctx, b, func(r bundle.Resource) bool { return slices.Contains(ids, r.ID) })
}

func (a *Applier) apply(ctx context.Context, b *bundle.Bundle, keep func(bundle.Resource) bool) Report {
	rep := Report{Version: b.BundleVersion, Errors: []ResourceError{}}
	for _, res := range sorted(b, keep) {
		rec, ok := a.recs[res.Type]
		if !ok {
			rep.Errors = append(rep.Errors, ResourceError{ID: res.ID, Message: "unsupported resource type " + res.Type})
			continue
		}
		switch out := rec.Apply(ctx, res); out.Status {
		case reconcile.Changed:
			rep.Changed++
			rep.ChangedIDs = append(rep.ChangedIDs, res.ID)
		case reconcile.Error:
			rep.Errors = append(rep.Errors, ResourceError{ID: res.ID, Message: out.Message})
		}
	}
	if !hasLogin(b) && keep(bundle.Resource{ID: reconcile.DenyListID}) {
		switch written, err := a.login.EnsureDenyList(); {
		case err != nil:
			rep.Errors = append(rep.Errors, ResourceError{ID: reconcile.DenyListID, Message: err.Error()})
		case written:
			rep.Changed++
			rep.ChangedIDs = append(rep.ChangedIDs, reconcile.DenyListID)
		}
	}
	return rep
}

// hasLogin reports whether b has a login resource; without one, the applier keeps the deny list of the PAM profile
// in place itself (plan M4a step 0c).
func hasLogin(b *bundle.Bundle) bool {
	return slices.ContainsFunc(b.Resources, func(r bundle.Resource) bool { return r.Type == bundle.TypeLogin })
}

// removeStale deletes files Paddock wrote that left the bundle, unless they were changed locally (plan M2b
// decision 10). A removed unit resource leaves the unit as it is.
func (a *Applier) removeStale(b *bundle.Bundle, rep *Report) {
	wanted := map[string]bool{}
	for _, r := range b.Resources {
		if r.Type == bundle.TypeFile {
			var s bundle.FileSpec
			if json.Unmarshal(r.Spec, &s) == nil {
				wanted[s.Path] = true
			}
		}
	}
	for _, path := range a.file.Managed.Paths() {
		if wanted[path] {
			continue
		}
		id := "file:" + path
		if err := a.file.Remove(path); err != nil { // reconcile.ErrModified: left in place and reported
			rep.Errors = append(rep.Errors, ResourceError{ID: id, Message: err.Error()})
			continue
		}
		rep.Changed++
		rep.ChangedIDs = append(rep.ChangedIDs, id)
	}
}

// Plan plans every resource of b without changing the system.
func (a *Applier) Plan(ctx context.Context, b *bundle.Bundle) []Planned {
	var out []Planned
	for _, res := range sorted(b, all) {
		p := Planned{ID: res.ID}
		if rec, ok := a.recs[res.Type]; !ok {
			p.Error = "unsupported resource type " + res.Type
		} else if changes, err := rec.Plan(ctx, res); err != nil {
			p.Error = err.Error()
		} else {
			p.Changes = changes
		}
		out = append(out, p)
	}
	if !hasLogin(b) && a.login.DenyListMissing() {
		out = append(out, Planned{ID: reconcile.DenyListID, Changes: []string{"create"}})
	}
	return out
}

// Drifted returns the IDs of planned resources with changes.
func Drifted(plan []Planned) []string {
	var ids []string
	for _, p := range plan {
		if len(p.Changes) > 0 {
			ids = append(ids, p.ID)
		}
	}
	return ids
}

// RejectReason maps a verification error to the reason of bundle.rejected.
func RejectReason(err error) string {
	switch {
	case errors.Is(err, bundle.ErrSignature):
		return "signature"
	case errors.Is(err, bundle.ErrWrongDevice):
		return "wrong_device"
	case errors.Is(err, bundle.ErrDowngrade):
		return "downgrade"
	case errors.Is(err, bundle.ErrSchema):
		return "schema"
	case errors.Is(err, ErrUnknownResourceType):
		return "unknown_resource_type"
	default:
		return strings.ReplaceAll(err.Error(), " ", "_")
	}
}
