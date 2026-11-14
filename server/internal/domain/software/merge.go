package software

import (
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/bundle"
)

// Effective is one assignment that applies to a device, with the package its entry resolves to on that device: an
// APT Package, or a FlatpakRef in Scope (plan M13b decision 8). Audience is set for an available assignment; Users are
// the targeted users of a user-scope Flatpak application with intent required, forbid or uninstall, nil when the
// assignment targets the whole device or is of a system-scope entry (architect decision A10-11).
type Effective struct {
	CatalogEntryID uuid.UUID
	Package        string
	FlatpakRef     string
	Scope          string
	Source         string
	Intent         string
	UpdateRule     string
	Version        *string
	Audience       *bundle.SoftwareAudience
	Users          []string
}

// Resolved is the software state a device gets for one package after the assignments are merged. A required
// application with a Version is pinned to it. An available result carries the merged Audience, a Flatpak application
// with intent required, forbid or uninstall the merged Users.
type Resolved struct {
	CatalogEntryID uuid.UUID
	Package        string
	FlatpakRef     string
	Scope          string
	Source         string
	Intent         string
	Version        *string
	Audience       *bundle.SoftwareAudience
	Users          []string
}

// key names what an assignment installs: an APT package and a Flatpak application of the same name are different
// packages.
func (e Effective) key() string {
	if e.FlatpakRef != "" {
		return "flatpak:" + e.FlatpakRef
	}
	return e.Package
}

// Conflict is a package whose assignments name different versions; Chosen is the version the device gets.
type Conflict struct {
	Package  string
	Versions []*string // sorted ascending, distinct
	Chosen   *string
}

// severity ranks the intents: the highest wins a merge (plan M13b decision 4).
var severity = map[string]int{IntentAvailable: 1, IntentHold: 2, IntentRequired: 3, IntentUninstall: 4, IntentForbid: 5}

// MergeIntents merges the assignments that apply to one device (plan M13a decision 10), one result per package,
// sorted by package. The intent with the highest severity wins: forbid, uninstall, required, hold, available; an
// available assignment is dropped whenever another intent applies to its package (plan M13b decision 4). When the winner is
// required or hold, the versions named by required-pinned and hold assignments are collected; the lexicographically
// smallest wins (the rule of updates.Merge) and two or more distinct versions are reported as a Conflict. A required
// winner with a named version is pinned to it. A hold assignment next to a required or hold winner yields a package
// hold (holds), without a version when none is named; uninstall and forbid winners yield none. Of several assignments
// with the winning intent the one with the smallest entry ID supplies the source and, for Flatpak, the scope; a Flatpak
// result carries no version and yields no hold. An
// available winner's audience merges those of every available assignment of the package: everyone when any names
// everyone, otherwise the sorted union of the users (plan M13b decision 8). A Flatpak winner with intent required,
// forbid or uninstall merges the Users of the assignments with that intent the same way: none when any of them targets
// the whole device or is of a system-scope entry of the same application, otherwise the sorted union (architect
// decision A10-11; per-user merge: PDK-925).
func MergeIntents(in []Effective) (out []Resolved, holds []bundle.Hold, conflicts []Conflict) {
	byPackage := map[string][]Effective{}
	for _, e := range in {
		byPackage[e.key()] = append(byPackage[e.key()], e)
	}
	names := make([]string, 0, len(byPackage))
	for p := range byPackage {
		names = append(names, p)
	}
	slices.Sort(names)
	for _, pkg := range names {
		group := byPackage[pkg]
		winner := winningIntent(group)
		if winner == "" {
			continue
		}
		r := Resolved{Package: group[0].Package, FlatpakRef: group[0].FlatpakRef, Intent: winner}
		hasHold := false
		var versions []*string
		var supplier *Effective
		for i := range group {
			e := &group[i]
			if e.Intent == winner && (supplier == nil || strings.Compare(e.CatalogEntryID.String(), supplier.CatalogEntryID.String()) < 0) {
				supplier = e
			}
			if e.Intent == IntentHold {
				hasHold = true
			}
			if e.Version != nil && (e.Intent == IntentHold || e.Intent == IntentRequired && e.UpdateRule == UpdatePinned) &&
				!slices.ContainsFunc(versions, func(v *string) bool { return *v == *e.Version }) {
				versions = append(versions, e.Version)
			}
		}
		r.CatalogEntryID, r.Source, r.Scope = supplier.CatalogEntryID, supplier.Source, supplier.Scope
		if winner == IntentAvailable {
			r.Audience = mergeAudiences(group)
		}
		if r.FlatpakRef != "" && (winner == IntentRequired || winner == IntentForbid || winner == IntentUninstall) {
			r.Users = mergeUsers(group, winner)
		}
		// Versions and holds are apt's (apt-mark and the pin file of the updates section); a Flatpak application has
		// neither, so it never reaches the updates section.
		if (winner == IntentRequired || winner == IntentHold) && r.FlatpakRef == "" {
			slices.SortFunc(versions, func(a, b *string) int { return strings.Compare(*a, *b) })
			if len(versions) > 0 {
				r.Version = versions[0]
			}
			if len(versions) > 1 {
				conflicts = append(conflicts, Conflict{Package: pkg, Versions: versions, Chosen: versions[0]})
			}
			if hasHold {
				holds = append(holds, bundle.Hold{Package: pkg, Version: r.Version})
			}
		}
		out = append(out, r)
	}
	return out, holds, conflicts
}

// mergeAudiences merges the audiences of the available assignments in group.
func mergeAudiences(group []Effective) *bundle.SoftwareAudience {
	var users []string
	for _, e := range group {
		if e.Intent != IntentAvailable || e.Audience == nil {
			continue
		}
		if e.Audience.All {
			return &bundle.SoftwareAudience{All: true}
		}
		users = append(users, e.Audience.Users...)
	}
	slices.Sort(users)
	return &bundle.SoftwareAudience{Users: slices.Compact(users)}
}

// mergeUsers merges the Users of the assignments with intent in group: nil when one of them has none, since it targets
// the whole device or belongs to a system-scope entry, and so the result applies in system scope.
func mergeUsers(group []Effective, intent string) []string {
	var users []string
	for _, e := range group {
		if e.Intent != intent {
			continue
		}
		if len(e.Users) == 0 {
			return nil
		}
		users = append(users, e.Users...)
	}
	slices.Sort(users)
	return slices.Compact(users)
}

func winningIntent(group []Effective) string {
	winner := ""
	for _, e := range group {
		if severity[e.Intent] > severity[winner] {
			winner = e.Intent
		}
	}
	return winner
}
