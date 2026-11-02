package software

import (
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/bundle"
)

// Effective is one assignment that applies to a device, with the package its entry resolves to on that device.
type Effective struct {
	CatalogEntryID uuid.UUID
	Package        string
	Source         string
	Intent         string
	UpdateRule     string
	Version        *string
}

// Resolved is the software state a device gets for one package after the assignments are merged. A required
// application with a Version is pinned to it.
type Resolved struct {
	CatalogEntryID uuid.UUID
	Package        string
	Source         string
	Intent         string
	Version        *string
}

// Conflict is a package whose assignments name different versions; Chosen is the version the device gets.
type Conflict struct {
	Package  string
	Versions []*string // sorted ascending, distinct
	Chosen   *string
}

// severity ranks the intents: the highest wins a merge.
var severity = map[string]int{IntentHold: 1, IntentRequired: 2, IntentUninstall: 3, IntentForbid: 4}

// MergeIntents merges the assignments that apply to one device (plan M13a decision 10), one result per package,
// sorted by package. The intent with the highest severity wins: forbid, uninstall, required, hold. When the winner is
// required or hold, the versions named by required-pinned and hold assignments are collected; the lexicographically
// smallest wins (the rule of updates.Merge) and two or more distinct versions are reported as a Conflict. A required
// winner with a named version is pinned to it. A hold assignment next to a required or hold winner yields a package
// hold (holds), without a version when none is named; uninstall and forbid winners yield none. Of several assignments
// with the winning intent the one with the smallest entry ID supplies the source.
func MergeIntents(in []Effective) (out []Resolved, holds []bundle.Hold, conflicts []Conflict) {
	byPackage := map[string][]Effective{}
	for _, e := range in {
		byPackage[e.Package] = append(byPackage[e.Package], e)
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
		r := Resolved{Package: pkg, Intent: winner}
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
		r.CatalogEntryID, r.Source = supplier.CatalogEntryID, supplier.Source
		if winner == IntentRequired || winner == IntentHold {
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

func winningIntent(group []Effective) string {
	winner := ""
	for _, e := range group {
		if severity[e.Intent] > severity[winner] {
			winner = e.Intent
		}
	}
	return winner
}
