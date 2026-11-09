package compiler

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/software"
)

// orgSoftware are the organization's package sources, catalog entries and software assignments, loaded once per
// compile round (plan M13a decision 14).
type orgSoftware struct {
	// sources are the sources that pass the current upload rules, as the bundle carries them, by ID and by slug. A
	// required package from any other source is left out of every bundle.
	sources     map[uuid.UUID]bundle.SoftwareSource
	bySlug      map[string]bundle.SoftwareSource
	entries     map[uuid.UUID]softwareEntry
	assignments []pgstore.SoftwareAssignment
	// invalidAssignments are the assignments that fail the assignment rules, with the reason.
	invalidAssignments map[uuid.UUID]error
}

// softwareEntry is a catalog entry as the compiler needs it: its name, source and package references, and invalid,
// the reason it fails the catalog rules (nil when it passes).
type softwareEntry struct {
	name     string
	source   uuid.NullUUID
	packages []software.PackageRef
	invalid  error
}

// loadSoftware returns the software catalog of the context's organization. Every row is checked again — sources with
// software.ValidateSource and the bundle contract, entries' package references, assignments' intent and version —
// because a rule tightened after the write, or a row changed outside the API, must never put a refused trust anchor or
// an unchecked package name into a signed bundle, nor stop the organization's round. A failing source is left out (a
// required package from it is then not installed, which is safe); a failing entry or assignment is kept with its
// reason, and section fails every device it applies to (architect decision 2026-11-02, PDK-697): skipping it could
// lift a forbid or let a competing intent win.
func loadSoftware(ctx context.Context, q *pgstore.Queries) (*orgSoftware, error) {
	sources, err := q.ListAllSoftwareSources(ctx)
	if err != nil {
		return nil, err
	}
	entries, err := q.ListAllSoftwareCatalogEntries(ctx)
	if err != nil {
		return nil, err
	}
	assignments, err := q.ListAllSoftwareAssignments(ctx)
	if err != nil {
		return nil, err
	}
	// The bundle carries no user targets, no available intent and no Flatpak sources or references until PDK-799
	// renders them (plan M13b §3.3): such rows stay out of every bundle instead of applying organization-wide or
	// failing the devices' bundles.
	assignments = slices.DeleteFunc(assignments, func(a pgstore.SoftwareAssignment) bool {
		return a.UserID.Valid || a.UserGroupID.Valid || a.Intent == software.IntentAvailable
	})
	s := &orgSoftware{sources: map[uuid.UUID]bundle.SoftwareSource{}, bySlug: map[string]bundle.SoftwareSource{},
		entries: make(map[uuid.UUID]softwareEntry, len(entries)), assignments: assignments,
		invalidAssignments: map[uuid.UUID]error{}}
	sourceKinds := make(map[uuid.UUID]string, len(sources))
	for _, src := range sources {
		sourceKinds[src.ID] = src.Kind
		if src.Kind == software.SourceKindFlatpak {
			continue
		}
		key, err := software.ValidateSource(software.SourceInput{Kind: src.Kind, Slug: src.Slug, Name: src.Name, URIs: src.Uris,
			Suites: src.Suites, Components: src.Components, Architectures: src.Architectures,
			SigningKey: src.SigningKey, Fingerprint: src.Fingerprint})
		if err != nil {
			slog.ErrorContext(ctx, "software source left out of bundles: it fails the current source rules",
				"source_id", src.ID, "slug", src.Slug, "error", err)
			continue
		}
		b := bundle.SoftwareSource{Slug: src.Slug, URIs: src.Uris, Suites: src.Suites,
			Components: src.Components, Architectures: src.Architectures,
			Keyring: base64.StdEncoding.EncodeToString(key.Keyring), Fingerprint: key.Fingerprint}
		if err := bundle.ValidateSoftware(bundle.SoftwareSpec{Sources: []bundle.SoftwareSource{b}}); err != nil {
			slog.ErrorContext(ctx, "software source left out of bundles: it fails the bundle contract",
				"source_id", src.ID, "slug", src.Slug, "error", err)
			continue
		}
		s.sources[src.ID], s.bySlug[src.Slug] = b, b
	}
	for _, e := range entries {
		refs, err := software.DecodePackages(e.Packages)
		kind := software.SourceKindAPT
		if e.SourceID.Valid {
			kind = sourceKinds[e.SourceID.UUID]
		}
		if err == nil {
			err = software.ValidatePackages(kind, refs)
		}
		// Only a valid entry of a Flatpak source stays out until PDK-799; a flatpak_ref anywhere else is invalid and
		// fails the devices the entry applies to (PDK-697), so it can never lift a forbid by being skipped.
		if err == nil && kind == software.SourceKindFlatpak {
			continue
		}
		entry := softwareEntry{name: e.Name, source: e.SourceID, packages: refs}
		if err != nil {
			slog.ErrorContext(ctx, "catalog entry fails the catalog rules; the devices it applies to keep their previous bundle",
				"catalog_entry_id", e.ID, "error", err)
			entry.invalid = err
		}
		s.entries[e.ID] = entry
	}
	for _, a := range assignments {
		if err := software.ValidateAssignment(a.Intent, a.UpdateRule, a.Version, ""); err != nil {
			slog.ErrorContext(ctx, "software assignment fails the assignment rules; the devices it applies to keep their previous bundle",
				"assignment_id", a.ID, "error", err)
			s.invalidAssignments[a.ID] = err
		}
	}
	return s, nil
}

// section returns the software section of a device in groups with the given os-release ID, VERSION_ID and
// architecture, the package holds its assignments add to the updates section, and the packages whose assignments
// name different versions. Assignments of the organization and of the device's groups apply; each resolves through
// its entry to the device's package and the results merge per package (software.MergeIntents). Only required packages
// name their source, and Sources lists exactly those. The section is nil when no package resolves. err names an entry
// that fails the current rules and has an assignment whose scope covers the device, or such an assignment whose entry
// resolves on the device; the device's bundle must then not be published.
func (s *orgSoftware) section(groups []uuid.UUID, osID, versionID, arch string) (*bundle.SoftwareSpec, []bundle.Hold, []software.Conflict, error) {
	var effective []software.Effective
	for _, a := range s.assignments {
		if a.DeviceGroupID.Valid && !slices.Contains(groups, a.DeviceGroupID.UUID) {
			continue
		}
		e, ok := s.entries[a.CatalogEntryID]
		if !ok {
			continue
		}
		// An invalid entry fails every device of the assignment's scope, whether or not its references resolve there:
		// which reference would apply cannot be trusted once the list fails the rules (an empty list resolves nowhere).
		if e.invalid != nil {
			return nil, nil, nil, fmt.Errorf("catalog entry %s (%s) fails the catalog rules: %w", a.CatalogEntryID,
				software.DisplayParam(e.name, 100), e.invalid)
		}
		pkg, ok := software.Resolve(e.packages, osID, versionID, arch)
		if !ok {
			continue
		}
		if err := s.invalidAssignments[a.ID]; err != nil {
			return nil, nil, nil, fmt.Errorf("software assignment %s of catalog entry %s (%s) fails the assignment rules: %w",
				a.ID, a.CatalogEntryID, software.DisplayParam(e.name, 100), err)
		}
		slug := ""
		if e.source.Valid {
			src, ok := s.sources[e.source.UUID]
			if !ok && a.Intent == software.IntentRequired {
				continue
			}
			slug = src.Slug
		}
		effective = append(effective, software.Effective{CatalogEntryID: a.CatalogEntryID, Package: pkg, Source: slug,
			Intent: a.Intent, UpdateRule: a.UpdateRule, Version: a.Version})
	}
	resolved, mergeHolds, conflicts := software.MergeIntents(effective)
	if len(resolved) == 0 {
		return nil, nil, conflicts, nil
	}
	spec := &bundle.SoftwareSpec{Sources: []bundle.SoftwareSource{}, Packages: make([]bundle.SoftwarePackage, 0, len(resolved))}
	var holds []bundle.Hold
	for _, r := range resolved {
		p := bundle.SoftwarePackage{Package: r.Package, Intent: r.Intent, Version: r.Version,
			CatalogEntryID: r.CatalogEntryID.String()}
		if r.Intent == software.IntentRequired && r.Source != "" {
			p.Source = r.Source
			if !slices.ContainsFunc(spec.Sources, func(x bundle.SoftwareSource) bool { return x.Slug == r.Source }) {
				spec.Sources = append(spec.Sources, s.bySlug[r.Source])
			}
		}
		spec.Packages = append(spec.Packages, p)
		// ADR 0042 decision 3: a hold and a required pinned package are held by the updates reconciler, the single
		// owner of apt-mark and the pin file.
		pinned := r.Intent == software.IntentRequired &&
			(r.Version != nil || slices.ContainsFunc(mergeHolds, func(h bundle.Hold) bool { return h.Package == r.Package }))
		if r.Intent == software.IntentHold || pinned {
			holds = append(holds, bundle.Hold{Package: r.Package, Version: r.Version})
		}
	}
	slices.SortFunc(spec.Sources, func(a, b bundle.SoftwareSource) int { return strings.Compare(a.Slug, b.Slug) })
	return spec, holds, conflicts, nil
}

// alignWithHolds makes the software section and the device's merged holds (updates section) agree, as ADR 0042
// decision 3 leaves holds to the updates reconciler alone:
//   - a forbid or uninstall result wins over a package hold of the same package (architect decision 2026-11-02): the
//     hold leaves the updates section, since apt refuses to remove a held package, and the package is marked
//     SupersededHold so the agent reports the overlap;
//   - a required or held package takes the version its merged hold keeps it at. updates.Merge ranks a hold without a
//     version first, so a versionless package_hold next to a required pinned assignment leaves the package required at
//     the installed version, while a versionless software hold does not unpin it (software.MergeIntents counts named
//     versions only); the software reconciler must not install a version the pin then refuses.
//
// It returns the holds to put into the updates section.
func alignWithHolds(spec *bundle.SoftwareSpec, holds []bundle.Hold) []bundle.Hold {
	if spec == nil {
		return holds
	}
	kept := holds[:0:0]
	for _, h := range holds {
		i := slices.IndexFunc(spec.Packages, func(p bundle.SoftwarePackage) bool { return p.Package == h.Package })
		if i < 0 {
			kept = append(kept, h)
			continue
		}
		p := &spec.Packages[i]
		switch p.Intent {
		case software.IntentForbid, software.IntentUninstall:
			p.SupersededHold = true
			continue
		default:
			p.Version = h.Version
		}
		kept = append(kept, h)
	}
	return kept
}

// softwareFailure checks a device's software section against the bundle contract the agent enforces. A section that
// fails it blocks the device's bundle (render failure: the device keeps its previous bundle and the failure is
// audited) instead of shipping a section the agent would refuse as a whole; other devices are unaffected.
func softwareFailure(device uuid.UUID, spec *bundle.SoftwareSpec) *renderFailure {
	if spec == nil {
		return nil
	}
	if err := bundle.ValidateSoftware(*spec); err != nil {
		return &renderFailure{device: device, reason: "the software section fails the bundle contract (" + err.Error() +
			"); the device keeps its previous bundle until the catalog is fixed"}
	}
	return nil
}
