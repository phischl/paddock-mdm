package compiler

import (
	"context"
	"encoding/base64"
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
}

// softwareEntry is a catalog entry as the compiler needs it: its source and its package references.
type softwareEntry struct {
	source   uuid.NullUUID
	packages []software.PackageRef
}

// loadSoftware returns the software catalog of the context's organization. Every row is checked again — sources with
// software.ValidateSource and the bundle contract, entries' package references, assignments' intent and version — and
// a failing row is left out and logged: a rule tightened after the write, or a row changed outside the API, must never
// put a refused trust anchor or an unchecked package name into a signed bundle, nor stop the organization's round.
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
	s := &orgSoftware{sources: map[uuid.UUID]bundle.SoftwareSource{}, bySlug: map[string]bundle.SoftwareSource{},
		entries: make(map[uuid.UUID]softwareEntry, len(entries))}
	for _, src := range sources {
		key, err := software.ValidateSource(software.SourceInput{Slug: src.Slug, Name: src.Name, URIs: src.Uris,
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
		if err == nil {
			err = software.ValidatePackageRefs(refs)
		}
		if err != nil {
			slog.ErrorContext(ctx, "catalog entry left out of bundles: its package references fail the catalog rules",
				"catalog_entry_id", e.ID, "error", err)
			continue
		}
		s.entries[e.ID] = softwareEntry{source: e.SourceID, packages: refs}
	}
	for _, a := range assignments {
		if err := software.ValidateAssignment(a.Intent, a.UpdateRule, a.Version, ""); err != nil {
			slog.ErrorContext(ctx, "software assignment left out of bundles: it fails the assignment rules",
				"assignment_id", a.ID, "error", err)
			continue
		}
		s.assignments = append(s.assignments, a)
	}
	return s, nil
}

// section returns the software section of a device in groups with the given os-release ID, VERSION_ID and
// architecture, the package holds its assignments add to the updates section, and the packages whose assignments
// name different versions. Assignments of the organization and of the device's groups apply; each resolves through
// its entry to the device's package and the results merge per package (software.MergeIntents). Only required packages
// name their source, and Sources lists exactly those. The section is nil when no package resolves.
func (s *orgSoftware) section(groups []uuid.UUID, osID, versionID, arch string) (*bundle.SoftwareSpec, []bundle.Hold, []software.Conflict) {
	var effective []software.Effective
	for _, a := range s.assignments {
		if a.DeviceGroupID.Valid && !slices.Contains(groups, a.DeviceGroupID.UUID) {
			continue
		}
		e, ok := s.entries[a.CatalogEntryID]
		if !ok {
			continue
		}
		pkg, ok := software.Resolve(e.packages, osID, versionID, arch)
		if !ok {
			continue
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
		return nil, nil, conflicts
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
	return spec, holds, conflicts
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
