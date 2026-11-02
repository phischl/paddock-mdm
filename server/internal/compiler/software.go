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

// loadSoftware returns the software catalog of the context's organization. Every source is checked again with
// software.ValidateSource: the stored key must still pass the key policy and match the stored fingerprint, so a policy
// tightened after the upload, or a row changed outside the API, never puts a refused trust anchor into a bundle.
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
		entries: make(map[uuid.UUID]softwareEntry, len(entries)), assignments: assignments}
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
		s.sources[src.ID], s.bySlug[src.Slug] = b, b
	}
	for _, e := range entries {
		refs, err := software.DecodePackages(e.Packages)
		if err != nil {
			slog.ErrorContext(ctx, "catalog entry left out of bundles: its packages cannot be read",
				"catalog_entry_id", e.ID, "error", err)
			continue
		}
		s.entries[e.ID] = softwareEntry{source: e.SourceID, packages: refs}
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

// pinToHolds sets the version of every required or held package of spec to the version the device's merged holds
// keep it at: a package_hold or another assignment may name a smaller version (or none, which holds the installed one),
// and the software reconciler must not install a version the updates reconciler's pin then refuses.
func pinToHolds(spec *bundle.SoftwareSpec, holds []bundle.Hold) {
	if spec == nil {
		return
	}
	for i := range spec.Packages {
		p := &spec.Packages[i]
		if p.Intent != software.IntentRequired && p.Intent != software.IntentHold {
			continue
		}
		if j := slices.IndexFunc(holds, func(h bundle.Hold) bool { return h.Package == p.Package }); j >= 0 {
			p.Version = holds[j].Version
		}
	}
}
