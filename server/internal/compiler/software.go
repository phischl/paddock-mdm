package compiler

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/buildinfo"
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
	// owners are the owners of the organization's devices by device, members the users of each user group: a user or
	// user-group assignment applies to a device through its owners (plan M13b decision 8).
	owners  map[uuid.UUID][]deviceOwner
	members map[uuid.UUID][]uuid.UUID
	// icons are the entries' icons that pass software.ValidateIcon, by entry ID (architect decision A10-14).
	icons map[uuid.UUID]catalogIcon
}

// catalogIcon is a validated catalog icon with the hex SHA-256 that names it in bundles and object storage.
type catalogIcon struct {
	sha256 string
	data   []byte
}

// deviceOwner is an owner of a device with the user name (lower-case UPN) an audience names.
type deviceOwner struct {
	user     uuid.UUID
	username string
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
	owners, err := q.ListDeviceOwnersWithUsernames(ctx)
	if err != nil {
		return nil, err
	}
	members, err := q.ListAllUserGroupMembers(ctx)
	if err != nil {
		return nil, err
	}
	icons, err := q.ListSoftwareCatalogIcons(ctx)
	if err != nil {
		return nil, err
	}
	s := &orgSoftware{sources: map[uuid.UUID]bundle.SoftwareSource{}, bySlug: map[string]bundle.SoftwareSource{},
		entries: make(map[uuid.UUID]softwareEntry, len(entries)), assignments: assignments,
		invalidAssignments: map[uuid.UUID]error{}, owners: map[uuid.UUID][]deviceOwner{}, members: map[uuid.UUID][]uuid.UUID{},
		icons: make(map[uuid.UUID]catalogIcon, len(icons))}
	for _, ic := range icons {
		// The api checked the icon on upload; a row changed outside it must not reach object storage, so the entry then
		// shows the category glyph.
		if err := software.ValidateIcon(ic.Icon); err != nil {
			slog.ErrorContext(ctx, "catalog icon left out of bundles: it fails the icon rules", "catalog_entry_id", ic.ID, "error", err)
			continue
		}
		sum := sha256.Sum256(ic.Icon)
		s.icons[ic.ID] = catalogIcon{sha256: hex.EncodeToString(sum[:]), data: ic.Icon}
	}
	for _, o := range owners {
		s.owners[o.DeviceID] = append(s.owners[o.DeviceID], deviceOwner{user: o.UserID, username: o.Username})
	}
	for _, m := range members {
		s.members[m.GroupID] = append(s.members[m.GroupID], m.UserID)
	}
	sourceKinds := make(map[uuid.UUID]string, len(sources))
	for _, src := range sources {
		sourceKinds[src.ID] = src.Kind
		key, err := software.ValidateSource(software.SourceInput{Kind: src.Kind, Slug: src.Slug, Name: src.Name, URIs: src.Uris,
			Suites: src.Suites, Components: src.Components, Architectures: src.Architectures,
			SigningKey: src.SigningKey, Fingerprint: src.Fingerprint})
		if err != nil {
			slog.ErrorContext(ctx, "software source left out of bundles: it fails the current source rules",
				"source_id", src.ID, "slug", src.Slug, "error", err)
			continue
		}
		kind := ""
		if src.Kind == software.SourceKindFlatpak {
			kind = bundle.SoftwareSourceFlatpak
		}
		b := bundle.SoftwareSource{Slug: src.Slug, Kind: kind, URIs: src.Uris, Suites: src.Suites,
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
		entry := softwareEntry{name: e.Name, source: e.SourceID, packages: software.NormalizePackages(refs)}
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

// section returns the software section of the device with the given ID, in groups, with the given os-release ID,
// VERSION_ID, architecture and agent version, the package holds its assignments add to the updates section, and the
// packages whose assignments name different versions. Assignments of the organization and of the device's groups
// apply, and those of a user or user group that owns the device (plan M13b decision 8); each resolves through its
// entry to the device's package and the results merge per package (software.MergeIntents). An available package
// carries its audience: everyone for an organization or device-group target, otherwise the user names of the targeted
// owners, capped at bundle.MaxSoftwareAudience. A user-scope Flatpak application with intent required, forbid or
// uninstall carries the same user names as its Users when every assignment of the winning intent targets users or
// user groups, and none (system scope) when one targets the organization or a device group, or when a system-scope entry
// of the same application contributes the winning intent (architect decision A10-11, PDK-925); a truncated list returns a flatpak_users_truncated warning. Required and available packages name their source, and Sources lists
// exactly those; a section with a Flatpak source also requires the flatpak runtime package (plan M13b decision 9), so
// a Flatpak forbid, uninstall or hold alone never installs Flatpak (architect decision A10-7). For an agent release
// before selfServiceAgent, available packages and Flatpak applications are left out (A10-6). When the flatpak package
// itself resolves to forbid or uninstall, every Flatpak application is left out with its remote and the runtime, and
// each required or available one returns a flatpak_forbidden warning (A10-9); a truncated audience returns an
// audience_truncated warning (A10-10). Both warnings name every assignment the package came from. The section is nil
// when no package resolves. err names an entry that fails the current rules and has an assignment whose scope covers the
// device, or such an assignment whose entry resolves on the device; the device's bundle must then not be published.
func (s *orgSoftware) section(ctx context.Context, device uuid.UUID, groups []uuid.UUID, osID, versionID, arch, agent string) (*bundle.SoftwareSpec, []bundle.Hold, []software.Conflict, []compileWarning, error) {
	var effective []software.Effective
	// contributors are the assignments each package came from, by packageKey, for the warnings.
	contributors := map[string][]pgstore.SoftwareAssignment{}
	for _, a := range s.assignments {
		owners, applies := s.targets(a, device, groups)
		if !applies {
			continue
		}
		e, ok := s.entries[a.CatalogEntryID]
		if !ok {
			continue
		}
		// An invalid entry fails every device of the assignment's scope, whether or not its references resolve there:
		// which reference would apply cannot be trusted once the list fails the rules (an empty list resolves nowhere).
		if e.invalid != nil {
			return nil, nil, nil, nil, fmt.Errorf("catalog entry %s (%s) fails the catalog rules: %w", a.CatalogEntryID,
				software.DisplayParam(e.name, 100), e.invalid)
		}
		ref, ok := software.ResolveRef(e.packages, osID, versionID, arch)
		if !ok {
			continue
		}
		if err := s.invalidAssignments[a.ID]; err != nil {
			return nil, nil, nil, nil, fmt.Errorf("software assignment %s of catalog entry %s (%s) fails the assignment rules: %w",
				a.ID, a.CatalogEntryID, software.DisplayParam(e.name, 100), err)
		}
		slug := ""
		if e.source.Valid {
			src, ok := s.sources[e.source.UUID]
			if !ok && (a.Intent == software.IntentRequired || a.Intent == software.IntentAvailable) {
				// Safe to leave out: the package is then just not installed (plan M13a decision 14).
				continue
			}
			// A forbid, uninstall or hold needs no source, also for a Flatpak application (architect decision A10-7),
			// so a failed source never lifts it.
			slug = src.Slug
		}
		audience, users, ok := targetedUsers(ctx, a, ref, owners, device)
		if !ok {
			continue
		}
		effective = append(effective, software.Effective{CatalogEntryID: a.CatalogEntryID, Package: ref.Package,
			FlatpakRef: ref.FlatpakRef, Scope: ref.Scope, Source: slug, Intent: a.Intent, UpdateRule: a.UpdateRule,
			Version: a.Version, Audience: audience, Users: users})
		key := packageKey(bundle.SoftwarePackage{Package: ref.Package, FlatpakRef: ref.FlatpakRef})
		contributors[key] = append(contributors[key], a)
	}
	resolved, mergeHolds, conflicts := software.MergeIntents(effective)
	if len(resolved) == 0 {
		return nil, nil, conflicts, nil, nil
	}
	selfService := !buildinfo.OlderRelease(agent, selfServiceAgent)
	flatpakForbidden := slices.ContainsFunc(resolved, func(r software.Resolved) bool {
		return r.FlatpakRef == "" && r.Package == flatpakRuntime &&
			(r.Intent == software.IntentForbid || r.Intent == software.IntentUninstall)
	})
	var warnings []compileWarning
	spec := &bundle.SoftwareSpec{Sources: []bundle.SoftwareSource{}, Packages: make([]bundle.SoftwarePackage, 0, len(resolved)+1)}
	var holds []bundle.Hold
	for _, r := range resolved {
		if !selfService && (r.FlatpakRef != "" || r.Intent == software.IntentAvailable) {
			continue
		}
		if flatpakForbidden && r.FlatpakRef != "" {
			if r.Intent == software.IntentRequired || r.Intent == software.IntentAvailable {
				slog.WarnContext(ctx, "flatpak_forbidden: an entry forbids or uninstalls flatpak, so a Flatpak application is left out",
					"device_id", device, "catalog_entry_id", r.CatalogEntryID)
				warnings = append(warnings, assignmentWarnings(contributors[packageKey(bundle.SoftwarePackage{FlatpakRef: r.FlatpakRef})],
					WarningFlatpakForbidden, map[string]any{"flatpak_ref": r.FlatpakRef})...)
			}
			continue
		}
		p := bundle.SoftwarePackage{Package: r.Package, FlatpakRef: r.FlatpakRef, Scope: r.Scope, Intent: r.Intent,
			Version: r.Version, CatalogEntryID: r.CatalogEntryID.String(), Audience: r.Audience}
		// Only the self-service app shows icons, and an agent before the gate refuses a field it does not know.
		if ic, ok := s.icons[r.CatalogEntryID]; ok && selfService {
			p.IconSHA256 = ic.sha256
		}
		// The supplier's scope decides: a system-scope result never carries the users of another entry's user scope.
		if r.Scope == bundle.SoftwareScopeUser && r.Users != nil {
			p.Users = &r.Users
		}
		if r.Source != "" && (r.Intent == software.IntentRequired || r.Intent == software.IntentAvailable) {
			p.Source = r.Source
			if !slices.ContainsFunc(spec.Sources, func(x bundle.SoftwareSource) bool { return x.Slug == r.Source }) {
				spec.Sources = append(spec.Sources, s.bySlug[r.Source])
			}
		}
		if a := p.Audience; a != nil && len(a.Users) > bundle.MaxSoftwareAudience {
			slog.WarnContext(ctx, "audience_truncated: the audience of an available package names more users than a bundle carries; "+
				"the first ones by user name keep it", "device_id", device, "catalog_entry_id", r.CatalogEntryID,
				"users", len(a.Users), "kept", bundle.MaxSoftwareAudience)
			warnings = append(warnings, assignmentWarnings(contributors[packageKey(p)], WarningAudienceTruncated,
				map[string]any{"users": len(a.Users), "kept": bundle.MaxSoftwareAudience})...)
			a.Users = a.Users[:bundle.MaxSoftwareAudience]
		}
		if u := p.Users; u != nil && len(*u) > bundle.MaxSoftwareAudience {
			slog.WarnContext(ctx, "flatpak_users_truncated: a user-scope Flatpak application targets more users than a bundle "+
				"carries; the first ones by user name keep it", "device_id", device, "catalog_entry_id", r.CatalogEntryID,
				"users", len(*u), "kept", bundle.MaxSoftwareAudience)
			// Only the winning intent's user-targeted assignments put users into the list; the others lost the merge.
			listed := slices.DeleteFunc(slices.Clone(contributors[packageKey(p)]), func(a pgstore.SoftwareAssignment) bool {
				return a.Intent != r.Intent || (!a.UserID.Valid && !a.UserGroupID.Valid)
			})
			warnings = append(warnings, assignmentWarnings(listed, WarningFlatpakUsersTruncated,
				map[string]any{"users": len(*u), "kept": bundle.MaxSoftwareAudience, "flatpak_ref": p.FlatpakRef})...)
			*u = (*u)[:bundle.MaxSoftwareAudience]
		}
		spec.Packages = append(spec.Packages, p)
		// ADR 0042 decision 3: a hold and a required pinned package are held by the updates reconciler, the single
		// owner of apt-mark and the pin file.
		pinned := r.Intent == software.IntentRequired &&
			(r.Version != nil || slices.ContainsFunc(mergeHolds, func(h bundle.Hold) bool { return h.Package == r.Package }))
		if r.FlatpakRef == "" && (r.Intent == software.IntentHold || pinned) {
			holds = append(holds, bundle.Hold{Package: r.Package, Version: r.Version})
		}
	}
	if len(spec.Packages) == 0 {
		return nil, nil, conflicts, warnings, nil
	}
	addFlatpakRuntime(spec)
	slices.SortFunc(spec.Sources, func(a, b bundle.SoftwareSource) int { return strings.Compare(a.Slug, b.Slug) })
	return spec, holds, conflicts, warnings, nil
}

// selfServiceAgent is the first agent release that reads what plan M13b added to the software section: available
// packages with their audience, Flatpak sources and applications, and so the flatpak runtime package. It is the first
// alpha.10 release, the first that contains PDK-800 (architect decisions A10-6 and 18). Releases before it validate
// the whole section with their own bundle.ValidateSoftware and refuse it for any of these, so the compiler leaves
// them out for an older agent and keeps its required, forbid, uninstall and hold APT packages (plan M13b C5).
const selfServiceAgent = "0.1.0-alpha.10"

// flatpakRuntime is the distribution package that provides the flatpak command.
const flatpakRuntime = "flatpak"

// addFlatpakRuntime requires the flatpak package from the distribution's repositories when the section has a Flatpak
// source and no entry names the package itself (plan M13b decision 9, architect-lead decision Q12). It carries the nil
// entry ID: it is not an entry of the organization, and the agent reports it as system-managed.
func addFlatpakRuntime(spec *bundle.SoftwareSpec) {
	if !slices.ContainsFunc(spec.Sources, func(x bundle.SoftwareSource) bool { return x.Kind == bundle.SoftwareSourceFlatpak }) ||
		slices.ContainsFunc(spec.Packages, func(p bundle.SoftwarePackage) bool { return p.Package == flatpakRuntime }) {
		return
	}
	i, _ := slices.BinarySearchFunc(spec.Packages, flatpakRuntime, func(p bundle.SoftwarePackage, name string) int {
		return strings.Compare(packageKey(p), name)
	})
	spec.Packages = slices.Insert(spec.Packages, i, bundle.SoftwarePackage{Package: flatpakRuntime,
		Intent: bundle.SoftwareRequired, CatalogEntryID: bundle.SoftwareRuntimeEntryID})
}

// packageKey is the order of the section's packages, the one software.MergeIntents returns them in.
func packageKey(p bundle.SoftwarePackage) string {
	if p.FlatpakRef != "" {
		return "flatpak:" + p.FlatpakRef
	}
	return p.Package
}

// targets reports whether assignment a applies to the device in groups and, for a user or user-group target, the
// owners it targets on the device (plan M13b decision 8): an organization target or a device group of the device
// applies with no owners named; a user target applies when the user owns the device, a user-group target with the
// owners who are members. A user or user-group assignment applies only when it names at least one owner, so a device
// without owners gets none of them.
func (s *orgSoftware) targets(a pgstore.SoftwareAssignment, device uuid.UUID, groups []uuid.UUID) ([]deviceOwner, bool) {
	var owners []deviceOwner
	switch {
	case a.DeviceGroupID.Valid && !slices.Contains(groups, a.DeviceGroupID.UUID):
		return nil, false
	case a.UserID.Valid:
		for _, o := range s.owners[device] {
			if o.user == a.UserID.UUID {
				owners = append(owners, o)
			}
		}
	case a.UserGroupID.Valid:
		for _, o := range s.owners[device] {
			if slices.Contains(s.members[a.UserGroupID.UUID], o.user) {
				owners = append(owners, o)
			}
		}
	default:
		return nil, true
	}
	return owners, len(owners) > 0
}

// targetedUsers returns what assignment a, applying to the device with the targeted owners (none for the whole
// device), carries for package ref: the audience of an available assignment, everyone for the whole device; the user
// names of a user-scope Flatpak application with intent required, forbid or uninstall, none for the whole device
// (architect decision A10-11). A user name a bundle cannot carry (bundle.ValidAudienceUser) is left out; ok is false
// when that leaves a user-targeted audience or user list with nobody, so the assignment does not apply, and is never
// widened to everyone or to system scope.
func targetedUsers(ctx context.Context, a pgstore.SoftwareAssignment, ref software.PackageRef, owners []deviceOwner,
	device uuid.UUID) (audience *bundle.SoftwareAudience, users []string, ok bool) {
	userScope := ref.FlatpakRef != "" && ref.Scope == bundle.SoftwareScopeUser &&
		(a.Intent == software.IntentRequired || a.Intent == software.IntentForbid || a.Intent == software.IntentUninstall)
	switch {
	case a.Intent != software.IntentAvailable && !userScope:
		return nil, nil, true
	case owners == nil && a.Intent == software.IntentAvailable:
		return &bundle.SoftwareAudience{All: true}, nil, true
	case owners == nil:
		return nil, nil, true
	}
	users = make([]string, 0, len(owners))
	for _, o := range owners {
		// app_user allows names a bundle cannot carry (white space, a lower case Go and PostgreSQL disagree on): one
		// such owner must not fail the device's bundle (PDK-799 review 1).
		if !bundle.ValidAudienceUser(o.username) {
			slog.WarnContext(ctx, "audience_user_dropped: an owner's user name cannot be carried in a bundle; the "+
				"package is not offered to or targeted at the owner", "device_id", device, "user_id", o.user,
				"catalog_entry_id", a.CatalogEntryID, "intent", a.Intent)
			continue
		}
		users = append(users, o.username)
	}
	if len(users) == 0 {
		return nil, nil, false
	}
	slices.Sort(users)
	users = slices.Compact(users)
	if a.Intent == software.IntentAvailable {
		return &bundle.SoftwareAudience{Users: users}, nil, true
	}
	return nil, users, true
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

// bundleIcons returns the icons the software section names, by catalog entry ID.
func (s *orgSoftware) bundleIcons(spec *bundle.SoftwareSpec) map[string]catalogIcon {
	if spec == nil {
		return nil
	}
	var icons map[string]catalogIcon
	for _, p := range spec.Packages {
		if p.IconSHA256 == "" {
			continue
		}
		id, err := uuid.Parse(p.CatalogEntryID)
		if err != nil {
			continue
		}
		if ic, ok := s.icons[id]; ok {
			if icons == nil {
				icons = map[string]catalogIcon{}
			}
			icons[p.CatalogEntryID] = ic
		}
	}
	return icons
}

// iconKeys maps the icon digests of a bundle, by catalog entry ID, to their object keys for the bundle pointer.
func iconKeys(org uuid.UUID, digests map[string]string) map[string]string {
	if len(digests) == 0 {
		return nil
	}
	keys := make(map[string]string, len(digests))
	for entry, sum := range digests {
		keys[entry] = IconObjectKey(org, sum)
	}
	return keys
}
