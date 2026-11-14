package declarative

import (
	"encoding/json"

	"github.com/phischl/paddock-mdm/server/internal/domain/software"
)

// Sections of the software catalog (plan M13c decision 1).
const (
	SectionSoftwareSources     = "software_sources"
	SectionSoftwareCatalog     = "software_catalog"
	SectionSoftwareAssignments = "software_assignments"
)

// SoftwareSource is a package source; key: Slug. SigningKey is the ASCII-armored public key, Fingerprint the key's
// fingerprint, which must match it (422 fingerprint_mismatch otherwise). Every change needs an organization
// administrator with a fresh step-up (ADR 0034 decision 3).
type SoftwareSource struct {
	Slug          string   `json:"slug"`
	Kind          string   `json:"kind"`
	Name          string   `json:"name"`
	URIs          []string `json:"uris"`
	Suites        []string `json:"suites"`
	Components    []string `json:"components"`
	Architectures []string `json:"architectures"`
	SigningKey    string   `json:"signing_key"`
	Fingerprint   string   `json:"fingerprint"`
}

// SoftwareCatalogEntry is a catalog entry; key: Name. Source is the slug of the source it installs from; nil for the
// distribution's own repositories. Approval is software.ApprovalRequired or empty for none (plan M13c decision 8), so a
// document without approvals reads as before. The icon is not part of the document.
type SoftwareCatalogEntry struct {
	Name        string                `json:"name"`
	Description string                `json:"description"`
	Category    string                `json:"category"`
	Source      *string               `json:"source"`
	Packages    []software.PackageRef `json:"packages"`
	Approval    string                `json:"approval,omitempty"`
}

// SoftwareAssignment assigns a catalog entry (by name) to a target; key: Entry and Target. UpdateRule is derived
// from Intent and Version (software.DefaultUpdateRule) when empty.
type SoftwareAssignment struct {
	Entry      string         `json:"entry"`
	Target     SoftwareTarget `json:"target"`
	Intent     string         `json:"intent"`
	UpdateRule string         `json:"update_rule,omitempty"`
	Version    *string        `json:"version"`
	Reason     string         `json:"reason"`
}

// SoftwareTarget is what an assignment targets: the organization, a device group (by name), a user (by username) or a
// user group (by slug). Type is one of the software.Target* kinds.
type SoftwareTarget struct {
	Type     string `json:"type"`
	Name     string `json:"name,omitempty"`
	Username string `json:"username,omitempty"`
	Slug     string `json:"slug,omitempty"`
}

// UnmarshalJSON fills the defaults of absent fields.
func (s *SoftwareSource) UnmarshalJSON(b []byte) error {
	type plain SoftwareSource
	v := plain{Kind: software.SourceKindAPT, URIs: []string{}, Suites: []string{}, Components: []string{}, Architectures: []string{}}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*s = SoftwareSource(v)
	return nil
}

// Key is the natural key of a source: its slug.
func (s SoftwareSource) Key() Key { return Key{Name: s.Slug} }

func (s SoftwareSource) fields() []field {
	return []field{{"slug", s.Slug}, {"kind", s.Kind}, {"name", s.Name}, {"uris", list(s.URIs)}, {"suites", list(s.Suites)},
		{"components", list(s.Components)}, {"architectures", list(s.Architectures)},
		{"signing_key", ContentSummary(s.SigningKey)}, {"fingerprint", s.Fingerprint}}
}

// Key is the natural key of a catalog entry: its name.
func (e SoftwareCatalogEntry) Key() Key { return Key{Name: e.Name} }

func (e SoftwareCatalogEntry) fields() []field {
	packages := make([]string, len(e.Packages))
	for i, p := range e.Packages {
		packages[i] = PackageSummary(p)
	}
	// The plan compares the fields of the desired item only, so approval is always one: an absent approval is none.
	approval := e.Approval
	if approval == "" {
		approval = software.ApprovalNone
	}
	return []field{{"name", e.Name}, {"description", e.Description}, {"category", e.Category}, {"source", optional(e.Source)},
		{"packages", packages}, {"approval", approval}}
}

// PackageSummary is how a plan shows a package reference: distribution/release/architecture=package, or
// =flatpak:<ref>@<scope> for a Flatpak application.
func PackageSummary(p software.PackageRef) string {
	s := p.Distribution + "/" + p.Release + "/" + p.Architecture + "="
	if p.FlatpakRef != "" {
		return s + "flatpak:" + p.FlatpakRef + "@" + p.Scope
	}
	return s + p.Package
}

// String is the plan form of a target: organization, device_group:<name>, user:<username> or user_group:<slug>.
func (t SoftwareTarget) String() string {
	switch t.Type {
	case software.TargetDeviceGroup:
		return t.Type + ":" + t.Name
	case software.TargetUser:
		return t.Type + ":" + t.Username
	case software.TargetUserGroup:
		return t.Type + ":" + t.Slug
	}
	return t.Type
}

// Key is the natural key of a software assignment: the device group of a device-group target (as group-scoped items
// carry it, so a group's deletion cascades to it), the entry, the target type and the user or user group.
func (a SoftwareAssignment) Key() Key {
	var group *string
	if a.Target.Type == software.TargetDeviceGroup {
		group = &a.Target.Name
	}
	k := scopedKey(group, a.Entry)
	k.assignment, k.SubjectType = true, a.Target.Type
	switch a.Target.Type {
	case software.TargetUser:
		k.Subject = a.Target.Username
	case software.TargetUserGroup:
		k.Subject = a.Target.Slug
	}
	return k
}

func (a SoftwareAssignment) fields() []field {
	return []field{{"entry", a.Entry}, {"target", a.Target.String()}, {"intent", a.Intent}, {"update_rule", a.UpdateRule},
		{"version", optional(a.Version)}, {"reason", a.Reason}}
}

// StepUpSections are the sections a change of which needs a fresh step-up for the whole apply (ADR 0034 decision 3,
// plan M13c decision 2): an API token's apply that changes one of them is refused as a whole.
func StepUpSections() []string { return []string{SectionSoftwareSources} }
