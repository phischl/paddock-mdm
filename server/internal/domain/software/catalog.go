package software

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/bundle"
)

// ErrEntry and ErrAssignment are the validation errors of catalog entries and assignments, answered with 400
// invalid_request.
var (
	ErrEntry      = errors.New("invalid catalog entry")
	ErrAssignment = errors.New("invalid software assignment")
)

// Limits of catalog entries and assignments (plan M13a decisions 7 to 9).
const (
	MaxDescriptionLength = 1000
	MaxCategoryLength    = 64
	MaxPackages          = 20
	MaxReasonLength      = 500
	MaxVersionLength     = 128
	// MaxIconBytes and MaxIconDimension bound a catalog icon (decision 11).
	MaxIconBytes     = 65536
	MaxIconDimension = 512
)

// The intents of an assignment (plan M13a decision 9) and its update rules. The intent values are part of the bundle
// format.
const (
	IntentRequired  = bundle.SoftwareRequired
	IntentUninstall = bundle.SoftwareUninstall
	IntentHold      = bundle.SoftwareHold
	IntentForbid    = bundle.SoftwareForbid
	// IntentAvailable offers an application to its target's users to install themselves (plan M13b decision 4). The
	// bundle constant follows with PDK-799.
	IntentAvailable = "available"

	UpdateLatest = "latest"
	UpdatePinned = "pinned"
)

// The scopes of a Flatpak reference (plan M13b decision 3): installed for the whole system or in the user's
// installation.
const (
	ScopeSystem = "system"
	ScopeUser   = "user"
)

// The targets of an assignment (plan M13b decision 1): the whole organization (no target ID), a device group, a user
// or a user group.
const (
	TargetOrganization = "organization"
	TargetDeviceGroup  = "device_group"
	TargetUser         = "user"
	TargetUserGroup    = "user_group"
)

// MaxFlatpakRefLength bounds a Flatpak application ID.
const MaxFlatpakRefLength = 255

// Wildcard is the release or architecture of a package reference that matches every release or architecture.
const Wildcard = "*"

var (
	distributionPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	releasePattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,31}$`)
	flatpakRefPattern   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*(\.[A-Za-z][A-Za-z0-9_-]*){2,}$`)
)

// PackageRef names the package that installs an application on one distribution, release and architecture. Release
// and Architecture may be Wildcard. A reference names either an APT Package or a Flatpak application (FlatpakRef,
// plan M13b decision 3) with its Scope; NormalizePackages sets the scope of a Flatpak reference that names none.
type PackageRef struct {
	Distribution string `json:"distribution"`
	Release      string `json:"release"`
	Architecture string `json:"architecture"`
	Package      string `json:"package,omitempty"`
	FlatpakRef   string `json:"flatpak_ref,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// NormalizePackages returns the references in their stored form: a Flatpak reference without a scope is a system
// one.
func NormalizePackages(packages []PackageRef) []PackageRef {
	out := slices.Clone(packages)
	for i := range out {
		if out[i].FlatpakRef != "" && out[i].Scope == "" {
			out[i].Scope = ScopeSystem
		}
	}
	return out
}

// DecodePackages reads the package references of a stored entry.
func DecodePackages(raw []byte) ([]PackageRef, error) {
	var out []PackageRef
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode package references: %w", err)
	}
	return out, nil
}

// ValidateEntry checks a catalog entry's name, description, category and package references against plan M13a
// decisions 7 and 8. Violations wrap ErrEntry. Name and category are checked in their trimmed form.
func ValidateEntry(name, description, category string, packages []PackageRef) error {
	if err := validateName(name, ErrEntry); err != nil {
		return err
	}
	if err := validateFreeText("description", description, MaxDescriptionLength, true, ErrEntry); err != nil {
		return err
	}
	if category = NormalizeName(category); category != "" {
		if err := validateName(category, ErrEntry); err != nil || utf8.RuneCountInString(category) > MaxCategoryLength {
			return fmt.Errorf("%w: category must be at most %d characters without control or invisible characters",
				ErrEntry, MaxCategoryLength)
		}
	}
	return ValidatePackageRefs(packages)
}

// ValidatePackages checks the package references of an entry whose source is of sourceKind (SourceKindAPT for the
// distribution's own repositories) against plan M13b decision 3: ValidatePackageRefs, and the references of a Flatpak
// source name Flatpak applications only while every other source's name APT packages only. Violations wrap ErrEntry.
func ValidatePackages(sourceKind string, packages []PackageRef) error {
	if err := ValidatePackageRefs(packages); err != nil {
		return err
	}
	for _, p := range packages {
		switch {
		case sourceKind == SourceKindFlatpak && p.FlatpakRef == "":
			return fmt.Errorf("%w: the packages of a flatpak source must name a flatpak_ref", ErrEntry)
		case sourceKind != SourceKindFlatpak && p.FlatpakRef != "":
			return fmt.Errorf("%w: a flatpak_ref needs a flatpak source", ErrEntry)
		}
	}
	return nil
}

// ValidatePackageRefs checks the package references of a catalog entry against plan M13a decision 8 and plan M13b
// decision 3: 1 to MaxPackages references, each with a valid distribution, release and architecture and either a
// valid package name or a valid Flatpak application ID with its scope, unique per distribution, release and
// architecture. Violations wrap ErrEntry.
func ValidatePackageRefs(packages []PackageRef) error {
	if len(packages) < 1 || len(packages) > MaxPackages {
		return fmt.Errorf("%w: packages must hold 1 to %d entries", ErrEntry, MaxPackages)
	}
	seen := map[[3]string]bool{}
	for _, p := range packages {
		if !distributionPattern.MatchString(p.Distribution) {
			return fmt.Errorf("%w: distribution must match ^[a-z][a-z0-9-]{0,31}$", ErrEntry)
		}
		if p.Release != Wildcard && !releasePattern.MatchString(p.Release) {
			return fmt.Errorf("%w: release must be * or match ^[a-z0-9][a-z0-9.-]{0,31}$", ErrEntry)
		}
		if p.Architecture != Wildcard && p.Architecture != "amd64" && p.Architecture != "arm64" {
			return fmt.Errorf("%w: architecture must be *, amd64 or arm64", ErrEntry)
		}
		if err := validatePackageName(p); err != nil {
			return err
		}
		key := [3]string{p.Distribution, p.Release, p.Architecture}
		if seen[key] {
			return fmt.Errorf("%w: distribution, release and architecture must be unique within packages", ErrEntry)
		}
		seen[key] = true
	}
	return nil
}

// validatePackageName checks what a reference installs: an APT package without a scope, or a Flatpak application
// ID in system or user scope.
func validatePackageName(p PackageRef) error {
	switch {
	case p.Package != "" && p.FlatpakRef != "":
		return fmt.Errorf("%w: a package reference names either package or flatpak_ref, not both", ErrEntry)
	case p.FlatpakRef != "":
		if len(p.FlatpakRef) > MaxFlatpakRefLength || !flatpakRefPattern.MatchString(p.FlatpakRef) {
			return fmt.Errorf("%w: flatpak_ref must be an application ID such as org.example.App (at most %d characters)",
				ErrEntry, MaxFlatpakRefLength)
		}
		if p.Scope != "" && p.Scope != ScopeSystem && p.Scope != ScopeUser {
			return fmt.Errorf("%w: scope must be system or user", ErrEntry)
		}
		return nil
	}
	if p.Scope != "" {
		return fmt.Errorf("%w: scope applies to a flatpak_ref only", ErrEntry)
	}
	if !bundle.ValidPackage(p.Package) {
		return fmt.Errorf("%w: package must match ^[a-z0-9][a-z0-9+.-]+$ (at most 128 characters)", ErrEntry)
	}
	if bundle.EntryRefused(p.Package) {
		return fmt.Errorf("%w: package %s is part of Paddock or its login stack and cannot be managed", ErrEntry, p.Package)
	}
	return nil
}

// NormalizeCategory trims a category, the form it is checked and stored in.
func NormalizeCategory(category string) string { return NormalizeName(category) }

// Resolve returns the package that installs the entry on a device with the given os-release ID, VERSION_ID and
// architecture (plan M13a decision 8). Only candidates of the device's distribution count; the most specific wins:
// exact release and architecture, exact release, exact architecture, neither. An empty device architecture matches
// the wildcard only. ok is false when no candidate applies: the entry is not applicable to the device.
func Resolve(packages []PackageRef, osID, versionID, arch string) (pkg string, ok bool) {
	ref, ok := ResolveRef(packages, osID, versionID, arch)
	return ref.Package, ok
}

// ResolveRef is Resolve returning the whole winning reference, so a Flatpak application keeps its ID and scope (plan
// M13b decision 8).
func ResolveRef(packages []PackageRef, osID, versionID, arch string) (ref PackageRef, ok bool) {
	best := -1
	for _, p := range packages {
		if p.Distribution != osID {
			continue
		}
		rank := 0
		switch {
		case p.Release == versionID && versionID != "":
			rank += 2
		case p.Release != Wildcard:
			continue
		}
		switch {
		case p.Architecture == arch && arch != "":
			rank++
		case p.Architecture != Wildcard:
			continue
		}
		if rank > best {
			best, ref, ok = rank, p, true
		}
	}
	return ref, ok
}

// DefaultUpdateRule is the update rule of an assignment that names none: pinned for a required application with a
// version, latest otherwise.
func DefaultUpdateRule(intent string, version *string) string {
	if intent == IntentRequired && version != nil {
		return UpdatePinned
	}
	return UpdateLatest
}

// MinUrgentReasonLength is the shortest reason an urgent assignment takes (plan M13c decision 7).
const MinUrgentReasonLength = 2

// ValidateUrgent checks the reason of an urgent assignment (plan M13c decision 7): an assignment the devices apply
// outside their maintenance windows says why, in 2 to 500 characters that are not only spaces. Violations wrap
// ErrAssignment.
func ValidateUrgent(urgent bool, reason string) error {
	if urgent && utf8.RuneCountInString(strings.TrimSpace(reason)) < MinUrgentReasonLength {
		return fmt.Errorf("%w: urgent needs a reason of %d to %d characters", ErrAssignment, MinUrgentReasonLength, MaxReasonLength)
	}
	return nil
}

// ValidateAssignment checks the intent, update rule, version and reason of an assignment (plan M13a decision 9, plan
// M13b decision 4). Violations wrap ErrAssignment.
func ValidateAssignment(intent, updateRule string, version *string, reason string) error {
	if updateRule != UpdateLatest && updateRule != UpdatePinned {
		return fmt.Errorf("%w: update_rule must be latest or pinned", ErrAssignment)
	}
	if version != nil && (!bundle.ValidPackageVersion(*version) || len(*version) > MaxVersionLength) {
		return fmt.Errorf("%w: version must match ^[A-Za-z0-9.+:~-]+$ (at most 128 characters)", ErrAssignment)
	}
	if err := validateFreeText("reason", reason, MaxReasonLength, false, ErrAssignment); err != nil {
		return err
	}
	switch intent {
	case IntentRequired:
		switch {
		case updateRule == UpdatePinned && version == nil:
			return fmt.Errorf("%w: a pinned required application needs a version", ErrAssignment)
		case updateRule == UpdateLatest && version != nil:
			return fmt.Errorf("%w: a required application with update_rule latest must not carry a version", ErrAssignment)
		}
	case IntentHold:
		if updateRule != UpdateLatest {
			return fmt.Errorf("%w: update_rule must be latest for intent hold", ErrAssignment)
		}
	case IntentUninstall, IntentForbid, IntentAvailable:
		if updateRule != UpdateLatest || version != nil {
			return fmt.Errorf("%w: intent %s takes no version and no update_rule other than latest", ErrAssignment, intent)
		}
	default:
		return fmt.Errorf("%w: intent must be required, uninstall, hold, forbid or available", ErrAssignment)
	}
	return nil
}

// Target names the target of an assignment with the given target IDs (plan M13b decision 1) and refuses more than
// one: an assignment applies to the whole organization, a device group, a user or a user group. Violations wrap
// ErrAssignment.
func Target(deviceGroupID, userID, userGroupID *uuid.UUID) (string, error) {
	target, n := TargetOrganization, 0
	for _, t := range []struct {
		id   *uuid.UUID
		name string
	}{{deviceGroupID, TargetDeviceGroup}, {userID, TargetUser}, {userGroupID, TargetUserGroup}} {
		if t.id != nil {
			target, n = t.name, n+1
		}
	}
	if n > 1 {
		return "", fmt.Errorf("%w: an assignment has at most one of device_group_id, user_id and user_group_id", ErrAssignment)
	}
	return target, nil
}

// ValidateAssignmentTarget refuses an assignment with intent of an entry whose packages the intent must not touch
// (bundle.RefusedIntent): forbid or uninstall of a package that Paddock depends on, required or hold of one that
// conflicts with it, and any intent of an entry stored before ValidateEntry refused it. available counts as required,
// since a user's install puts the package on the device like a required one. Violations wrap ErrAssignment.
func ValidateAssignmentTarget(intent string, packages []PackageRef) error {
	checked := intent
	if intent == IntentAvailable {
		checked = IntentRequired
	}
	for _, p := range packages {
		if p.Package != "" && bundle.RefusedIntent(p.Package, checked) {
			return fmt.Errorf("%w: intent %s is not allowed for the package %s, which Paddock depends on or conflicts with",
				ErrAssignment, intent, p.Package)
		}
	}
	return nil
}

// validateFreeText checks a description or a reason: valid UTF-8 of at most max runes without the characters a name
// must not contain, because the text reaches the portal and the audit log; line breaks stay allowed when multiline.
func validateFreeText(field, s string, max int, multiline bool, kind error) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("%w: %s must be valid UTF-8", kind, field)
	}
	if utf8.RuneCountInString(s) > max {
		return fmt.Errorf("%w: %s must be at most %d characters", kind, field, max)
	}
	if strings.ContainsFunc(s, func(r rune) bool {
		return invisibleInName(r) && (!multiline || r != '\n' && r != '\t')
	}) {
		return fmt.Errorf("%w: %s must not contain control, format or invisible characters", kind, field)
	}
	return nil
}
