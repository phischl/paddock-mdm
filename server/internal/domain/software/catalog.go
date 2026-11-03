package software

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

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
	IntentRequired  = "required"
	IntentUninstall = "uninstall"
	IntentHold      = "hold"
	IntentForbid    = "forbid"

	UpdateLatest = "latest"
	UpdatePinned = "pinned"
)

// Wildcard is the release or architecture of a package reference that matches every release or architecture.
const Wildcard = "*"

var (
	distributionPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	releasePattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,31}$`)
)

// PackageRef names the package that installs an application on one distribution, release and architecture. Release
// and Architecture may be Wildcard.
type PackageRef struct {
	Distribution string `json:"distribution"`
	Release      string `json:"release"`
	Architecture string `json:"architecture"`
	Package      string `json:"package"`
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
		if !bundle.ValidPackage(p.Package) {
			return fmt.Errorf("%w: package must match ^[a-z0-9][a-z0-9+.-]+$ (at most 128 characters)", ErrEntry)
		}
		if bundle.EntryRefused(p.Package) {
			return fmt.Errorf("%w: package %s is part of Paddock or its login stack and cannot be managed", ErrEntry, p.Package)
		}
		key := [3]string{p.Distribution, p.Release, p.Architecture}
		if seen[key] {
			return fmt.Errorf("%w: distribution, release and architecture must be unique within packages", ErrEntry)
		}
		seen[key] = true
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
			best, pkg, ok = rank, p.Package, true
		}
	}
	return pkg, ok
}

// DefaultUpdateRule is the update rule of an assignment that names none: pinned for a required application with a
// version, latest otherwise.
func DefaultUpdateRule(intent string, version *string) string {
	if intent == IntentRequired && version != nil {
		return UpdatePinned
	}
	return UpdateLatest
}

// ValidateAssignment checks the intent, update rule, version and reason of an assignment (plan M13a decision 9).
// Violations wrap ErrAssignment.
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
	case IntentUninstall, IntentForbid:
		if updateRule != UpdateLatest || version != nil {
			return fmt.Errorf("%w: intent %s takes no version and no update_rule other than latest", ErrAssignment, intent)
		}
	default:
		return fmt.Errorf("%w: intent must be required, uninstall, hold or forbid", ErrAssignment)
	}
	return nil
}

// ValidateAssignmentTarget refuses an assignment with intent of an entry whose packages the intent must not touch
// (bundle.RefusedIntent): forbid or uninstall of a package that Paddock depends on, required or hold of one that
// conflicts with it, and any intent of an entry stored before ValidateEntry refused it. Violations wrap
// ErrAssignment.
func ValidateAssignmentTarget(intent string, packages []PackageRef) error {
	for _, p := range packages {
		if bundle.RefusedIntent(p.Package, intent) {
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
