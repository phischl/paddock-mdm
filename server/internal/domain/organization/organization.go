// Package organization holds the organization entity rules.
package organization

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/policy"
)

// Statuses.
const (
	StatusProvisioning       = "provisioning"
	StatusActive             = "active"
	StatusProvisioningFailed = "provisioning_failed"
	StatusSuspended          = "suspended"
	// StatusDeleting and StatusDeleted are the offboarding states (ADR 0052 decision 1): the worker deletes the
	// organization's data, then leaves a tombstone.
	StatusDeleting = "deleting"
	StatusDeleted  = "deleted"
)

// ListedByDefault are the statuses an organization list shows without a status filter: every status but deleted,
// so tombstones do not crowd the list (plan M17 §6).
func ListedByDefault() []string {
	return []string{StatusProvisioning, StatusActive, StatusProvisioningFailed, StatusSuspended, StatusDeleting}
}

// Deletable reports whether a deletion can be requested for an organization in status (plan M17 decision 1).
func Deletable(status string) bool {
	return status == StatusActive || status == StatusProvisioningFailed
}

// DeletionPending reports whether an organization's deletion is requested and not yet running (ADR 0052 decision 1).
func DeletionPending(status string, deleteAfter *time.Time) bool {
	return Deletable(status) && deleteAfter != nil
}

// Grace period bounds of a deletion request in days (plan M17 decision 2): development stacks may delete at once.
const (
	MinGraceDays            = 7
	MinGraceDaysDevelopment = 0
	MaxGraceDays            = 90
)

// OffboardedDeviceRetention is how long a device keeps receiving the offboarding uninstall after its organization
// was deleted (ADR 0052 decision 2); the command expires delete_after plus this retention.
const OffboardedDeviceRetention = 365 * 24 * time.Hour

// Deletion reasons are bounded like the database column.
const (
	minDeletionReason = 2
	maxDeletionReason = 500
)

// ErrInvalidDeletionReason and ErrInvalidGraceDays are validation errors of a deletion request.
var (
	ErrInvalidDeletionReason = fmt.Errorf("reason must have %d to %d characters", minDeletionReason, maxDeletionReason)
	ErrInvalidGraceDays      = fmt.Errorf("grace_days must be %d to %d", MinGraceDays, MaxGraceDays)
	ErrInvalidGraceDaysDev   = fmt.Errorf("grace_days must be %d to %d", MinGraceDaysDevelopment, MaxGraceDays)
)

// ValidateDeletionReason checks the length of a deletion reason in characters.
func ValidateDeletionReason(reason string) error {
	if n := utf8.RuneCountInString(reason); n < minDeletionReason || n > maxDeletionReason {
		return ErrInvalidDeletionReason
	}
	return nil
}

// ValidateGraceDays checks the grace period of a deletion request; development allows 0.
func ValidateGraceDays(days int, development bool) error {
	if development {
		if days < MinGraceDaysDevelopment || days > MaxGraceDays {
			return ErrInvalidGraceDaysDev
		}
		return nil
	}
	if days < MinGraceDays || days > MaxGraceDays {
		return ErrInvalidGraceDays
	}
	return nil
}

var slugPattern = regexp.MustCompile(`^` + policy.OrgSlugPattern + `$`)

// ErrInvalidSlug and ErrInvalidName are validation errors.
var (
	ErrInvalidSlug = errors.New("slug must match ^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$ and must not be \"platform\"")
	ErrInvalidName = errors.New("name must be 1 to 200 characters")
)

// ValidateSlug checks the slug rules of the database constraint.
func ValidateSlug(slug string) error {
	if !slugPattern.MatchString(slug) || slug == "platform" {
		return ErrInvalidSlug
	}
	return nil
}

// ValidateName checks the name length.
func ValidateName(name string) error {
	if n := utf8.RuneCountInString(name); n < 1 || n > 200 {
		return ErrInvalidName
	}
	return nil
}

// GroupRole is the suffix of an organization's Authentik role group.
type GroupRole string

// Organization role groups.
const (
	GroupAdmins    GroupRole = "admins"
	GroupOperators GroupRole = "operators"
	GroupAuditors  GroupRole = "auditors"
)

// Authentik group names use "." as separator because Himmelblau drops group claim values containing ":"
// (architecture §9.2); slugs cannot contain ".", so the names are unambiguous.
const groupPrefix = "paddock."

var roleGroupPattern = regexp.MustCompile(`^paddock\.([a-z0-9][a-z0-9-]{1,30}[a-z0-9])\.(admins|operators|auditors)$`)

// RootGroup returns the Authentik root group of an organization: paddock.<slug>.
func RootGroup(slug string) string { return groupPrefix + slug }

// RoleGroup returns the Authentik role group of an organization: paddock.<slug>.<role>.
func RoleGroup(slug string, role GroupRole) string { return RootGroup(slug) + "." + string(role) }

// PlatformAdminsGroup returns the Authentik group of platform administrators: paddock.platform.admins.
func PlatformAdminsGroup() string { return groupPrefix + "platform." + string(GroupAdmins) }

// ParseRoleGroup returns slug and role of an organization role group. ok is false for every other name,
// including the platform group and role groups of the reserved slug "platform".
func ParseRoleGroup(name string) (slug string, role GroupRole, ok bool) {
	m := roleGroupPattern.FindStringSubmatch(name)
	if m == nil || m[1] == "platform" {
		return "", "", false
	}
	return m[1], GroupRole(m[2]), true
}

// IsAdministratorGroup reports whether a direct membership of the group name grants a portal role by its name alone:
// paddock.<x>.admins, .operators or .auditors for any x, the platform group included. It is the predicate of the
// sign-in policy paddock-admin-login-webauthn-administrator (deploy/compose/authentik/blueprints/paddock-portal.yaml),
// which denies such an account without a passkey (ADR 0053); the two MUST stay equal.
func IsAdministratorGroup(name string) bool {
	p := strings.Split(name, ".")
	return len(p) == 3 && p[0] == "paddock" && (p[2] == string(GroupAdmins) || p[2] == string(GroupOperators) ||
		p[2] == string(GroupAuditors))
}

// LockedGroup returns the group whose members are locked: paddock.<slug>.locked (architecture §9.2).
func LockedGroup(slug string) string { return RootGroup(slug) + ".locked" }

// LocalUserGroup returns the Authentik group of a local Paddock user group: paddock.<slug>.g.<group_slug>.
func LocalUserGroup(slug, groupSlug string) string { return RootGroup(slug) + ".g." + groupSlug }

// SyncedUserGroup returns the mirror group of an imported upstream group: paddock.<slug>.s.<group_slug>.
func SyncedUserGroup(slug, groupSlug string) string { return RootGroup(slug) + ".s." + groupSlug }

// DeviceLoginGroup returns the per-device group of directly assigned users: paddock.<slug>.d.<device_id>.
func DeviceLoginGroup(slug string, deviceID uuid.UUID) string {
	return DeviceLoginGroupPrefix(slug) + deviceID.String()
}

// DeviceLoginGroupPrefix returns the prefix of the names of the organization's per-device groups: paddock.<slug>.d.
func DeviceLoginGroupPrefix(slug string) string { return RootGroup(slug) + ".d." }

// DeviceLoginApp returns the slug of the device login OAuth2 provider and application: paddock-device-<slug>.
func DeviceLoginApp(slug string) string { return "paddock-device-" + slug }

// IsPaddockGroup reports whether an Authentik group name belongs to Paddock's namespace (paddock.*).
func IsPaddockGroup(name string) bool { return strings.HasPrefix(name, groupPrefix) }

// MaxDomains bounds the domains of one organization.
const MaxDomains = 20

// ErrInvalidDomains is returned for malformed or duplicate domains.
var ErrInvalidDomains = fmt.Errorf("domains must be at most %d distinct lowercase DNS names such as example.org", MaxDomains)

// ValidateDomains checks the domains of an organization (plan M3a decision 1); the order is kept because the first
// domain is the primary domain.
func ValidateDomains(domains []string) error {
	if len(domains) > MaxDomains {
		return ErrInvalidDomains
	}
	seen := map[string]bool{}
	for _, d := range domains {
		if policy.ValidateLoginDomain(d) != nil || seen[d] {
			return ErrInvalidDomains
		}
		seen[d] = true
	}
	return nil
}

// PrimaryDomain is the first domain, or "" for an organization without domains.
func PrimaryDomain(domains []string) string {
	if len(domains) == 0 {
		return ""
	}
	return domains[0]
}
