// Package organization holds the organization entity rules.
package organization

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

// Statuses.
const (
	StatusProvisioning       = "provisioning"
	StatusActive             = "active"
	StatusProvisioningFailed = "provisioning_failed"
	StatusSuspended          = "suspended"
)

var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$`)

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

// LockedGroup returns the group whose members are locked: paddock.<slug>.locked (architecture §9.2).
func LockedGroup(slug string) string { return RootGroup(slug) + ".locked" }

// LocalUserGroup returns the Authentik group of a local Paddock user group: paddock.<slug>.g.<group_slug>.
func LocalUserGroup(slug, groupSlug string) string { return RootGroup(slug) + ".g." + groupSlug }

// SyncedUserGroup returns the mirror group of an imported upstream group: paddock.<slug>.s.<group_slug>.
func SyncedUserGroup(slug, groupSlug string) string { return RootGroup(slug) + ".s." + groupSlug }

// DeviceLoginGroup returns the per-device group of directly assigned users: paddock.<slug>.d.<device_id>.
func DeviceLoginGroup(slug string, deviceID uuid.UUID) string {
	return RootGroup(slug) + ".d." + deviceID.String()
}

// DeviceLoginApp returns the slug of the device login OAuth2 provider and application: paddock-device-<slug>.
func DeviceLoginApp(slug string) string { return "paddock-device-" + slug }

// IsPaddockGroup reports whether an Authentik group name belongs to Paddock's namespace (paddock.*).
func IsPaddockGroup(name string) bool { return strings.HasPrefix(name, groupPrefix) }

// MaxDomains bounds the domains of one organization.
const MaxDomains = 20

// ErrInvalidDomains is returned for malformed or duplicate domains.
var ErrInvalidDomains = fmt.Errorf("domains must be at most %d distinct lowercase DNS names such as example.org", MaxDomains)

var domainPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$`)

// ValidateDomains checks the domains of an organization (plan M3a decision 1); the order is kept because the first
// domain is the primary domain.
func ValidateDomains(domains []string) error {
	if len(domains) > MaxDomains {
		return ErrInvalidDomains
	}
	seen := map[string]bool{}
	for _, d := range domains {
		if len(d) > 253 || !domainPattern.MatchString(d) || seen[d] {
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
