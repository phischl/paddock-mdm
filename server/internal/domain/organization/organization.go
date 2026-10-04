// Package organization holds the organization entity rules.
package organization

import (
	"errors"
	"regexp"
	"unicode/utf8"
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
