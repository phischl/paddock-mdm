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

// AuthentikGroups returns the four Authentik groups of an organization (plan M0 decision 14).
func AuthentikGroups(slug string) (root, admins, operators, auditors string) {
	root = "paddock:" + slug
	return root, root + ":admins", root + ":operators", root + ":auditors"
}
