// Package usergroup holds the rules of user groups (plan M3a decision 3): local groups managed in Paddock and imported
// upstream groups whose membership a worker mirrors (read-only in Paddock).
package usergroup

import (
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Sources of a group.
const (
	SourceLocal  = "local"
	SourceSynced = "synced"
)

// Validation errors.
var (
	ErrInvalidSlug = errors.New("slug must match ^[a-z0-9][a-z0-9-]{0,40}[a-z0-9]$")
	ErrInvalidName = errors.New("name must be 1 to 100 characters")
)

var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}[a-z0-9]$`)

// ValidateSlug checks the slug that forms the group's Authentik name.
func ValidateSlug(slug string) error {
	if !slugPattern.MatchString(slug) {
		return ErrInvalidSlug
	}
	return nil
}

// NormalizeName trims surrounding whitespace.
func NormalizeName(name string) string { return strings.TrimSpace(name) }

// ValidateName checks the display name.
func ValidateName(name string) error {
	if n := utf8.RuneCountInString(name); n < 1 || n > 100 {
		return ErrInvalidName
	}
	return nil
}
