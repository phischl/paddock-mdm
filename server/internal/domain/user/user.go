// Package user holds the rules of the organization's users (plan M3a decision 2): local users created through
// Paddock and synced users mirrored from Authentik, whose upstream attributes are read-only.
package user

import (
	"errors"
	"net/mail"
	"slices"
	"strings"
	"unicode/utf8"
)

// Sources of a user.
const (
	SourceLocal  = "local"
	SourceSynced = "synced"
)

// Validation errors.
var (
	ErrInvalidUsername    = errors.New("username must be <local-part>@<domain> with a domain of the organization, lowercase letters, digits and . _ + -")
	ErrNoDomains          = errors.New("the organization has no domains; a platform administrator must add one before local users can be created")
	ErrInvalidDisplayName = errors.New("display name must be 1 to 200 characters")
	ErrInvalidEmail       = errors.New("email must be a plain address such as dave@example.org")
)

// NormalizeUsername trims and lowercases a username (usernames are UPNs, compared case-insensitively).
func NormalizeUsername(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// ValidateLocalUsername checks <local-part>@<one of domains> (plan M3a decision 1); username is normalized.
func ValidateLocalUsername(username string, domains []string) error {
	if len(domains) == 0 {
		return ErrNoDomains
	}
	local, domain, ok := strings.Cut(username, "@")
	if !ok || len(local) == 0 || len(local) > 64 || !slices.Contains(domains, domain) {
		return ErrInvalidUsername
	}
	if local[0] == '.' || local[len(local)-1] == '.' || strings.Contains(local, "..") {
		return ErrInvalidUsername
	}
	for _, r := range local {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && !strings.ContainsRune("._+-", r) {
			return ErrInvalidUsername
		}
	}
	return nil
}

// ValidateDisplayName checks the display name.
func ValidateDisplayName(name string) error {
	if n := utf8.RuneCountInString(name); n < 1 || n > 200 {
		return ErrInvalidDisplayName
	}
	return nil
}

// ValidateEmail checks an optional email address ("" = none).
func ValidateEmail(email string) error {
	if email == "" {
		return nil
	}
	a, err := mail.ParseAddress(email)
	if err != nil || a.Address != email || len(email) > 254 {
		return ErrInvalidEmail
	}
	return nil
}
