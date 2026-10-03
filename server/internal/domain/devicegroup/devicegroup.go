// Package devicegroup holds the device group entity rules.
package devicegroup

import (
	"errors"
	"strings"
	"unicode/utf8"
)

// Validation errors.
var (
	ErrInvalidName        = errors.New("name must be 1 to 100 characters")
	ErrInvalidDescription = errors.New("description must be at most 1000 characters")
)

// NormalizeName trims surrounding whitespace.
func NormalizeName(name string) string { return strings.TrimSpace(name) }

// ValidateName checks the name length.
func ValidateName(name string) error {
	if n := utf8.RuneCountInString(name); n < 1 || n > 100 {
		return ErrInvalidName
	}
	return nil
}

// ValidateDescription checks the description length.
func ValidateDescription(d string) error {
	if utf8.RuneCountInString(d) > 1000 {
		return ErrInvalidDescription
	}
	return nil
}
