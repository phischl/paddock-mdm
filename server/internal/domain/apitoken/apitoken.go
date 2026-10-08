// Package apitoken holds the API token rules (plan M6c decisions 2, 3 and 6): secret format, name, expiry window and
// the role ceiling of the creating administrator.
package apitoken

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// Prefix starts every API token secret.
const Prefix = "pdk_"

// Shape of a secret: Prefix and 32 random bytes in base64url without padding (43 characters).
const (
	secretBytes = 32
	// SecretLength is the length of a secret.
	SecretLength = len(Prefix) + 43
	// PrefixLength is the length of the part of a secret shown in lists (Prefix and 8 characters).
	PrefixLength = len(Prefix) + 8
)

// Expiry window of a token, relative to its creation.
const (
	MinValidity = time.Hour
	MaxValidity = 365 * 24 * time.Hour
)

// Validation errors.
var (
	ErrInvalidName      = errors.New("name must start with a letter or digit and have at most 64 characters of letters, digits, spaces, '.', '_' and '-'")
	ErrExpiresTooSoon   = errors.New("expires_at must be at least 1 hour ahead")
	ErrExpiresTooLate   = errors.New("expires_at must be at most 365 days ahead")
	ErrRoleAboveCeiling = errors.New("role exceeds the creating administrator's role")
)

var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)

// Generate creates a new secret, its SHA-256 for storage and the prefix shown in lists.
func Generate() (secret string, hash []byte, prefix string, err error) {
	b := make([]byte, secretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", nil, "", fmt.Errorf("apitoken: random secret: %w", err)
	}
	secret = Prefix + base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(secret))
	return secret, sum[:], secret[:PrefixLength], nil
}

// Hash returns the SHA-256 of secret; false when the secret does not have the shape of a token secret.
func Hash(secret string) ([]byte, bool) {
	if len(secret) != SecretLength || !strings.HasPrefix(secret, Prefix) {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(secret[len(Prefix):])
	if err != nil || len(raw) != secretBytes {
		return nil, false
	}
	sum := sha256.Sum256([]byte(secret))
	return sum[:], true
}

// ValidateName checks a token name.
func ValidateName(name string) error {
	if !namePattern.MatchString(name) {
		return ErrInvalidName
	}
	return nil
}

// ValidateExpiry checks now+MinValidity ≤ expiresAt ≤ now+MaxValidity.
func ValidateExpiry(now, expiresAt time.Time) error {
	switch {
	case expiresAt.Before(now.Add(MinValidity)):
		return ErrExpiresTooSoon
	case expiresAt.After(now.Add(MaxValidity)):
		return ErrExpiresTooLate
	}
	return nil
}

// RoleAllowed reports whether an administrator with role creator may create a token with role requested: an
// organization administrator any organization role, an operator operator and auditor tokens, an auditor none.
func RoleAllowed(creator, requested principal.Role) bool {
	switch creator {
	case principal.RoleOrgAdmin:
		return requested == principal.RoleOrgAdmin || requested == principal.RoleOrgOperator || requested == principal.RoleOrgAuditor
	case principal.RoleOrgOperator:
		return requested == principal.RoleOrgOperator || requested == principal.RoleOrgAuditor
	}
	return false
}
