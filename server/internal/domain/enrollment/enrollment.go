// Package enrollment holds the enrollment token rules (plan M2a decision 9): validity, secret generation and the
// conditions under which a token may be used.
package enrollment

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// Limits of enrollment tokens.
const (
	MaxValidity = 30 * 24 * time.Hour
	MinUses     = 1
	MaxUses     = 1000
)

// Token statuses as shown to administrators.
const (
	StatusActive    = "active"
	StatusRevoked   = "revoked"
	StatusExpired   = "expired"
	StatusExhausted = "exhausted"
)

// Validation errors.
var (
	ErrInvalidName    = errors.New("name must be 1 to 100 characters")
	ErrInvalidExpiry  = errors.New("expires_at must be in the future and at most 30 days ahead")
	ErrInvalidMaxUses = errors.New("max_uses must be between 1 and 1000")
)

// Reasons a token cannot be used; the value is the rejection reason reported to the device.
var (
	ErrRevoked   = errors.New("token_revoked")
	ErrExpired   = errors.New("token_expired")
	ErrExhausted = errors.New("token_exhausted")
)

// NormalizeName trims surrounding whitespace.
func NormalizeName(name string) string { return strings.TrimSpace(name) }

// Validate checks the fields of a new token.
func Validate(name string, expiresAt time.Time, maxUses int, now time.Time) error {
	if n := utf8.RuneCountInString(name); n < 1 || n > 100 {
		return ErrInvalidName
	}
	if !expiresAt.After(now) || expiresAt.Sub(now) > MaxValidity {
		return ErrInvalidExpiry
	}
	if maxUses < MinUses || maxUses > MaxUses {
		return ErrInvalidMaxUses
	}
	return nil
}

// NewSecret returns 32 random bytes as unpadded base64url and its SHA-256, the only form that is stored.
func NewSecret() (string, []byte, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", nil, fmt.Errorf("enrollment: secret: %w", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(b[:])
	return secret, HashSecret(secret), nil
}

// HashSecret is the stored and cached form of a token secret.
func HashSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// Usable returns nil when a token may enroll one more device, otherwise ErrRevoked, ErrExpired or ErrExhausted.
func Usable(revokedAt *time.Time, expiresAt time.Time, uses, maxUses int, now time.Time) error {
	switch {
	case revokedAt != nil:
		return ErrRevoked
	case !now.Before(expiresAt):
		return ErrExpired
	case uses >= maxUses:
		return ErrExhausted
	}
	return nil
}

// Status is the status shown to administrators.
func Status(revokedAt *time.Time, expiresAt time.Time, uses, maxUses int, now time.Time) string {
	switch Usable(revokedAt, expiresAt, uses, maxUses, now) {
	case ErrRevoked:
		return StatusRevoked
	case ErrExpired:
		return StatusExpired
	case ErrExhausted:
		return StatusExhausted
	}
	return StatusActive
}
