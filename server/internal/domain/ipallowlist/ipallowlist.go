// Package ipallowlist is the IP allow list of the administrative surfaces (plan M7a decision 11): the entries, the
// in-memory set the api enforces, and the consequence check that protects a platform administrator from locking
// themself out.
package ipallowlist

import (
	"errors"
	"fmt"
	"net/netip"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

// Entry is one allow-listed range.
type Entry struct {
	ID        uuid.UUID
	CIDR      netip.Prefix
	Label     string
	CreatedBy string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// MaxLabelRunes bounds the label (the column has the same check).
const MaxLabelRunes = 64

// ParseCIDR accepts "a.b.c.d/n" and "<ipv6>/n" only: IPv4-mapped IPv6 is refused, a /0 is refused (it would switch
// the feature on without restricting anything) and host bits must be zero; the error names the canonical form.
func ParseCIDR(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, errors.New("not a CIDR: use a.b.c.d/n or <ipv6>/n; a single address is /32 or /128")
	}
	if p.Addr().Is4In6() {
		return netip.Prefix{}, errors.New("IPv4-mapped IPv6 ranges are not allowed: use the IPv4 form")
	}
	if p.Bits() == 0 {
		return netip.Prefix{}, errors.New("a /0 range is not allowed: it would admit every address")
	}
	if m := p.Masked(); m != p {
		return netip.Prefix{}, fmt.Errorf("host bits are set: use %s", m)
	}
	return p, nil
}

// ValidateLabel accepts 1–64 runes without control characters; the caller trims the label.
func ValidateLabel(s string) error {
	n := utf8.RuneCountInString(s)
	if n == 0 || n > MaxLabelRunes {
		return fmt.Errorf("label must be 1 to %d characters", MaxLabelRunes)
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return errors.New("label must not contain control characters")
		}
	}
	return nil
}

// Consequence is what a change of the list means for the caller or the feature.
type Consequence string

// Consequences of a change (plan M7a decision 12).
const (
	ConsequenceNone    Consequence = "none"
	ConsequenceLockout Consequence = "lockout" // the caller's own address would no longer be covered
	ConsequenceDisable Consequence = "disable" // the last entry would be removed: the feature switches off
)

// ConsequenceOf: Disable when before is non-empty and after is empty; Lockout when after is non-empty and no prefix of
// after contains caller (an invalid caller address counts as not contained); otherwise None.
func ConsequenceOf(before, after []netip.Prefix, caller netip.Addr) Consequence {
	switch {
	case len(before) > 0 && len(after) == 0:
		return ConsequenceDisable
	case len(after) > 0 && !containsAny(after, caller):
		return ConsequenceLockout
	}
	return ConsequenceNone
}

func containsAny(prefixes []netip.Prefix, ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// Set is the enforced allow list: off while empty.
type Set struct{ prefixes []netip.Prefix }

// NewSet copies prefixes.
func NewSet(prefixes []netip.Prefix) Set {
	out := make([]netip.Prefix, len(prefixes))
	copy(out, prefixes)
	return Set{prefixes: out}
}

// Enabled reports whether the list restricts anything (at least one entry).
func (s Set) Enabled() bool { return len(s.prefixes) > 0 }

// Len is the number of entries.
func (s Set) Len() int { return len(s.prefixes) }

// Allows reports whether ip may use the administrative surfaces: always while the list is off.
func (s Set) Allows(ip netip.Addr) bool { return !s.Enabled() || containsAny(s.prefixes, ip) }

// Covering returns the prefixes that contain ip.
func (s Set) Covering(ip netip.Addr) []netip.Prefix {
	if !ip.IsValid() {
		return nil
	}
	ip = ip.Unmap()
	var out []netip.Prefix
	for _, p := range s.prefixes {
		if p.Contains(ip) {
			out = append(out, p)
		}
	}
	return out
}
