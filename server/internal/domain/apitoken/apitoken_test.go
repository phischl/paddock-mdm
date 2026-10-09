package apitoken_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/domain/apitoken"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

func TestGenerateHasTheDocumentedShape(t *testing.T) {
	secret, hash, prefix, err := apitoken.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != 47 || !strings.HasPrefix(secret, "pdk_") {
		t.Fatalf("secret %q: want 47 characters starting with pdk_", secret)
	}
	if prefix != secret[:12] || len(prefix) != 12 {
		t.Fatalf("prefix %q, want the first 12 characters of the secret", prefix)
	}
	sum := sha256.Sum256([]byte(secret))
	if !bytes.Equal(hash, sum[:]) {
		t.Fatal("hash is not the SHA-256 of the secret")
	}
	again, _, _, err := apitoken.Generate()
	if err != nil || again == secret {
		t.Fatalf("two secrets are equal (%v)", err)
	}
}

func TestHash(t *testing.T) {
	secret, want, _, err := apitoken.Generate()
	if err != nil {
		t.Fatal(err)
	}
	got, ok := apitoken.Hash(secret)
	if !ok || !bytes.Equal(got, want) {
		t.Fatalf("Hash of a generated secret = %x, %v", got, ok)
	}
	for name, s := range map[string]string{
		"empty":        "",
		"short":        secret[:46],
		"long":         secret + "A",
		"prefix":       "pdx_" + secret[4:],
		"not base64":   "pdk_" + strings.Repeat("!", 43),
		"padding char": "pdk_" + strings.Repeat("A", 42) + "=",
	} {
		if _, ok := apitoken.Hash(s); ok {
			t.Errorf("%s: %q accepted", name, s)
		}
	}
}

func TestValidateName(t *testing.T) {
	for _, ok := range []string{"ci", "CI deploy", "a", "x.y_z-1", "9" + strings.Repeat("a", 63)} {
		if err := apitoken.ValidateName(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", " ci", "-ci", "ci/deploy", "a" + strings.Repeat("b", 64), "über"} {
		if err := apitoken.ValidateName(bad); !errors.Is(err, apitoken.ErrInvalidName) {
			t.Errorf("%q: %v, want ErrInvalidName", bad, err)
		}
	}
}

func TestValidateExpiry(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	for name, c := range map[string]struct {
		at   time.Time
		want error
	}{
		"exactly one hour":   {now.Add(time.Hour), nil},
		"exactly 365 days":   {now.Add(365 * 24 * time.Hour), nil},
		"90 days":            {now.Add(90 * 24 * time.Hour), nil},
		"30 minutes":         {now.Add(30 * time.Minute), apitoken.ErrExpiresTooSoon},
		"past":               {now.Add(-time.Hour), apitoken.ErrExpiresTooSoon},
		"365 days and a sec": {now.Add(365*24*time.Hour + time.Second), apitoken.ErrExpiresTooLate},
	} {
		if err := apitoken.ValidateExpiry(now, c.at); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
}

func TestRoleAllowed(t *testing.T) {
	admin, operator, auditor := principal.RoleOrgAdmin, principal.RoleOrgOperator, principal.RoleOrgAuditor
	for _, c := range []struct {
		creator, requested principal.Role
		want               bool
	}{
		{admin, admin, true}, {admin, operator, true}, {admin, auditor, true},
		{operator, admin, false}, {operator, operator, true}, {operator, auditor, true},
		{auditor, admin, false}, {auditor, operator, false}, {auditor, auditor, false},
		{admin, principal.RolePlatform, false}, {principal.RolePlatform, auditor, false},
	} {
		if got := apitoken.RoleAllowed(c.creator, c.requested); got != c.want {
			t.Errorf("RoleAllowed(%s, %s) = %v, want %v", c.creator, c.requested, got, c.want)
		}
	}
}
