package enrollment

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestValidate(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	if err := Validate("laptops", now.Add(MaxValidity), 1000, now); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		name    string
		expires time.Time
		uses    int
		want    error
	}{
		"empty name":    {"", now.Add(time.Hour), 1, ErrInvalidName},
		"long name":     {strings.Repeat("n", 101), now.Add(time.Hour), 1, ErrInvalidName},
		"past":          {"x", now.Add(-time.Second), 1, ErrInvalidExpiry},
		"now":           {"x", now, 1, ErrInvalidExpiry},
		"more than 30d": {"x", now.Add(MaxValidity + time.Second), 1, ErrInvalidExpiry},
		"zero uses":     {"x", now.Add(time.Hour), 0, ErrInvalidMaxUses},
		"too many uses": {"x", now.Add(time.Hour), 1001, ErrInvalidMaxUses},
		"negative uses": {"x", now.Add(time.Hour), -1, ErrInvalidMaxUses},
	}
	for name, c := range cases {
		if err := Validate(c.name, c.expires, c.uses, now); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
}

func TestSecret(t *testing.T) {
	secret, hash, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != 43 || !bytes.Equal(hash, HashSecret(secret)) || len(hash) != 32 {
		t.Fatalf("secret %q hash %x", secret, hash)
	}
	other, _, _ := NewSecret()
	if other == secret {
		t.Fatal("secrets repeat")
	}
}

func TestUsableAndStatus(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	revoked := now.Add(-time.Minute)
	cases := []struct {
		revokedAt *time.Time
		expires   time.Time
		uses, max int
		want      error
		status    string
	}{
		{nil, now.Add(time.Hour), 0, 1, nil, StatusActive},
		{&revoked, now.Add(time.Hour), 0, 1, ErrRevoked, StatusRevoked},
		{nil, now, 0, 1, ErrExpired, StatusExpired},
		{nil, now.Add(time.Hour), 1, 1, ErrExhausted, StatusExhausted},
		{&revoked, now.Add(-time.Hour), 5, 1, ErrRevoked, StatusRevoked},
	}
	for i, c := range cases {
		if err := Usable(c.revokedAt, c.expires, c.uses, c.max, now); !errors.Is(err, c.want) {
			t.Errorf("case %d: %v, want %v", i, err, c.want)
		}
		if s := Status(c.revokedAt, c.expires, c.uses, c.max, now); s != c.status {
			t.Errorf("case %d: status %s, want %s", i, s, c.status)
		}
	}
}
