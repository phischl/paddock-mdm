package app_test

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
)

// TestIdentityEnsureJitter (PDK-1021, plan M17 decision 20): the jitter is the first eight bytes of the organization
// ID as uint64 modulo 3600 seconds, the same for every call, within [0, 3600) s and spread over the hour.
func TestIdentityEnsureJitter(t *testing.T) {
	for id, want := range map[string]time.Duration{
		"00000000-0000-0000-ffff-ffffffffffff": 0,
		"00000000-0000-0e0f-0000-000000000000": 3599 * time.Second, // 0x0e0f = 3599
		"00000000-0000-0e10-0000-000000000000": 0,                  // 0x0e10 = 3600
		"ffffffff-ffff-ffff-0000-000000000000": 15 * time.Second,   // (2^64 - 1) mod 3600
	} {
		if got := app.IdentityEnsureJitter(uuid.MustParse(id)); got != want {
			t.Errorf("jitter of %s: %v, want %v", id, got, want)
		}
	}
	buckets := map[time.Duration]int{}
	// Version 7 IDs one millisecond apart, as organizations created one after another get them: the timestamp in
	// the first six bytes moves the jitter by 65536 mod 3600 = 736 s per millisecond.
	base := uuid.Must(uuid.NewV7())
	ms := uint64(base[0])<<40 | uint64(base[1])<<32 | uint64(base[2])<<24 | uint64(base[3])<<16 | uint64(base[4])<<8 | uint64(base[5])
	for i := range uint64(2000) {
		id := base
		for b := range 6 {
			id[b] = byte((ms + i) >> (40 - 8*b))
		}
		j := app.IdentityEnsureJitter(id)
		if j < 0 || j >= time.Hour || j%time.Second != 0 {
			t.Fatalf("jitter of %s: %v, outside [0, 3600) s", id, j)
		}
		if again := app.IdentityEnsureJitter(id); again != j {
			t.Fatalf("jitter of %s: %v, then %v", id, j, again)
		}
		buckets[j/(10*time.Minute)]++
	}
	if len(buckets) != 6 {
		t.Fatalf("jitter of 2000 new organizations falls into %d of 6 ten-minute slices", len(buckets))
	}
}

// TestIdentityEnsureDue (PDK-1021): due without a mark, with another revision, from the full interval plus jitter on;
// not due before it; always due without a revision (no cache).
func TestIdentityEnsureDue(t *testing.T) {
	id := uuid.MustParse("00000000-0000-0064-0000-000000000000") // jitter 100 s
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	full := app.IdentityFullEnsureInterval + 100*time.Second
	org := func(ago time.Duration, revision string) pgstore.Organization {
		o := pgstore.Organization{ID: id}
		if ago >= 0 {
			at := now.Add(-ago)
			o.IdpEnsuredAt = &at
		}
		if revision != "" {
			o.IdpEnsureRevision = &revision
		}
		return o
	}
	for _, tc := range []struct {
		name     string
		o        pgstore.Organization
		revision string
		want     bool
	}{
		{"never ensured", org(-1, ""), "r1", true},
		{"mark cleared, revision kept", org(-1, "r1"), "r1", true},
		{"just ensured", org(0, "r1"), "r1", false},
		{"one second before the full interval", org(full-time.Second, "r1"), "r1", false},
		{"at the full interval", org(full, "r1"), "r1", true},
		{"after the full interval", org(full+time.Hour, "r1"), "r1", true},
		{"other revision", org(0, "r0"), "r1", true},
		{"no revision recorded", org(0, ""), "r1", true},
		{"no cache", org(0, "r1"), "", true},
	} {
		if got := app.IdentityEnsureDue(tc.o, tc.revision, now); got != tc.want {
			t.Errorf("%s: due %v, want %v", tc.name, got, tc.want)
		}
	}
}
