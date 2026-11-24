package offboarding_test

import (
	"slices"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/domain/offboarding"
)

// TestSteps (plan M17 decision 6): the order of the steps, each followed by the next, none after the tombstone.
func TestSteps(t *testing.T) {
	want := []string{"sessions", "devices", "outbox", "authentik", "fleet", "objects", "valkey", "audit_final", "database", "tombstone"}
	if !slices.Equal(offboarding.Steps(), want) {
		t.Fatalf("steps %v, want %v", offboarding.Steps(), want)
	}
	for i, s := range want[:len(want)-1] {
		if next, ok := offboarding.Next(s); !ok || next != want[i+1] {
			t.Fatalf("Next(%s) = %s, %v", s, next, ok)
		}
	}
	for _, s := range []string{"tombstone", "unknown", ""} {
		if next, ok := offboarding.Next(s); ok {
			t.Fatalf("Next(%q) = %s", s, next)
		}
	}
}

// TestErrorCodes: the closed set of §6 plus object_retained (amendment k addendum), finalize_waiting (amendment j)
// and signing_unavailable (step devices, PDK-1016).
func TestErrorCodes(t *testing.T) {
	codes := offboarding.ErrorCodes()
	sorted := slices.Clone(codes)
	slices.Sort(sorted)
	if len(slices.Compact(sorted)) != len(codes) || len(codes) != 10 {
		t.Fatalf("error codes %v", codes)
	}
	for _, c := range []string{"authentik_unavailable", "fleet_unavailable", "object_store_unavailable", "object_retained",
		"valkey_unavailable", "outbox_pending", "audit_writer_pending", "database_error", "signing_unavailable", "finalize_waiting"} {
		if !slices.Contains(codes, c) {
			t.Fatalf("%s missing", c)
		}
	}
}
