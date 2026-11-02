package outbound_test

import (
	"reflect"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/outbound"
)

// TestPseudonym: a fixed vector (openssl dgst -sha256 -hmac k1 over "alice"), case-insensitive.
func TestPseudonym(t *testing.T) {
	if got := outbound.Pseudonym([]byte("k1"), "Alice"); got != "u_aff3e2227d2581aeb66e413f" {
		t.Fatalf("Pseudonym = %s", got)
	}
}

func sampleEvent() audit.Event {
	return audit.Event{
		Code: "user_group.member_added", Outcome: audit.OutcomeSuccess,
		Actor:  audit.Actor{Type: audit.ActorAdmin, ID: "acc-1", Display: "admin@example.org", IP: "203.0.113.7", StepUp: true},
		Target: &audit.Target{Type: "user", ID: "u-1", Display: "alice"},
		Params: map[string]any{
			"username": "alice", "user": "bob", "display_name": "Alice A.", "requested_by": "carol",
			"approved_by": "dave", "created_by": "erin", "users": []any{"frank", "grace"},
			"members": 3, "group": "admins", "file": "/etc/sudoers.d/x",
		},
	}
}

// TestPseudonymize: exactly the fields of ADR 0031 decision 8 change, admin actor id and ip are dropped, the input
// stays unchanged, the result is deterministic per key and differs across keys.
func TestPseudonymize(t *testing.T) {
	key := []byte("org-key-1")
	in := sampleEvent()
	before := sampleEvent()
	out := outbound.Pseudonymize(key, in)
	if !reflect.DeepEqual(in, before) {
		t.Fatal("the input event was modified")
	}
	ps := func(s string) string { return outbound.Pseudonym(key, s) }
	if out.Actor.Display != ps("admin@example.org") || out.Actor.ID != "" || out.Actor.IP != "" || !out.Actor.StepUp ||
		out.Actor.Type != audit.ActorAdmin {
		t.Errorf("actor %+v", out.Actor)
	}
	if out.Target.Display != ps("alice") || out.Target.ID != "u-1" {
		t.Errorf("target %+v", out.Target)
	}
	want := map[string]any{
		"username": ps("alice"), "user": ps("bob"), "display_name": ps("Alice A."), "requested_by": ps("carol"),
		"approved_by": ps("dave"), "created_by": ps("erin"), "users": []any{ps("frank"), ps("grace")},
		"members": 3, "group": "admins", "file": "/etc/sudoers.d/x",
	}
	if !reflect.DeepEqual(out.Params, want) {
		t.Errorf("params %v, want %v", out.Params, want)
	}
	if !reflect.DeepEqual(outbound.Pseudonymize(key, sampleEvent()), out) {
		t.Error("not deterministic for one key")
	}
	other := outbound.Pseudonymize([]byte("org-key-2"), sampleEvent())
	if other.Params["username"] == out.Params["username"] || other.Actor.Display == out.Actor.Display {
		t.Error("two keys give the same pseudonym")
	}
}

// TestPseudonymizeLeavesOthers: device actors and device targets keep their identity; a platform administrator is an
// administrator; admin_account targets are pseudonymized.
func TestPseudonymizeLeavesOthers(t *testing.T) {
	key := []byte("k")
	dev := audit.Event{
		Actor:  audit.Actor{Type: audit.ActorDevice, ID: "d-1", Display: "lt-01", IP: "198.51.100.2"},
		Target: &audit.Target{Type: "device", ID: "d-1", Display: "lt-01"},
		Params: map[string]any{"users": []string{"alice"}},
	}
	out := outbound.Pseudonymize(key, dev)
	if out.Actor != dev.Actor || *out.Target != *dev.Target {
		t.Errorf("device identity changed: %+v %+v", out.Actor, out.Target)
	}
	if got := out.Params["users"].([]string); got[0] != outbound.Pseudonym(key, "alice") {
		t.Errorf("users %v", got)
	}
	pa := outbound.Pseudonymize(key, audit.Event{
		Actor:  audit.Actor{Type: audit.ActorPlatformAdmin, ID: "p", Display: "root@example.org", IP: "192.0.2.1"},
		Target: &audit.Target{Type: "admin_account", ID: "a", Display: "eve"},
	})
	if pa.Actor.ID != "" || pa.Actor.IP != "" || pa.Actor.Display != outbound.Pseudonym(key, "root@example.org") ||
		pa.Target.Display != outbound.Pseudonym(key, "eve") {
		t.Errorf("platform admin %+v target %+v", pa.Actor, pa.Target)
	}
}
