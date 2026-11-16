package state_test

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/state"
)

// TestInstallSlotKeepsItsJSONName: state files written before the field was renamed carry the install passphrase's
// keyslot under passphrase_slot; losing it would stop the agent from ever removing that keyslot.
func TestInstallSlotKeepsItsJSONName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"luks":{"passphrase_slot":3,"recovery_slot":4}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := state.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.LUKS.InstallSlot == nil || *s.LUKS.InstallSlot != 3 || s.LUKS.RecoverySlot == nil || *s.LUKS.RecoverySlot != 4 {
		t.Fatalf("loaded keyslots: install %v, recovery %v", s.LUKS.InstallSlot, s.LUKS.RecoverySlot)
	}
	if err := state.Save(path, s); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var saved struct {
		LUKS map[string]any `json:"luks"`
	}
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.LUKS["passphrase_slot"] != float64(3) {
		t.Fatalf("saved LUKS state %v, want passphrase_slot 3", saved.LUKS)
	}
}

// TestIntegritySuspendedReadByOlderAgents (plan M5a R15.3, main §153): a state.json with integrity_suspended round-trips,
// and a decoder of the agent state from before the field, which is json.Unmarshal without DisallowUnknownFields
// into State without it, accepts the file, so a rollback to an older agent keeps its state.
func TestIntegritySuspendedReadByOlderAgents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	at := time.Date(2026, 11, 16, 8, 0, 0, 0, time.UTC)
	want := map[string]state.IntegritySuspension{"slots": {File: "/var/lib/paddock/state/probation.json", Observed: 600,
		Last: at, Reported: true}}
	if err := state.Save(path, state.State{Status: state.StatusActive, IntegritySuspended: want}); err != nil {
		t.Fatal(err)
	}
	s, err := state.Load(path)
	if err != nil || !maps.Equal(s.IntegritySuspended, want) {
		t.Fatalf("loaded %v, %v", s.IntegritySuspended, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The fields of State as of 96183f31 that this file sets; every other field is decoded the same way.
	var older struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(raw, &older); err != nil || older.Status != state.StatusActive {
		t.Fatalf("an older agent could not read the state: %v, %+v", err, older)
	}
	// Load is unchanged since 96183f31: it ignores a field it does not know, as an older agent meets this one.
	if err := os.WriteFile(path, []byte(`{"status":"active","a_field_of_a_newer_agent":{"x":{"observed_s":1}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if s, err := state.Load(path); err != nil || s.Status != state.StatusActive {
		t.Fatalf("an unknown field broke the state: %v", err)
	}
}
