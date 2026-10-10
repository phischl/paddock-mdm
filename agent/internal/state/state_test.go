package state_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

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
