package backupset

import "testing"

// TestEscrowHeader: only the escrowed LUKS headers of a device belong to a backup set, never a diagnostics bundle or
// a key that leaves its device's directory.
func TestEscrowHeader(t *testing.T) {
	for key, want := range map[string]bool{
		"org/o1/devices/d1/luks-header/1.bin":           true,
		"org/o1/devices/d1/luks-header/root/2.bin":      true,
		"org/o1/devices/d1/diagnostics/20261104.tar.gz": false,
		"org/o1/devices/d1/luks-header":                 false,
		"org/o1/devices/d1/luks-header/":                false,
		"org/o1/devices/../luks-header/1.bin":           false,
		"org//devices/d1/luks-header/1.bin":             false,
		"tenant/o1/devices/d1/luks-header/1.bin":        false,
		"":                                              false,
	} {
		if got := EscrowHeader(key); got != want {
			t.Errorf("EscrowHeader(%q) = %v, want %v", key, got, want)
		}
	}
}
