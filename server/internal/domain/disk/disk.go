// Package disk holds the disk encryption policy of devices (ADR 0038).
package disk

// Unlock modes of a disk encrypted by the Paddock autoinstall (ADR 0038 decision 1).
const (
	UnlockModeTPMPIN  = "tpm_pin"  // TPM2 + boot PIN, the default
	UnlockModeTPMOnly = "tpm_only" // TPM2 alone, while Secure Boot is unchanged
)

// ValidUnlockMode reports whether mode is a known unlock mode.
func ValidUnlockMode(mode string) bool {
	return mode == UnlockModeTPMPIN || mode == UnlockModeTPMOnly
}
