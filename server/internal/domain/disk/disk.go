// Package disk holds the disk encryption policy of devices (ADR 0038).
package disk

import "slices"

// Unlock modes of a disk encrypted by the Paddock autoinstall (ADR 0038 decision 1).
const (
	UnlockModeTPMPIN  = "tpm_pin"  // TPM2 + boot PIN, the default
	UnlockModeTPMOnly = "tpm_only" // TPM2 alone, while Secure Boot is unchanged
)

// ValidUnlockMode reports whether mode is a known unlock mode.
func ValidUnlockMode(mode string) bool {
	return mode == UnlockModeTPMPIN || mode == UnlockModeTPMOnly
}

// EffectiveUnlockMode is the unlock mode of a device (plan M8d decision 44): the stricter mode wins across its device
// groups — any group with tpm_pin makes it tpm_pin, else any group with tpm_only makes it tpm_only — and without an
// override the organization's mode applies.
func EffectiveUnlockMode(org string, groups []string) string {
	switch {
	case slices.Contains(groups, UnlockModeTPMPIN):
		return UnlockModeTPMPIN
	case slices.Contains(groups, UnlockModeTPMOnly):
		return UnlockModeTPMOnly
	case ValidUnlockMode(org):
		return org
	}
	return UnlockModeTPMPIN
}
