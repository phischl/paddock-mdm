package revocation

import "encoding/json"

// Confirmation is the result paddock-revoke posts before its reboot (plan M4c decision 10, extended additively by
// plan M4c.1 decision 2): the sums over the reported volumes, each volume, and the crypttab entries it could not
// erase with certainty. A confirmation of M4c has no volumes. SkippedNotEscrowed are the volumes a Lock left alone
// because the token did not confirm their header escrow (PDK-009); they do not make the erasure incomplete.
type Confirmation struct {
	Erased             bool                 `json:"erased"`
	SlotsBefore        int                  `json:"slots_before"`
	SlotsAfter         int                  `json:"slots_after"`
	Volumes            []VolumeConfirmation `json:"volumes"`
	Unresolved         []string             `json:"unresolved"`
	SkippedNotEscrowed []SkippedVolume      `json:"skipped_not_escrowed"`
	// SharedUUID are the devices whose LUKS UUID another volume or the root volume has (PDK-009 review round 2); a
	// Destroy erases them, a Lock skips them. They do not make the erasure incomplete.
	SharedUUID []string `json:"shared_uuid"`
}

// VolumeConfirmation is the erasure of one LUKS volume of the device.
type VolumeConfirmation struct {
	Device      string `json:"device"`
	UUID        string `json:"uuid"`
	SlotsBefore int    `json:"slots_before"`
	SlotsAfter  int    `json:"slots_after"`
	Erased      bool   `json:"erased"`
}

// SkippedVolume is a volume a Lock did not erase.
type SkippedVolume struct {
	Device string `json:"device"`
	UUID   string `json:"uuid"`
}

// ParseConfirmation reads a device's confirmation; a malformed one yields the zero value, which is not erased.
func ParseConfirmation(raw []byte) Confirmation {
	var c Confirmation
	if json.Unmarshal(raw, &c) != nil {
		return Confirmation{}
	}
	return c
}

// AllErased reports whether the device erased every volume: the device says so, no volume it lists contradicts it by
// a keyslot left or a failed erasure, and no crypttab entry is unresolved (plan M4c.1 decision 2, review round 1).
func (c Confirmation) AllErased() bool {
	if !c.Erased || len(c.Unresolved) > 0 {
		return false
	}
	for _, v := range c.Volumes {
		if !v.Erased || v.SlotsAfter != 0 {
			return false
		}
	}
	return true
}
