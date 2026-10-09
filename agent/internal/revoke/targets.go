package revoke

import (
	"context"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/luks"
)

// CrypttabFile lists the encrypted volumes of the device besides the root volume (plan M4c.1 decision 1).
const CrypttabFile = luks.CrypttabFile

// SelectWithin bounds the classification of the crypttab entries (cryptsetup isLuks, luksUUID): a hung device must
// not keep the root volume from being erased (plan M4c.1, review round 1). Entries not classified in time are
// unresolved.
const SelectWithin = time.Minute

// Targets are the LUKS volumes of the device: every other LUKS volume of /etc/crypttab first, the root volume last
// (plan M4c.1 decision 1). UUIDs holds the LUKS UUID of a device in Devices as far as cryptsetup reported it; a Lock
// erases a volume other than the root volume only if its UUID is one the token lists (PDK-009). Shared lists the
// devices in Devices whose UUID another volume or the root volume has (a cloned header): a Destroy erases them, a Lock
// never, as their header cannot be escrowed (review round 2). Unresolved lists the crypttab sources that could not be
// erased with certainty; they are reported in the confirmation, do not stop the erasure of the others (decision 3)
// and make it incomplete.
// RootUnknown is set when the root volume's UUID could not be read: a clone of it cannot be recognized, so a Lock
// erases the root volume only (review round 3); a Destroy is not affected.
type Targets struct {
	Devices     []string
	UUIDs       map[string]string
	Shared      []string
	Unresolved  []string
	RootUnknown bool
}

// crypttabTargets reads /etc/crypttab below root through the volume selection the luks reconciler escrows with
// (luks.ReadCrypttab). Without the file the root volume is the only target; an unreadable file is reported as
// unresolved, and the root volume is still erased.
func crypttabTargets(ctx context.Context, t luks.Tools, root, rootDevice string) Targets {
	return targetsOf(luks.ReadCrypttab(ctx, t, root, rootDevice, SelectWithin))
}

// targetsOf orders the volumes of /etc/crypttab as targets: the other volumes in crypttab order, the root last.
func targetsOf(c luks.Crypttab) Targets {
	tg := Targets{Unresolved: c.Unresolved, RootUnknown: c.RootUUID == ""}
	for _, v := range c.Volumes {
		tg.Devices = append(tg.Devices, v.Header)
		if v.Shared {
			tg.Shared = append(tg.Shared, v.Header)
		}
		if v.UUID != "" {
			if tg.UUIDs == nil {
				tg.UUIDs = map[string]string{}
			}
			tg.UUIDs[v.Header] = v.UUID
		}
	}
	tg.Devices = append(tg.Devices, c.Root)
	return tg
}
