package devicecache

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// deleteChunk bounds the keys of one DEL, so a large organization does not block Valkey with one command.
const deleteChunk = 500

// OffboardDevice is a device of an organization being deleted with its identity keys. Offboarded marks a device that
// has an offboarded_device record: it may still contact the server to fetch its uninstall (plan M17 decision 15).
type OffboardDevice struct {
	ID         uuid.UUID
	KeyIDs     []string
	Offboarded bool
}

// OffboardOrgKeys are the identifiers of the organization's cached keys that no device row names: the SHA-256 of
// every enrollment token secret and every escrow id. The deletion reads them before the database step removes the rows.
type OffboardOrgKeys struct {
	TokenHashes [][]byte
	EscrowIDs   []uuid.UUID
}

// DeleteOrganization deletes the device keys of an organization that is being deleted (plan M17 decision 13,
// amendment l points 2 and 3) and returns how many keys existed:
//   - of every device bp:, hb:, au: and enr: (an enrollment request id is the id of the device it created);
//   - the organization's et: and esc: from refs;
//   - of a device that is not offboarded also cmd:, seq:, sd: and dk: of its keys;
//   - the organization's tt:.
//
// An offboarded device keeps dk: (rewritten to status offboarded by the devices step), cmd: with its uninstall, and
// seq: and sd:, which the gateway's request check needs; the worker deletes them on its agent.uninstalled or at the
// 365-day purge. The worker may only delete bp: and tt: (its delete-only selector, M17 amendment k addendum point 2):
// Valkey allows a DEL only when the root permissions or one selector cover every key of it, and that selector grants
// neither UNLINK nor scripts, so those keys go in plain DEL calls of their own.
func (c *Cache) DeleteOrganization(ctx context.Context, org uuid.UUID, devices []OffboardDevice, refs OffboardOrgKeys) (int64, error) {
	owned := make([]string, 0, 7*len(devices)+len(refs.TokenHashes)+len(refs.EscrowIDs))
	deleteOnly := make([]string, 0, len(devices)+1)
	for _, d := range devices {
		owned = append(owned, heartbeatKey(d.ID), updateRequestKey(d.ID), enrollmentKey(d.ID))
		deleteOnly = append(deleteOnly, bundleKey(d.ID))
		if d.Offboarded {
			continue
		}
		owned = append(owned, commandsKey(d.ID), seqKey(d.ID), deliveredKey(d.ID))
		for _, k := range d.KeyIDs {
			owned = append(owned, deviceKeyKey(k))
		}
	}
	for _, h := range refs.TokenHashes {
		owned = append(owned, tokenKey(h))
	}
	for _, id := range refs.EscrowIDs {
		owned = append(owned, escrowKey(id))
	}
	deleteOnly = append(deleteOnly, ticketKey(org))
	var total int64
	for _, keys := range [][]string{owned, deleteOnly} {
		for start := 0; start < len(keys); start += deleteChunk {
			n, err := c.c.Do(ctx, c.c.B().Del().Key(keys[start:min(start+deleteChunk, len(keys))]...).Build()).AsInt64()
			if err != nil {
				return total, fmt.Errorf("delete the device keys of organization %s: %w", org, err)
			}
			total += n
		}
	}
	return total, nil
}

// OffboardedKey is an identity key of an offboarded device.
type OffboardedKey struct {
	KeyID     string
	PublicKey []byte // SubjectPublicKeyInfo DER
}

// OffboardedCommand is one signed command an offboarded device keeps in cmd:.
type OffboardedCommand struct {
	ID      uuid.UUID
	Command Command
}

// OffboardedDevice is what the gateway needs to serve a device of a deleted organization its last commands (plan M17
// decision 15, amendment n): its keys, cached with status offboarded, and the signed disarm of the dead man's switch
// and uninstall.
type OffboardedDevice struct {
	ID             uuid.UUID
	OrganizationID uuid.UUID
	Keys           []OffboardedKey
	Commands       []OffboardedCommand
}

// PutOffboardedDevice adds the device's commands to cmd:<device> and caches every key of the device with status
// offboarded; a missing seq:<device> is restored from lastSeq (PutDeviceKey). It never removes a field of cmd:
// (amendment n point 2): a pending disarm already there stays. The commands go first, so a check-in that already sees
// the offboarded key finds them.
func (c *Cache) PutOffboardedDevice(ctx context.Context, d OffboardedDevice, lastSeq int64) error {
	for _, cmd := range d.Commands {
		if err := c.PutCommand(ctx, d.ID, cmd.ID, cmd.Command); err != nil {
			return fmt.Errorf("devicecache: put the commands of offboarded device %s: %w", d.ID, err)
		}
	}
	for _, k := range d.Keys {
		if err := c.PutDeviceKey(ctx, k.KeyID, DeviceKey{DeviceID: d.ID, OrganizationID: d.OrganizationID, Status: KeyOffboarded,
			PublicKey: k.PublicKey}, lastSeq); err != nil {
			return err
		}
	}
	return nil
}

// DeleteOffboardedDevice deletes what an offboarded device kept (amendment l point 3): dk: of its keys, cmd:, seq:
// and sd:. Its nonce: keys are outside the worker's ACL and expire within NonceTTL (amendment l point 2).
func (c *Cache) DeleteOffboardedDevice(ctx context.Context, device uuid.UUID, keyIDs []string) error {
	keys := []string{commandsKey(device), seqKey(device), deliveredKey(device)}
	for _, k := range keyIDs {
		keys = append(keys, deviceKeyKey(k))
	}
	if err := c.c.Do(ctx, c.c.B().Del().Key(keys...).Build()).Error(); err != nil {
		return fmt.Errorf("devicecache: delete the keys of offboarded device %s: %w", device, err)
	}
	return nil
}
