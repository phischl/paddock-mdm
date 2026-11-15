package devicecache

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// deleteChunk bounds the keys of one DEL, so a large organization does not block Valkey with one command.
const deleteChunk = 500

// DeleteOrganization deletes the device keys of an organization that is being deleted (plan M17 decision 13): cmd:,
// seq:, sd:, bp:, hb: and au: of every device, dk: of every identity key and the organization's tt:. It returns how
// many keys existed. The worker may only delete bp: and tt: (its delete-only selector, M17 amendment k addendum point
// 2), and Valkey allows a DEL only when the root permissions or one selector cover every key of it, so those keys go
// in DEL calls of their own.
func (c *Cache) DeleteOrganization(ctx context.Context, org uuid.UUID, devices []uuid.UUID, keyIDs []string) (int64, error) {
	owned := make([]string, 0, 5*len(devices)+len(keyIDs))
	deleteOnly := make([]string, 0, len(devices)+1)
	for _, d := range devices {
		owned = append(owned, commandsKey(d), seqKey(d), deliveredKey(d), heartbeatKey(d), updateRequestKey(d))
		deleteOnly = append(deleteOnly, bundleKey(d))
	}
	for _, k := range keyIDs {
		owned = append(owned, deviceKeyKey(k))
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
