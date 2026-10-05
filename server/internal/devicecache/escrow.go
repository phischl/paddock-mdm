package devicecache

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/valkey-io/valkey-go"
)

// EscrowTTL is how long the storage status of an escrow upload stays readable (plan M4a decision 12).
const EscrowTTL = 24 * time.Hour

func escrowKey(id uuid.UUID) string { return "esc:" + id.String() }

// PutEscrowStatus sets esc:<escrow_id> to "<device_id>:<status>" for EscrowTTL.
func (c *Cache) PutEscrowStatus(ctx context.Context, id, device uuid.UUID, status string) error {
	err := c.c.Do(ctx, c.c.B().Set().Key(escrowKey(id)).Value(device.String()+":"+status).Ex(EscrowTTL).Build()).Error()
	if err != nil {
		return fmt.Errorf("devicecache: escrow status: %w", err)
	}
	return nil
}

// EscrowStatus reads esc:<escrow_id>; ok is false while the worker has not processed the upload.
func (c *Cache) EscrowStatus(ctx context.Context, id uuid.UUID) (device uuid.UUID, status string, ok bool, err error) {
	v, err := c.c.Do(ctx, c.c.B().Get().Key(escrowKey(id)).Build()).ToString()
	if valkey.IsValkeyNil(err) {
		return uuid.Nil, "", false, nil
	}
	if err != nil {
		return uuid.Nil, "", false, fmt.Errorf("devicecache: escrow status: %w", err)
	}
	dev, status, found := strings.Cut(v, ":")
	if device, err = uuid.Parse(dev); err != nil || !found {
		return uuid.Nil, "", false, fmt.Errorf("devicecache: corrupt escrow status of %s", id)
	}
	return device, status, true, nil
}
