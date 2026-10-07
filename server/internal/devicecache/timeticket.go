package devicecache

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/valkey-io/valkey-go"
)

func ticketKey(org uuid.UUID) string { return "tt:" + org.String() }

// PutTimeTicket sets tt:<organization_id> to the newest signed time ticket of the organization (plan M4c decision
// 14).
func (c *Cache) PutTimeTicket(ctx context.Context, org uuid.UUID, envelope []byte) error {
	if err := c.c.Do(ctx, c.c.B().Set().Key(ticketKey(org)).Value(string(envelope)).Build()).Error(); err != nil {
		return fmt.Errorf("devicecache: put time ticket: %w", err)
	}
	return nil
}

// TimeTicket returns tt:<organization_id>; nil when there is none yet.
func (c *Cache) TimeTicket(ctx context.Context, org uuid.UUID) ([]byte, error) {
	s, err := c.c.Do(ctx, c.c.B().Get().Key(ticketKey(org)).Build()).ToString()
	if valkey.IsValkeyNil(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("devicecache: time ticket: %w", err)
	}
	return []byte(s), nil
}
