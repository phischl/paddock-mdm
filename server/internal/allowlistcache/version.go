// Package allowlistcache propagates changes of the IP allow list between api replicas (plan M7a decision 19): a
// change counter in Valkey that every replica polls; the list itself is read from PostgreSQL.
package allowlistcache

import (
	"context"
	"fmt"

	"github.com/valkey-io/valkey-go"
)

const key = "ipal:ver"

// Version is the change counter of the IP allow list in Valkey under ipal:ver.
type Version struct{ c valkey.Client }

// NewVersion wraps a Valkey client.
func NewVersion(c valkey.Client) *Version { return &Version{c: c} }

// Bump raises the counter after a committed change.
func (v *Version) Bump(ctx context.Context) error {
	if err := v.c.Do(ctx, v.c.B().Incr().Key(key).Build()).Error(); err != nil {
		return fmt.Errorf("bump ip allow list version: %w", err)
	}
	return nil
}

// Get returns the counter; 0 when absent.
func (v *Version) Get(ctx context.Context) (int64, error) {
	n, err := v.c.Do(ctx, v.c.B().Get().Key(key).Build()).AsInt64()
	if valkey.IsValkeyNil(err) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read ip allow list version: %w", err)
	}
	return n, nil
}
