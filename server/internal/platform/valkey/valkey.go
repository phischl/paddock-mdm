// Package valkey opens the Valkey client of the device control plane (ADR 0003). Valkey is a cache and
// coordination store, never a source of truth; only core commands are used.
package valkey

import (
	"context"
	"fmt"
	"time"

	"github.com/valkey-io/valkey-go"
)

// Config locates Valkey.
type Config struct {
	Addr     string // host:port
	Password string
}

// New connects to Valkey. Client-side caching is off: every read must see the latest write of another role.
func New(cfg Config) (valkey.Client, error) {
	c, err := valkey.NewClient(valkey.ClientOption{
		InitAddress:      []string{cfg.Addr},
		Password:         cfg.Password,
		DisableCache:     true,
		ConnWriteTimeout: 5 * time.Second,
		SelectDB:         0,
	})
	if err != nil {
		return nil, fmt.Errorf("valkey: connect %s: %w", cfg.Addr, err)
	}
	return c, nil
}

// Ping checks connectivity (readiness).
func Ping(ctx context.Context, c valkey.Client) error {
	return c.Do(ctx, c.B().Ping().Build()).Error()
}
