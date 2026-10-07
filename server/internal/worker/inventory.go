package worker

import (
	"context"
	"log/slog"
	"time"
)

// DefaultInventorySyncInterval is the period of the inventory rounds (plan M5a decision 6).
const DefaultInventorySyncInterval = 5 * time.Minute

// inventoryRetryInterval is how soon a failed settings round is repeated: Fleet may still be starting.
const inventoryRetryInterval = 15 * time.Second

// InventorySettings keeps the data minimization settings of the inventory system (fleet.Client).
type InventorySettings interface {
	// EnsureSettings resets drift and returns what it corrected.
	EnsureSettings(ctx context.Context) ([]string, error)
}

// Inventory runs the inventory rounds (plan M5a decisions 2 and 6).
type Inventory struct {
	settings InventorySettings
	every    time.Duration
	retry    time.Duration
}

// NewInventory creates the inventory rounds.
func NewInventory(settings InventorySettings, every time.Duration) *Inventory {
	return &Inventory{settings: settings, every: every, retry: inventoryRetryInterval}
}

// RunSettings checks the inventory system's settings at start and then every round until ctx ends; every replica
// does (idempotent). A failure is retried after inventoryRetryInterval.
func (i *Inventory) RunSettings(ctx context.Context) error {
	for {
		wait := i.every
		corrected, err := i.settings.EnsureSettings(ctx)
		switch {
		case err != nil && ctx.Err() == nil:
			slog.WarnContext(ctx, "checking the inventory settings failed", "retry_in", i.retry, "error", err)
			wait = i.retry
		case len(corrected) > 0:
			slog.WarnContext(ctx, "inventory settings drifted; reset", "corrected", corrected)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}
