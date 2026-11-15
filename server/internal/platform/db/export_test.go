package db

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// NewOrgPoolWithClock is NewOrgPool with the status cache's monotonic clock injected.
func NewOrgPoolWithClock(ctx context.Context, dsn string, o Options, since func() time.Duration) (*OrgPool, error) {
	return newOrgPool(ctx, dsn, o, since)
}

// StopStatusPoller stops p's status cache poller, so only RefreshOrganizationStatus changes the cache.
func StopStatusPoller(p *OrgPool) { p.gate.close() }

// SetBeforeGate makes fn run at the start of every gate pass of p, before the status cache is consulted. Set it
// before p is used concurrently.
func SetBeforeGate(p *OrgPool, fn func(org uuid.UUID)) { p.beforeGate = fn }
