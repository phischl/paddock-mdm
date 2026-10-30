package app

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// SetTimeout shortens the bound of one import for tests of a source that does not answer.
func (r *ReleaseImports) SetTimeout(d time.Duration) { r.timeout = d }

// SetCountBudget shortens the bound of the identity-provider session count for tests of a count that does not answer.
func (s *Sessions) SetCountBudget(d time.Duration) { s.countBudget = d }

// SetBudget shortens the bound of one retention pass for tests of a backlog larger than one pass.
func (r *Retention) SetBudget(d time.Duration) { r.budget = d }

// SetLockTimeout shortens the row-lock wait of one batch for tests of a blocked batch.
func (r *Retention) SetLockTimeout(d time.Duration) { r.lockTimeout = d }

// SetHostUsers replaces the cross-organization check of a Fleet host's other devices, for tests of a failing check.
func (r *Retention) SetHostUsers(f func(ctx context.Context, retiredDevice uuid.UUID, host string) (string, error)) {
	r.hosts = hostUsersFunc(f)
}

type hostUsersFunc func(ctx context.Context, retiredDevice uuid.UUID, host string) (string, error)

func (f hostUsersFunc) FleetHostInUse(ctx context.Context, retiredDevice uuid.UUID, host string) (string, error) {
	return f(ctx, retiredDevice, host)
}

// SetPage shortens the page of the retired inventory pass for tests with more devices than one page.
func (r *Retention) SetPage(n int32) { r.page = n }

// SetHoldNotice shortens the unchanged rounds of a kept Fleet host before its notice, for tests of the notice.
func (r *Retention) SetHoldNotice(n int32) { r.holdNotice = n }

// SetClock replaces time.Now of the read-access recording, for tests of consecutive windows.
func (r *ReadAudit) SetClock(now func() time.Time) { r.now = now }
