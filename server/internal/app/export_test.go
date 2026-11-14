package app

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/patchsla"
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

// SetIndexDays replaces the audit index retention, for tests of a retention below the minimum.
func (r *Retention) SetIndexDays(n int) { r.indexDays = n }

// KeptByIndex is keptByIndex, for tests of the month start, the margin and the youngest row.
var KeptByIndex = keptByIndex

// SetStoreTimeouts shortens the bounds of an upload's object store write and a publish's checksum verification for
// tests of a store that does not answer.
func (a *AgentReleases) SetStoreTimeouts(store, verify time.Duration) {
	a.storeTimeout, a.verifyTimeout = store, verify
}

// ForeignNotFound exposes the mapping of a destination foreign key violation to not_found.
var ForeignNotFound = foreignNotFound

// SetClock replaces the clock of the patch compliance report.
func (p *PatchCompliance) SetClock(now func() time.Time) { p.now = now }

// CountLoads counts the findings loads of the patch SLA summary; the returned function reads the count.
func (s *VulnerabilitySLASummary) CountLoads() func() int {
	n := 0
	load := s.load
	s.load = func(ctx context.Context, q *pgstore.Queries, group uuid.NullUUID, now time.Time) (patchsla.Input, error) {
		n++
		return load(ctx, q, group, now)
	}
	return func() int { return n }
}
