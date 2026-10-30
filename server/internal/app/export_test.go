package app

import "time"

// SetTimeout shortens the bound of one import for tests of a source that does not answer.
func (r *ReleaseImports) SetTimeout(d time.Duration) { r.timeout = d }

// SetCountBudget shortens the bound of the identity-provider session count for tests of a count that does not answer.
func (s *Sessions) SetCountBudget(d time.Duration) { s.countBudget = d }

// SetBudget shortens the bound of one retention pass for tests of a backlog larger than one pass.
func (r *Retention) SetBudget(d time.Duration) { r.budget = d }

// SetLockTimeout shortens the row-lock wait of one batch for tests of a blocked batch.
func (r *Retention) SetLockTimeout(d time.Duration) { r.lockTimeout = d }
