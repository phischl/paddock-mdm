package outbox

import "time"

// SetAfterConfirm installs the crash simulation hook.
func (r *Relay) SetAfterConfirm(fn func() error) { r.afterConfirm = fn }

// SetBatchSize changes the batch size.
func (r *Relay) SetBatchSize(n int32) { r.batchSize = n }

// SetClock replaces time.Now of the reaper.
func (rp *Reaper) SetClock(now func() time.Time) { rp.now = now }
