package app

import "time"

// SetTimeout shortens the bound of one import for tests of a source that does not answer.
func (r *ReleaseImports) SetTimeout(d time.Duration) { r.timeout = d }

// SetCountBudget shortens the bound of the identity-provider session count for tests of a count that does not answer.
func (s *Sessions) SetCountBudget(d time.Duration) { s.countBudget = d }

// SetStoreTimeouts shortens the bounds of an upload's object store write and a publish's checksum verification for
// tests of a store that does not answer.
func (a *AgentReleases) SetStoreTimeouts(store, verify time.Duration) {
	a.storeTimeout, a.verifyTimeout = store, verify
}
