package app

import "time"

// SetTimeout shortens the bound of one import for tests of a source that does not answer.
func (r *ReleaseImports) SetTimeout(d time.Duration) { r.timeout = d }
