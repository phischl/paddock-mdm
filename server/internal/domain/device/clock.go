package device

import "time"

// Clock drift thresholds (plan M8b decision 13). Between the two the state does not change, so a clock that hovers
// around one threshold does not open and close episodes on every check-in.
const (
	// DriftThreshold raises a drift episode when |offset| exceeds it.
	DriftThreshold = 60 * time.Second
	// DriftClearThreshold ends a drift episode when |offset| is at most this.
	DriftClearThreshold = 30 * time.Second
)

// DriftState decides the transition of a device's clock drift episode for a measured offset (server time minus
// device time). drifting tells whether an episode is open. At most one of raise and clear is true.
func DriftState(offset time.Duration, drifting bool) (raise, clear bool) {
	if offset < 0 {
		offset = -offset
	}
	if drifting {
		return false, offset <= DriftClearThreshold
	}
	return offset > DriftThreshold, false
}
