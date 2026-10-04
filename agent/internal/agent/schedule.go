package agent

import "time"

// Check-in timing (plan M2b decision 8).
const (
	DefaultCheckin  = 300 * time.Second
	TriggerMaxDelay = 15 * time.Second
	TriggerMinGap   = 60 * time.Second
)

// failureBackoff is the wait after the n-th consecutive failed check-in (the last value repeats).
var failureBackoff = []time.Duration{
	30 * time.Second, 60 * time.Second, 2 * time.Minute, 5 * time.Minute, 10 * time.Minute, 30 * time.Minute,
}

// jitter spreads d by ±20 %; r is uniform in [0, 1).
func jitter(d time.Duration, r float64) time.Duration {
	return time.Duration(float64(d) * (0.8 + 0.4*r))
}

// afterSuccess is the wait until the next check-in: next_checkin_s from the server (already jittered by the server),
// or the jittered default when the server sent none.
func afterSuccess(nextCheckinS int, r float64) time.Duration {
	if nextCheckinS <= 0 {
		return jitter(DefaultCheckin, r)
	}
	return time.Duration(nextCheckinS) * time.Second
}

// afterFailure is the jittered back-off after the n-th consecutive failure (n ≥ 1), at least retryAfter.
func afterFailure(n int, r float64, retryAfter time.Duration) time.Duration {
	d := jitter(failureBackoff[min(max(n, 1), len(failureBackoff))-1], r)
	return max(d, retryAfter)
}

// triggered is the time of the check-in caused by an event (network up, resume): 0–15 s from now, but at most one
// check-in per minute.
func triggered(now, lastAttempt time.Time, r float64) time.Time {
	at := now.Add(time.Duration(r * float64(TriggerMaxDelay)))
	if earliest := lastAttempt.Add(TriggerMinGap); at.Before(earliest) {
		return earliest
	}
	return at
}
