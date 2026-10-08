package updates

import "time"

// Staleness levels of a device (plan M5b decision 10); the value is the kind of its open alert.
const (
	StaleNone     = ""
	StaleWarning  = "stale_warning"
	StaleCritical = "stale_critical"
)

// StaleLevel returns the staleness level of a device whose last contact was at last: critical from criticalH, warning
// from warningH units of silence. unit is an hour (minute in development installations, gate U4).
func StaleLevel(last, now time.Time, warningH, criticalH int, unit time.Duration) string {
	silent := now.Sub(last)
	switch {
	case silent >= time.Duration(criticalH)*unit:
		return StaleCritical
	case silent >= time.Duration(warningH)*unit:
		return StaleWarning
	}
	return StaleNone
}
