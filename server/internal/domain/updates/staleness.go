package updates

import (
	"fmt"
	"time"
)

// Staleness levels of a device (plan M5b decision 10); the value is the kind of its open alert.
const (
	StaleNone     = ""
	StaleWarning  = "stale_warning"
	StaleCritical = "stale_critical"
)

// Sources of the thresholds a device is evaluated with (plan M8d decision 12).
const (
	SourceOrganization = "organization"
	SourceDeviceGroup  = "device_group"
)

// ValidateThresholds checks a pair of staleness thresholds (hours) against the limits; prefix names the fields in
// the message ("staleness_" for the organization's settings, "staleness." for a device group's override).
func ValidateThresholds(prefix string, warningH, criticalH int) error {
	if warningH < MinStalenessWarningH || warningH > MaxStalenessWarningH {
		return fmt.Errorf("%swarning_h must be between %d and %d", prefix, MinStalenessWarningH, MaxStalenessWarningH)
	}
	if criticalH <= warningH || criticalH > MaxStalenessCriticalH {
		return fmt.Errorf("%scritical_h must be above %swarning_h and at most %d", prefix, prefix, MaxStalenessCriticalH)
	}
	return nil
}

// Thresholds returns the staleness thresholds of a device (plan M8d decision 12): the most lenient override of its
// device groups when one is set (groupWarningH and groupCriticalH are the maxima over its groups with an override,
// 0 without one; an override is at least one hour), else the organization's.
func Thresholds(groupWarningH, groupCriticalH, orgWarningH, orgCriticalH int) (warningH, criticalH int, source string) {
	if groupWarningH > 0 && groupCriticalH > 0 {
		return groupWarningH, groupCriticalH, SourceDeviceGroup
	}
	return orgWarningH, orgCriticalH, SourceOrganization
}

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
