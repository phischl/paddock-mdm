package bundle

import (
	"fmt"
	"regexp"
	"strings"
)

// SoftwareWindow is a maintenance window of a device group (plan M13c decisions 4 and 5): on each of Days (ISO
// weekdays, 1 = Monday, ascending) it opens StartMinute minutes after local midnight in Timezone and stays open for
// DurationMinutes, so it may run past midnight into the next day.
type SoftwareWindow struct {
	Days            []int  `json:"days"`
	StartMinute     int    `json:"start_minute"`
	DurationMinutes int    `json:"duration_minutes"`
	Timezone        string `json:"timezone"`
}

// Limits of a maintenance window (plan M13c decision 4).
const (
	MaxWindowStartMinute     = 1439
	MinWindowDurationMinutes = 30
	MaxWindowDurationMinutes = 1440
	// MaxSoftwareWindows bounds the windows of a software section: one per device group of the device, identical ones
	// once.
	MaxSoftwareWindows = 64
)

// windowTimezone is the form of an IANA timezone name (the migration's check). Whether the name is loadable is the
// server's check (time.LoadLocation); a device without the zone falls back to UTC instead of refusing the bundle.
var windowTimezone = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+/-]{0,63}$`)

// ValidWindowTimezone reports whether name has the form of an IANA timezone name.
func ValidWindowTimezone(name string) bool {
	return windowTimezone.MatchString(name) && !strings.Contains(name, "//") && !strings.HasSuffix(name, "/")
}

// ValidateSoftwareWindow checks the ranges of a window: 1 to 7 distinct ascending ISO weekdays, a start of 0 to 1439
// minutes, a duration of 30 to 1440 minutes and a timezone name of the IANA form. The message names the field.
func ValidateSoftwareWindow(w SoftwareWindow) error {
	if len(w.Days) == 0 || len(w.Days) > 7 {
		return fmt.Errorf("days must list 1 to 7 weekdays")
	}
	for i, d := range w.Days {
		if d < 1 || d > 7 {
			return fmt.Errorf("days must be ISO weekdays from 1 (Monday) to 7 (Sunday)")
		}
		if i > 0 && w.Days[i-1] >= d {
			return fmt.Errorf("days must be distinct and ascending")
		}
	}
	if w.StartMinute < 0 || w.StartMinute > MaxWindowStartMinute {
		return fmt.Errorf("start_minute must be 0 to %d", MaxWindowStartMinute)
	}
	if w.DurationMinutes < MinWindowDurationMinutes || w.DurationMinutes > MaxWindowDurationMinutes {
		return fmt.Errorf("duration_minutes must be %d to %d", MinWindowDurationMinutes, MaxWindowDurationMinutes)
	}
	if !ValidWindowTimezone(w.Timezone) {
		return fmt.Errorf("timezone must be an IANA timezone name such as Europe/Berlin")
	}
	return nil
}
