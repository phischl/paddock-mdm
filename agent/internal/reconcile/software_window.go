package reconcile

import (
	"slices"
	"time"

	"github.com/phischl/paddock-mdm/pkg/bundle"
)

// windowState is what a pass found of the maintenance windows (plan M13c decision 6): whether the policy's package
// operations wait for a window, and the timezones the device does not know, evaluated in UTC instead (§3.8 L3).
type windowState struct {
	outside      bool
	unknownZones []string
}

// evaluateWindows reports whether now is outside every window of the section. No window means no restriction. A zone
// the device cannot load falls back to UTC: the window still opens once a day in UTC, so the device never waits for
// good (design contract 8).
func evaluateWindows(windows []bundle.SoftwareWindow, now time.Time) windowState {
	if len(windows) == 0 {
		return windowState{}
	}
	st := windowState{outside: true}
	for _, w := range windows {
		loc, err := time.LoadLocation(w.Timezone)
		if err != nil {
			loc = time.UTC
			if !slices.Contains(st.unknownZones, w.Timezone) {
				st.unknownZones = append(st.unknownZones, w.Timezone)
			}
		}
		if windowOpen(w, loc, now) {
			st.outside = false
		}
	}
	return st
}

// windowOpen reports whether w is open at now in loc. A window opens StartMinute minutes after local midnight of each
// of its days and stays open DurationMinutes of elapsed time, so it may reach into the next day; the opening of the
// previous day is checked for that. On a day with a DST change the local start is the zone's: a start inside the
// skipped hour moves forward by the gap, and the window still opens that day; one inside the repeated hour opens once,
// at the zone's second occurrence of that time.
func windowOpen(w bundle.SoftwareWindow, loc *time.Location, now time.Time) bool {
	local := now.In(loc)
	for _, back := range []int{0, 1} {
		y, m, d := local.Date()
		// Noon is never inside a DST gap, so the weekday of the date is safe to read there.
		day := time.Date(y, m, d-back, 12, 0, 0, 0, loc)
		if !slices.Contains(w.Days, isoWeekday(day.Weekday())) {
			continue
		}
		dy, dm, dd := day.Date()
		start := time.Date(dy, dm, dd, 0, w.StartMinute, 0, 0, loc)
		if !now.Before(start) && now.Before(start.Add(time.Duration(w.DurationMinutes)*time.Minute)) {
			return true
		}
	}
	return false
}

// isoWeekday is the ISO number of a weekday: 1 = Monday to 7 = Sunday.
func isoWeekday(d time.Weekday) int {
	if d == time.Sunday {
		return 7
	}
	return int(d)
}
