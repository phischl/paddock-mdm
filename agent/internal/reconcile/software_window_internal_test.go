package reconcile

import (
	"slices"
	"testing"
	"time"

	// The zone database of the test binary, so that the DST cases do not depend on the host's tzdata.
	_ "time/tzdata"

	"github.com/phischl/paddock-mdm/pkg/bundle"
)

func mustZone(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

// TestWindowOpenAcrossMidnight: a window that starts late reaches into the next day, which need not be one of its days.
func TestWindowOpenAcrossMidnight(t *testing.T) {
	berlin := mustZone(t, "Europe/Berlin")
	w := bundle.SoftwareWindow{Days: []int{1}, StartMinute: 22 * 60, DurationMinutes: 180, Timezone: "Europe/Berlin"}
	for _, tc := range []struct {
		at   time.Time
		open bool
	}{
		{time.Date(2026, 11, 9, 21, 59, 0, 0, berlin), false}, // Monday
		{time.Date(2026, 11, 9, 22, 0, 0, 0, berlin), true},
		{time.Date(2026, 11, 9, 23, 59, 0, 0, berlin), true},
		{time.Date(2026, 11, 10, 0, 30, 0, 0, berlin), true}, // Tuesday, still Monday's window
		{time.Date(2026, 11, 10, 0, 59, 59, 0, berlin), true},
		{time.Date(2026, 11, 10, 1, 0, 0, 0, berlin), false},
		{time.Date(2026, 11, 10, 22, 30, 0, 0, berlin), false}, // Tuesday is not a day of the window
		{time.Date(2026, 11, 8, 23, 0, 0, 0, berlin), false},   // Sunday
	} {
		if got := windowOpen(w, berlin, tc.at); got != tc.open {
			t.Errorf("%s: open %v, want %v", tc.at, got, tc.open)
		}
	}
	// The same instant seen from another zone is the same answer: the window's own zone decides.
	if !windowOpen(w, berlin, time.Date(2026, 11, 9, 21, 30, 0, 0, time.UTC)) {
		t.Error("22:30 in Berlin given in UTC")
	}
	full := bundle.SoftwareWindow{Days: []int{7}, StartMinute: 0, DurationMinutes: 1440, Timezone: "UTC"}
	if !windowOpen(full, time.UTC, time.Date(2026, 11, 8, 23, 59, 0, 0, time.UTC)) || windowOpen(full, time.UTC, time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)) {
		t.Error("a whole-day window")
	}
}

// TestWindowOpenOnDSTDays (plan M13c §9): on every day of a year with DST changes, a daily window opens once and stays
// open for its duration of elapsed time: a start inside the skipped hour is not skipped, a start inside the repeated
// hour does not open twice.
func TestWindowOpenOnDSTDays(t *testing.T) {
	for _, zone := range []string{"Europe/Berlin", "America/New_York", "Australia/Sydney"} {
		loc := mustZone(t, zone)
		for _, start := range []int{0, 90, 150, 165, 1410} {
			w := bundle.SoftwareWindow{Days: []int{1, 2, 3, 4, 5, 6, 7}, StartMinute: start, DurationMinutes: 30, Timezone: zone}
			counts := map[string]int{}
			from := time.Date(2026, 1, 1, 0, 0, 0, 0, loc)
			for at := from; at.Year() == 2026; at = at.Add(time.Minute) {
				// Every start ends by local midnight, so an open minute belongs to the local day it is on.
				if windowOpen(w, loc, at) {
					counts[at.In(loc).Format(time.DateOnly)]++
				}
			}
			for d := from; d.Year() == 2026; d = d.AddDate(0, 0, 1) {
				key := d.Format(time.DateOnly)
				if counts[key] != 30 {
					t.Errorf("%s start %d: %s open %d minutes, want 30", zone, start, key, counts[key])
				}
			}
		}
	}
}

// TestWindowSpanningTheSpringForwardNight: a window of elapsed minutes that spans the skipped hour ends an hour later
// on the local clock.
func TestWindowSpanningTheSpringForwardNight(t *testing.T) {
	berlin := mustZone(t, "Europe/Berlin")
	w := bundle.SoftwareWindow{Days: []int{6}, StartMinute: 22 * 60, DurationMinutes: 360, Timezone: "Europe/Berlin"}
	if !windowOpen(w, berlin, time.Date(2026, 3, 29, 4, 30, 0, 0, berlin)) {
		t.Error("04:30 CEST is inside six hours from 22:00 CET")
	}
	if windowOpen(w, berlin, time.Date(2026, 3, 29, 5, 0, 0, 0, berlin)) {
		t.Error("05:00 CEST is six hours after 22:00 CET")
	}
}

// TestWholeDayWindowOnTheFallBackNight: a daily window of 1440 elapsed minutes from 00:00 ends at 23:00 on the day
// the clocks go back, an hour before the next day's window opens; the runbook names this hour.
func TestWholeDayWindowOnTheFallBackNight(t *testing.T) {
	berlin := mustZone(t, "Europe/Berlin")
	w := bundle.SoftwareWindow{Days: []int{1, 2, 3, 4, 5, 6, 7}, StartMinute: 0, DurationMinutes: 1440, Timezone: "Europe/Berlin"}
	for _, tc := range []struct {
		at   time.Time
		open bool
	}{
		{time.Date(2026, 10, 25, 22, 59, 0, 0, berlin), true},
		{time.Date(2026, 10, 25, 23, 0, 0, 0, berlin), false},
		{time.Date(2026, 10, 25, 23, 59, 0, 0, berlin), false},
		{time.Date(2026, 10, 26, 0, 0, 0, 0, berlin), true},
	} {
		if got := windowOpen(w, berlin, tc.at); got != tc.open {
			t.Errorf("%s: open %v, want %v", tc.at, got, tc.open)
		}
	}
}

// TestEvaluateWindows: no window restricts nothing; the union of windows is open when one of them is, adjacent windows
// join without a gap; an unknown zone falls back to UTC and is named once.
func TestEvaluateWindows(t *testing.T) {
	monday := func(h, m int) time.Time { return time.Date(2026, 11, 9, h, m, 0, 0, time.UTC) }
	if st := evaluateWindows(nil, monday(12, 0)); st.outside || st.unknownZones != nil {
		t.Fatalf("no windows %+v", st)
	}
	early := bundle.SoftwareWindow{Days: []int{1}, StartMinute: 20 * 60, DurationMinutes: 120, Timezone: "UTC"}
	late := bundle.SoftwareWindow{Days: []int{1}, StartMinute: 22 * 60, DurationMinutes: 120, Timezone: "UTC"}
	for _, tc := range []struct {
		at      time.Time
		outside bool
	}{
		{monday(19, 59), true}, {monday(20, 0), false}, {monday(21, 59), false}, {monday(22, 0), false},
		{monday(23, 59), false}, {monday(24, 0), true},
	} {
		if st := evaluateWindows([]bundle.SoftwareWindow{late, early}, tc.at); st.outside != tc.outside {
			t.Errorf("%s: outside %v, want %v", tc.at, st.outside, tc.outside)
		}
	}
	// Overlapping windows: the union, not the intersection.
	wide := bundle.SoftwareWindow{Days: []int{1}, StartMinute: 21 * 60, DurationMinutes: 30, Timezone: "Europe/Berlin"}
	if st := evaluateWindows([]bundle.SoftwareWindow{early, wide}, monday(20, 10)); st.outside {
		t.Error("inside one of two overlapping windows")
	}

	unknown := bundle.SoftwareWindow{Days: []int{1}, StartMinute: 12 * 60, DurationMinutes: 60, Timezone: "Mars/Olympus_Mons"}
	st := evaluateWindows([]bundle.SoftwareWindow{unknown, unknown}, monday(12, 30))
	if st.outside || !slices.Equal(st.unknownZones, []string{"Mars/Olympus_Mons"}) {
		t.Fatalf("unknown zone %+v", st)
	}
	if st := evaluateWindows([]bundle.SoftwareWindow{unknown}, monday(14, 0)); !st.outside {
		t.Fatal("the UTC fallback must still close")
	}
}
