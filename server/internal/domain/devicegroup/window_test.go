package devicegroup

import (
	"slices"
	"strings"
	"testing"
)

func TestValidateWindow(t *testing.T) {
	w := NormalizeWindow(Window{Days: []int{5, 1, 3}, StartMinute: 1320, DurationMinutes: 120, Timezone: "Europe/Berlin"})
	if !slices.Equal(w.Days, []int{1, 3, 5}) {
		t.Fatalf("days not sorted: %v", w.Days)
	}
	if err := ValidateWindow(w); err != nil {
		t.Fatalf("valid window refused: %v", err)
	}
	for _, zone := range []string{"Mars/Olympus_Mons", "Local", "Europe/Berlinx"} {
		bad := w
		bad.Timezone = zone
		if err := ValidateWindow(bad); err == nil || !strings.Contains(err.Error(), "timezone") {
			t.Errorf("timezone %q: got %v", zone, err)
		}
	}
	bad := w
	bad.DurationMinutes = 1441
	if err := ValidateWindow(bad); err == nil || !strings.Contains(err.Error(), "duration_minutes") {
		t.Errorf("range not checked: %v", err)
	}
	dup := NormalizeWindow(Window{Days: []int{2, 2}, StartMinute: 0, DurationMinutes: 60, Timezone: "UTC"})
	if err := ValidateWindow(dup); err == nil {
		t.Error("duplicate days accepted")
	}
}

func TestWindowSummaryAndUnion(t *testing.T) {
	night := Window{Days: []int{1, 2, 3, 4, 5}, StartMinute: 1320, DurationMinutes: 120, Timezone: "Europe/Berlin"}
	if got := WindowSummary(night); got != "1,2,3,4,5 22:00+120m Europe/Berlin" {
		t.Fatalf("summary %q", got)
	}
	weekend := Window{Days: []int{6, 7}, StartMinute: 0, DurationMinutes: 1440, Timezone: "UTC"}
	got := UnionWindows([]Window{weekend, night, night})
	if len(got) != 2 || WindowSummary(got[0]) != WindowSummary(night) || WindowSummary(got[1]) != WindowSummary(weekend) {
		t.Fatalf("union %+v", got)
	}
	if got := UnionWindows(nil); len(got) != 0 {
		t.Fatalf("union of none: %+v", got)
	}
}
