package bundle

import (
	"strings"
	"testing"
)

func TestValidateSoftwareWindow(t *testing.T) {
	ok := SoftwareWindow{Days: []int{1, 2, 3, 4, 5}, StartMinute: 1320, DurationMinutes: 120, Timezone: "Europe/Berlin"}
	if err := ValidateSoftwareWindow(ok); err != nil {
		t.Fatalf("valid window refused: %v", err)
	}
	for _, w := range []SoftwareWindow{
		{Days: []int{7}, StartMinute: 0, DurationMinutes: 30, Timezone: "UTC"},
		{Days: []int{1, 2, 3, 4, 5, 6, 7}, StartMinute: 1439, DurationMinutes: 1440, Timezone: "America/Argentina/Buenos_Aires"},
		{Days: []int{6}, StartMinute: 60, DurationMinutes: 60, Timezone: "Etc/GMT+5"},
	} {
		if err := ValidateSoftwareWindow(w); err != nil {
			t.Errorf("boundary window %+v refused: %v", w, err)
		}
	}
	for name, tc := range map[string]struct {
		mutate func(*SoftwareWindow)
		want   string
	}{
		"no days":        {func(w *SoftwareWindow) { w.Days = nil }, "days"},
		"day 0":          {func(w *SoftwareWindow) { w.Days = []int{0, 1} }, "days"},
		"day 8":          {func(w *SoftwareWindow) { w.Days = []int{8} }, "days"},
		"duplicate day":  {func(w *SoftwareWindow) { w.Days = []int{2, 2} }, "days"},
		"unsorted days":  {func(w *SoftwareWindow) { w.Days = []int{3, 1} }, "days"},
		"eight days":     {func(w *SoftwareWindow) { w.Days = []int{1, 2, 3, 4, 5, 6, 7, 7} }, "days"},
		"negative start": {func(w *SoftwareWindow) { w.StartMinute = -1 }, "start_minute"},
		"start 1440":     {func(w *SoftwareWindow) { w.StartMinute = 1440 }, "start_minute"},
		"duration 29":    {func(w *SoftwareWindow) { w.DurationMinutes = 29 }, "duration_minutes"},
		"duration 1441":  {func(w *SoftwareWindow) { w.DurationMinutes = 1441 }, "duration_minutes"},
		"empty zone":     {func(w *SoftwareWindow) { w.Timezone = "" }, "timezone"},
		"dot zone":       {func(w *SoftwareWindow) { w.Timezone = "../etc/passwd" }, "timezone"},
		"space zone":     {func(w *SoftwareWindow) { w.Timezone = "Europe/ Berlin" }, "timezone"},
		"long zone":      {func(w *SoftwareWindow) { w.Timezone = "A" + strings.Repeat("b", 64) }, "timezone"},
		"double slash":   {func(w *SoftwareWindow) { w.Timezone = "Europe//Berlin" }, "timezone"},
	} {
		w := ok
		w.Days = append([]int(nil), ok.Days...)
		tc.mutate(&w)
		err := ValidateSoftwareWindow(w)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want an error naming %s", name, err, tc.want)
		}
	}
}

func TestValidateSoftwareWindows(t *testing.T) {
	w := SoftwareWindow{Days: []int{1}, StartMinute: 0, DurationMinutes: 60, Timezone: "UTC"}
	if err := ValidateSoftware(SoftwareSpec{Windows: []SoftwareWindow{w, w}}); err != nil {
		t.Fatalf("two windows refused: %v", err)
	}
	bad := w
	bad.DurationMinutes = 10
	if err := ValidateSoftware(SoftwareSpec{Windows: []SoftwareWindow{w, bad}}); err == nil || !strings.Contains(err.Error(), "software window 1") {
		t.Fatalf("invalid window accepted or unnamed: %v", err)
	}
	many := make([]SoftwareWindow, MaxSoftwareWindows+1)
	for i := range many {
		many[i] = w
	}
	if err := ValidateSoftware(SoftwareSpec{Windows: many}); err == nil {
		t.Fatal("more than MaxSoftwareWindows windows accepted")
	}
}
