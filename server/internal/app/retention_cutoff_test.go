package app_test

import (
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/app"
)

// TestKeptByIndex (ADR 0032 amendment 2026-10-31): the cutoff of a store kept by the audit index is the start of the
// UTC month containing now − the index days − a margin of 2 days, and never later than an hour before now.
func TestKeptByIndex(t *testing.T) {
	day := 24 * time.Hour
	berlin := time.FixedZone("CET", 3600)
	for _, tc := range []struct {
		name      string
		now       time.Time
		indexDays int
		unit      time.Duration
		want      time.Time
	}{
		{"mid-month: the month start", time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC), 1, day,
			time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)},
		{"month boundary: the previous month's start", time.Date(2026, 3, 1, 0, 3, 0, 0, time.UTC), 1, day,
			time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)},
		{"now − index days in this month, the margin in the previous one", time.Date(2026, 3, 3, 12, 0, 0, 0, time.UTC), 1, day,
			time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)},
		{"now − index days − margin just in this month", time.Date(2026, 3, 4, 0, 0, 1, 0, time.UTC), 1, day,
			time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)},
		{"the month in UTC, not in the clock's zone", time.Date(2026, 3, 3, 0, 30, 0, 0, berlin), 0, day,
			time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)},
		{"days in seconds: the month start", time.Date(2026, 3, 1, 2, 0, 0, 0, time.UTC), 400, time.Second,
			time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)},
		{"days in seconds: never within the last hour", time.Date(2026, 3, 1, 0, 30, 0, 0, time.UTC), 400, time.Second,
			time.Date(2026, 2, 28, 23, 30, 0, 0, time.UTC)},
	} {
		if got := app.KeptByIndex(tc.now, tc.indexDays, tc.unit); !got.Equal(tc.want) {
			t.Errorf("%s: cutoff %v, want %v", tc.name, got, tc.want)
		}
	}
}
