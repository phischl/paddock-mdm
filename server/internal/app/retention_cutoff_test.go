package app_test

import (
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/app"
)

// TestKeptByIndex (ADR 0032 amendment 2026-10-31): the cutoff of a store kept by the audit index is the earlier of
// now − the store's days and the start of the UTC month containing now − the index days. With the store's days equal
// to the index days, as for every store today, the month start always wins; a store kept longer than the index would
// take its own period.
func TestKeptByIndex(t *testing.T) {
	day := 24 * time.Hour
	berlin := time.FixedZone("CET", 3600)
	for _, tc := range []struct {
		name                 string
		now                  time.Time
		storeDays, indexDays int
		want                 time.Time
	}{
		{"mid-month: the month start", time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC), 1, 1,
			time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)},
		{"month boundary: the previous month's start", time.Date(2026, 3, 1, 0, 3, 0, 0, time.UTC), 1, 1,
			time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)},
		{"the month in UTC, not in the clock's zone", time.Date(2026, 3, 1, 0, 30, 0, 0, berlin), 0, 0,
			time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)},
		{"a store kept longer than the index: its own period", time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC), 60, 1,
			time.Date(2026, 1, 14, 12, 0, 0, 0, time.UTC)},
	} {
		if got := app.KeptByIndex(tc.now, tc.storeDays, tc.indexDays, day); !got.Equal(tc.want) {
			t.Errorf("%s: cutoff %v, want %v", tc.name, got, tc.want)
		}
	}
}
