package backupset

import (
	"errors"
	"fmt"
)

// ErrInvalidSchedule is the cause of every schedule ValidateSchedule refuses.
var ErrInvalidSchedule = errors.New("invalid backup schedule")

// Schedule holds the intervals and retention of the backup role (plan M15 decision 12); the bounds are the CHECKs of
// backup_schedule.
type Schedule struct {
	FullIntervalHours    int
	OpenBaoIntervalHours int
	FleetIntervalHours   int
	EscrowIntervalHours  int
	RetentionFull        int
	OpenBaoKeepDays      int
	FleetKeepDays        int
}

// DefaultSchedule is the schedule without a backup_schedule row; it equals the RPO table before M15.
func DefaultSchedule() Schedule {
	return Schedule{FullIntervalHours: 24, OpenBaoIntervalHours: 6, FleetIntervalHours: 24, EscrowIntervalHours: 1,
		RetentionFull: 14, OpenBaoKeepDays: 30, FleetKeepDays: 30}
}

// ValidateSchedule checks every field of s against its bounds.
func ValidateSchedule(s Schedule) error {
	for _, f := range []struct {
		name          string
		value, lo, hi int
	}{
		{"full_interval_hours", s.FullIntervalHours, 6, 168},
		{"openbao_interval_hours", s.OpenBaoIntervalHours, 1, 24},
		{"fleet_interval_hours", s.FleetIntervalHours, 6, 168},
		{"escrow_interval_hours", s.EscrowIntervalHours, 1, 24},
		{"retention_full", s.RetentionFull, 2, 60},
		{"openbao_keep_days", s.OpenBaoKeepDays, 7, 365},
		{"fleet_keep_days", s.FleetKeepDays, 7, 365},
	} {
		if f.value < f.lo || f.value > f.hi {
			return fmt.Errorf("%w: %s must be %d to %d", ErrInvalidSchedule, f.name, f.lo, f.hi)
		}
	}
	return nil
}
