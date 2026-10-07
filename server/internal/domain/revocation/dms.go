package revocation

import (
	"errors"
	"fmt"
	"slices"
	"time"
)

// Dead man's switch settings (plan M4c decision 15).
const (
	DefaultPeriodDays = 30
	// MinPeriodDays is the shortest period: the offline window of Himmelblau's cached logins.
	MinPeriodDays = 7
	// DevMinPeriodDays is the shortest period of development installations (PADDOCK_ENV=development), for the
	// one-day test period of the hardware acceptance protocol (plan M4c §7).
	DevMinPeriodDays = 1
	MaxPeriodDays    = 365
	// WarnBelowDays is the period below which the portal warns.
	WarnBelowDays = 30
	MaxWarnDays   = 5
)

// DefaultWarnDays are the lead times of the warnings before the period ends.
var DefaultWarnDays = []int{3, 1}

// SelfLockLifetime is the validity of a self-lock token; the issuer replaces a token SelfLockRenewal before it
// expires.
const (
	SelfLockLifetime = 365 * 24 * time.Hour
	SelfLockRenewal  = 60 * 24 * time.Hour
)

// ErrDMSSettings is wrapped by every invalid setting.
var ErrDMSSettings = errors.New("invalid dead man's switch settings")

// ValidateDMS checks a period and its warning lead times: the period between minPeriodDays (MinPeriodDays, or
// DevMinPeriodDays in development) and MaxPeriodDays, at most MaxWarnDays distinct lead times, each at least 1 and
// shorter than the period.
func ValidateDMS(minPeriodDays, periodDays int, warnDays []int) error {
	if periodDays < minPeriodDays || periodDays > MaxPeriodDays {
		return fmt.Errorf("%w: period_days must be between %d and %d", ErrDMSSettings, minPeriodDays, MaxPeriodDays)
	}
	if len(warnDays) > MaxWarnDays {
		return fmt.Errorf("%w: at most %d warn_days", ErrDMSSettings, MaxWarnDays)
	}
	for i, d := range warnDays {
		if d < 1 || d >= periodDays || slices.Contains(warnDays[:i], d) {
			return fmt.Errorf("%w: warn_days must be distinct days from 1 to period_days - 1", ErrDMSSettings)
		}
	}
	return nil
}
