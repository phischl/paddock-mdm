// Package configrollout is the domain of staged configuration rollouts (plan M11 §3.7): the wave rules and the
// defaults of the organization's rollout settings. It mirrors the agent rollout parameters (domain/agentrelease) so
// operators learn one vocabulary.
package configrollout

import "errors"

// Defaults of the rollout settings (plan M11 decision 23).
const (
	DefaultMinWaveMinutes          = 60
	DefaultFailureThresholdPercent = 2
	DefaultFailureThresholdMin     = 3
	// MinWaveMinutesProduction is the smallest wave duration outside development; development allows 1.
	MinWaveMinutesProduction = 15
	// MinWaveMinutesDevelopment is the smallest wave duration in development (PADDOCK_ENV=development).
	MinWaveMinutesDevelopment = 1
	// MaxWaves bounds the number of waves.
	MaxWaves = 10
)

// DefaultWaves returns the default waves: 1 %, 10 %, 50 %, then everything.
func DefaultWaves() []int { return []int{1, 10, 50, 100} }

// Validation errors.
var (
	ErrInvalidWaves     = errors.New("waves must be 1 to 10 strictly increasing percentages between 1 and 100 ending with 100")
	ErrInvalidMinWave   = errors.New("min_wave_minutes is below the minimum")
	ErrInvalidThreshold = errors.New("failure_threshold_percent must be 0 to 100 and failure_threshold_min at least 0")
)

// ValidateWaves checks the wave percentages of a rollout (the same rule as agentrelease.ValidateWaves).
func ValidateWaves(w []int) error {
	if len(w) == 0 || len(w) > MaxWaves || w[len(w)-1] != 100 {
		return ErrInvalidWaves
	}
	for i, p := range w {
		if p < 1 || p > 100 || (i > 0 && p <= w[i-1]) {
			return ErrInvalidWaves
		}
	}
	return nil
}

// Settings are the validated values of the rollout settings; the canary device group is an organization reference
// the use case checks.
type Settings struct {
	Enabled                 bool
	Waves                   []int
	MinWaveMinutes          int
	FailureThresholdPercent int
	FailureThresholdMin     int
}

// Defaults returns the settings of an organization that never changed them: rollouts off.
func Defaults() Settings {
	return Settings{
		Waves: DefaultWaves(), MinWaveMinutes: DefaultMinWaveMinutes,
		FailureThresholdPercent: DefaultFailureThresholdPercent, FailureThresholdMin: DefaultFailureThresholdMin,
	}
}

// Validate checks the settings; development lowers the minimum wave duration.
func (s Settings) Validate(development bool) error {
	if err := ValidateWaves(s.Waves); err != nil {
		return err
	}
	minimum := MinWaveMinutesProduction
	if development {
		minimum = MinWaveMinutesDevelopment
	}
	if s.MinWaveMinutes < minimum {
		return ErrInvalidMinWave
	}
	if s.FailureThresholdPercent < 0 || s.FailureThresholdPercent > 100 || s.FailureThresholdMin < 0 {
		return ErrInvalidThreshold
	}
	return nil
}
