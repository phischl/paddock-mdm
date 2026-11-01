// Package configrollout is the domain of staged configuration rollouts (plan M11 §3.7 and §3.8): the wave rules, the
// defaults of the organization's rollout settings, the bucket of a device in a rollout and the evaluation of a wave.
// It mirrors the agent rollout parameters (domain/agentrelease) so operators learn one vocabulary.
package configrollout

import (
	"encoding/json"
	"errors"
	"hash/fnv"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/domain/declarative"
)

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

// Statuses of a rollout; running and halted are open (at most one per organization).
const (
	StatusRunning   = "running"
	StatusHalted    = "halted"
	StatusCompleted = "completed"
	StatusReverted  = "reverted"
)

// Open reports whether a rollout with status stages its keys.
func Open(status string) bool { return status == StatusRunning || status == StatusHalted }

// Bucket is the bucket (0–99) of a device in one rollout: FNV-1a (32 bit) of "<device>:<rollout>" modulo 100, so
// every rollout draws its waves anew. The SQL function paddock_config_rollout_bucket computes the same value.
func Bucket(device, rollout uuid.UUID) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(device.String() + ":" + rollout.String()))
	return int(h.Sum32() % 100)
}

// Eligible reports whether a device receives the staged change: a member of the canary group always, every other
// device once the wave percentage exceeds its bucket.
func Eligible(bucket, percent int, canary bool) bool { return canary || bucket < percent }

// Percent is the share of devices a rollout has reached: the current wave while running, and the same while halted —
// a halted rollout keeps the wave it reached, so devices inside keep the new state and devices outside the old one.
// A completed rollout reached everything, a reverted one nothing.
func Percent(status string, waves []int, current int) int {
	switch status {
	case StatusRunning, StatusHalted:
		if current >= 0 && current < len(waves) {
			return waves[current]
		}
		return 0
	case StatusCompleted:
		return 100
	default:
		return 0
	}
}

// Threshold is the number of failed devices that halts a rollout: the larger of the minimum and the percentage of the
// eligible devices (rounded up), as for agent rollouts.
func Threshold(eligible int64, percent, minimum int) int64 {
	return max(int64(minimum), (eligible*int64(percent)+99)/100)
}

// Rollout is what the evaluation of a rollout reads.
type Rollout struct {
	Status           string
	Waves            []int
	CurrentWave      int
	WaveStartedAt    time.Time
	MinWaveMinutes   int
	FailurePercent   int
	FailureMin       int
	Eligible, Failed int64
}

// Decision is what the worker does with a running rollout.
type Decision int

// Decisions.
const (
	Keep Decision = iota
	Halt
	Advance
	Complete
)

// Decide evaluates a rollout at now (plan M11 decision 28): a running rollout halts when the failed devices reach the
// threshold; otherwise it advances when the current wave is older than the minimum wave duration, and completes after
// the last wave. Halted, completed and reverted rollouts are kept as they are.
func Decide(r Rollout, now time.Time) Decision {
	if r.Status != StatusRunning {
		return Keep
	}
	if r.Failed > 0 && r.Failed >= Threshold(r.Eligible, r.FailurePercent, r.FailureMin) {
		return Halt
	}
	if now.Sub(r.WaveStartedAt) < time.Duration(r.MinWaveMinutes)*time.Minute {
		return Keep
	}
	if r.CurrentWave+1 < len(r.Waves) {
		return Advance
	}
	return Complete
}

// rolloutSection reports whether section is one of declarative.RolloutSections.
func rolloutSection(section string) bool {
	return slices.Contains(declarative.RolloutSections(), section)
}

// Touches reports whether plan changes a section a rollout stages.
func Touches(p declarative.Plan) bool {
	return slices.ContainsFunc(p.Changes, func(c declarative.Change) bool { return rolloutSection(c.Section) })
}

// SectionGroup is the section of the one-open-rollout rule (ADR 0033 E1, amendment 2026-11-01): package holds and the
// update settings render into the same bundle resource (updates) and count as one section.
func SectionGroup(section string) string {
	if section == declarative.SectionPackageHolds {
		return declarative.SectionSettingsUpdates
	}
	return section
}

// StagedKeys returns the keys of plan's changes in rollout-able sections by section (settings.updates: the key "").
func StagedKeys(p declarative.Plan) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, c := range p.Changes {
		if !rolloutSection(c.Section) {
			continue
		}
		if out[c.Section] == nil {
			out[c.Section] = map[string]bool{}
		}
		out[c.Section][c.Key] = true
	}
	return out
}

// StagedResourceIDs returns the bundle resource IDs the staged changes of plan reach, sorted and without duplicates:
// file:<path> for a managed file, unit:<name> for a unit, updates for a package hold or the update settings. A failure
// of one of these resources counts against the rollout.
func StagedResourceIDs(p declarative.Plan) []string {
	var out []string
	for _, c := range p.Changes {
		switch c.Section {
		case declarative.SectionManagedFiles:
			out = append(out, "file:"+keyName(c.Key))
		case declarative.SectionManagedUnits:
			out = append(out, "unit:"+keyName(c.Key))
		case declarative.SectionPackageHolds, declarative.SectionSettingsUpdates:
			out = append(out, "updates")
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// keyName is the name part of a group-scoped key ([group, name]).
func keyName(key string) string {
	var parts []*string
	if err := json.Unmarshal([]byte(key), &parts); err != nil || len(parts) < 2 || parts[1] == nil {
		return key
	}
	return *parts[1]
}
