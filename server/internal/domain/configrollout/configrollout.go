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
	// DefaultWaveSuccessThresholdPercent is the share of a wave's new devices that must have applied before the wave
	// advances while some of them still wait for their maintenance window (architect decision A10-16).
	DefaultWaveSuccessThresholdPercent = 90
	// DefaultStallWarningHours is how long a wave may go without a new apply before the worker warns (A10-16).
	DefaultStallWarningHours = 24
	// MaxStallWarningHours bounds the stall warning to 30 days.
	MaxStallWarningHours = 720
)

// DefaultWaves returns the default waves: 1 %, 10 %, 50 %, then everything.
func DefaultWaves() []int { return []int{1, 10, 50, 100} }

// Validation errors.
var (
	ErrInvalidWaves     = errors.New("waves must be 1 to 10 strictly increasing percentages between 1 and 100 ending with 100")
	ErrInvalidMinWave   = errors.New("min_wave_minutes is below the minimum")
	ErrInvalidThreshold = errors.New("failure_threshold_percent must be 0 to 100 and failure_threshold_min at least 0")
	ErrInvalidSuccess   = errors.New("wave_success_threshold_percent must be 1 to 100")
	ErrInvalidStall     = errors.New("stall_warning_hours must be 1 to 720")
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
	// WaveSuccessThresholdPercent and StallWarningHours are the rules of waves against maintenance windows (A10-16).
	WaveSuccessThresholdPercent int
	StallWarningHours           int
}

// Defaults returns the settings of an organization that never changed them: rollouts off.
func Defaults() Settings {
	return Settings{
		Waves: DefaultWaves(), MinWaveMinutes: DefaultMinWaveMinutes,
		FailureThresholdPercent: DefaultFailureThresholdPercent, FailureThresholdMin: DefaultFailureThresholdMin,
		WaveSuccessThresholdPercent: DefaultWaveSuccessThresholdPercent, StallWarningHours: DefaultStallWarningHours,
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
	if s.WaveSuccessThresholdPercent < 1 || s.WaveSuccessThresholdPercent > 100 {
		return ErrInvalidSuccess
	}
	if s.StallWarningHours < 1 || s.StallWarningHours > MaxStallWarningHours {
		return ErrInvalidStall
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

// JoinedIn reports whether an eligible device joined the rollout in wave current: every eligible device in the first
// wave, in a later one a device the previous wave did not reach. The wave's own rules (Decide) look at these devices
// only, because the devices of the earlier waves applied before the wave started (A10-16).
func JoinedIn(bucket int, waves []int, current int, canary bool) bool {
	if current < 0 || current >= len(waves) || !Eligible(bucket, waves[current], canary) {
		return false
	}
	return current == 0 || !Eligible(bucket, waves[current-1], canary) //nolint:gosec // the guard above bounds current to 1..len(waves)-1 here
}

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

// Rollout is what the evaluation of a rollout reads. Eligible, Failed, Waiting and AwaitingRetry count every eligible
// device of the reached waves (set E of the A10-19 accounting table): Waiting those that wait for their maintenance
// window, AwaitingRetry those whose failure the last resume discarded and, after a resume, those whose newest report is
// a failure. Wave counts the devices that joined in the current wave.
type Rollout struct {
	Status                 string
	Waves                  []int
	CurrentWave            int
	WaveStartedAt          time.Time
	MinWaveMinutes         int
	FailurePercent         int
	FailureMin             int
	Eligible, Failed       int64
	Waiting, AwaitingRetry int64
	SuccessPercent         int
	FirstAppliedAt         *time.Time
	Wave                   WaveCounts
	WaveProgressAt         time.Time
	StallWarningHours      int
	StallWarned            bool
}

// WaveCounts are the eligible devices that joined in the current wave (JoinedIn, set J of the A10-19 accounting table):
// how many there are, how many have applied with success or failure at any time (Applied, dates the wave's clock), how
// many of those applied since the rollout's start or last resume (Recent, the share), and how many applied without
// failure at any time (Succeeded, the observed success a wave needs).
type WaveCounts struct {
	Eligible, Applied, Recent, Succeeded int64
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

// Decide evaluates a rollout at now (plan M11 decision 28, the A10-19 accounting table): a running rollout halts when
// the failed devices of every reached wave reach the threshold; otherwise it advances, or completes after the last
// wave, once its current wave is done (WaveDone). Halted, completed and reverted rollouts are kept as they are.
func Decide(r Rollout, now time.Time) Decision {
	if r.Status != StatusRunning {
		return Keep
	}
	if r.Failed > 0 && r.Failed >= Threshold(r.Eligible, r.FailurePercent, r.FailureMin) {
		return Halt
	}
	if !WaveDone(r, now) {
		return Keep
	}
	if r.CurrentWave+1 < len(r.Waves) {
		return Advance
	}
	return Complete
}

// WaveDone reports whether the current wave of r is done at now (A10-16, A10-19, agent contract 6): the wave is
// Observed and the minimum wave duration has passed since the worker first saw a device that joined in the wave
// applied. Time never stands in for an observed apply. Only a wave that no device joined has nothing to observe; its
// duration counts from its start. A resume clears the first apply, so the wave gets its full observation period again
// (plan M11 amendment R6.14 (d), A10-18).
func WaveDone(r Rollout, now time.Time) bool {
	if !Observed(r) {
		return false
	}
	start := r.WaveStartedAt
	if r.Wave.Eligible > 0 {
		start = *r.FirstAppliedAt
	}
	return now.Sub(start) >= time.Duration(r.MinWaveMinutes)*time.Minute
}

// Observed reports whether everything but the minimum duration of WaveDone holds for r (A10-19 §3): no device of any
// reached wave awaits a retry after a resume, and either no device joined the wave, or one of those that joined applied
// without failure and the share of them that applied since the start or last resume reaches the success threshold or
// no eligible device waits for its maintenance window. A rollout therefore never advances without an observed success
// (I1) and never past a failure a resume discarded (I2).
func Observed(r Rollout) bool {
	if r.AwaitingRetry > 0 {
		return false
	}
	if r.Wave.Eligible == 0 {
		return true
	}
	return r.FirstAppliedAt != nil && r.Wave.Succeeded >= 1 &&
		(r.Wave.Recent*100 >= int64(r.SuccessPercent)*r.Wave.Eligible || r.Waiting == 0)
}

// Stalled reports whether a running rollout's wave is not Observed and has gone StallWarningHours without progress since
// WaveProgressAt (the wave's start, the last resume, the last growth of its applied devices or the last shrink of the
// devices it waits for) and was not warned about yet (A10-16, A10-19). A wave that only waits for its minimum duration
// is never stalled. The warning only informs: nothing advances and nothing is applied outside a window because of it.
func Stalled(r Rollout, now time.Time) bool {
	return r.Status == StatusRunning && !Observed(r) && !r.StallWarned &&
		now.Sub(r.WaveProgressAt) >= time.Duration(r.StallWarningHours)*time.Hour
}

// rolloutSection reports whether section is one of declarative.RolloutSections.
func rolloutSection(section string) bool {
	return slices.Contains(declarative.RolloutSections(), section)
}

// SectionGroup is the section of the one-open-rollout rule (ADR 0033 E1, amendment 2026-11-01): package holds and the
// update settings render into the same bundle resource (updates) and count as one section.
func SectionGroup(section string) string {
	if section == declarative.SectionPackageHolds {
		return declarative.SectionSettingsUpdates
	}
	return section
}

// StagedKeys returns the keys of plan's changes in rollout-able sections by section (settings.updates: the key ""),
// without the changes cascaded from a device group the plan deletes: those are never staged (plan M11 amendment
// R6.13), because an overlay could not restore an item whose group is gone. Items of a group the plan creates follow
// the normal rules. A catalog entry has no such cascade: its deletion is refused while it has assignments (plan M13c
// amendment 2026-11-09, A10-12), so a deletion of an assignment is always staged.
func StagedKeys(p declarative.Plan) map[string]map[string]bool { return StagedKeysExcept(p, nil) }

// StagedKeysExcept is StagedKeys that also leaves out the item changes of renamed, the new names of device groups the
// plan renamed by identity (a rename records the deletion of the old name and the creation of the new one). Only the
// writer that renamed a group knows its identity; such a change set stages nothing, so readers of a stored plan use
// StagedKeys.
func StagedKeysExcept(p declarative.Plan, renamed map[string]bool) map[string]map[string]bool {
	cascaded := DeletedGroups(p)
	for g := range renamed {
		cascaded[g] = true
	}
	out := map[string]map[string]bool{}
	for _, c := range p.Changes {
		if !rolloutSection(c.Section) {
			continue
		}
		if g, ok := KeyGroup(c.Key); ok && cascaded[g] {
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
	for section, keys := range StagedKeys(p) {
		for key := range keys {
			switch section {
			case declarative.SectionManagedFiles:
				out = append(out, "file:"+KeyName(key))
			case declarative.SectionManagedUnits:
				out = append(out, "unit:"+KeyName(key))
			case declarative.SectionPackageHolds, declarative.SectionSettingsUpdates:
				out = append(out, "updates")
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// DeletedGroups returns the names of the device groups plan deletes; a rename deletes the old name (natural keys).
func DeletedGroups(p declarative.Plan) map[string]bool {
	out := map[string]bool{}
	for _, c := range p.Changes {
		if c.Section == declarative.SectionDeviceGroups && c.Action == declarative.ActionDelete {
			out[KeyName(c.Key)] = true
		}
	}
	return out
}

// StagedEntries returns the names of the catalog entries whose assignments plan stages, sorted: a failed software
// status of one of them on a device of the wave counts against the rollout as resource software:<entry id> (plan M13c
// decision 3). The names resolve to IDs against the catalog: an open rollout keeps them, because a write that renames or
// deletes such an entry is refused while the rollout is open (app requireEntriesNotStaged), staged assignment deletions
// included.
func StagedEntries(p declarative.Plan) []string {
	var out []string
	for key := range StagedKeys(p)[declarative.SectionSoftwareAssignments] {
		out = append(out, KeyEntry(key))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// StagedAssignment is the row a staged software assignment key named when its rollout started: the assignment's row ID
// (the replaced row of an update or deletion, the new row of a creation), its catalog entry and the device group, user
// or user group it targets (nil for the organization). The compiler matches live rows and before items by these IDs,
// not by the names in the key: a username comes from identity sync and can change while the rollout runs (plan M13c
// decision 3).
type StagedAssignment struct {
	ID     uuid.UUID  `json:"id"`
	Entry  uuid.UUID  `json:"entry_id"`
	Target *uuid.UUID `json:"target_id,omitempty"`
}

// KeyEntry is the entry of a software assignment key ([group, entry, target type, user or user group]); "" for any
// other key.
func KeyEntry(key string) string {
	var parts []*string
	if err := json.Unmarshal([]byte(key), &parts); err != nil || len(parts) != 4 || parts[1] == nil {
		return ""
	}
	return *parts[1]
}

// KeyGroup returns the device group of a group-scoped key ([group, name]); false for an item of every device and for
// keys that are not group-scoped.
func KeyGroup(key string) (string, bool) {
	var parts []*string
	if err := json.Unmarshal([]byte(key), &parts); err != nil || len(parts) < 2 || parts[0] == nil {
		return "", false
	}
	return *parts[0], true
}

// KeyName is the name part of a key: the last part of a group-scoped key ([group, name]) or the only one ([name]).
func KeyName(key string) string {
	var parts []*string
	if err := json.Unmarshal([]byte(key), &parts); err != nil || len(parts) == 0 || parts[len(parts)-1] == nil {
		return key
	}
	return *parts[len(parts)-1]
}
