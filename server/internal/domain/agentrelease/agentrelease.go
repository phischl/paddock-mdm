// Package agentrelease holds the rules of agent releases and staged rollouts (plan M2b decisions 19–22): versions,
// architectures, waves, the rollout bucket of a device, and when a rollout halts, advances or completes.
package agentrelease

import (
	"errors"
	"fmt"
	"hash/fnv"
	"regexp"
	"slices"
	"time"

	"github.com/google/uuid"
)

// Release and rollout states.
const (
	StatusDraft     = "draft"
	StatusPublished = "published"

	RolloutRunning   = "running"
	RolloutHalted    = "halted"
	RolloutCompleted = "completed"
)

// Arches are the supported agent architectures.
var Arches = []string{"amd64", "arm64"}

// Rollout defaults (plan M2b decision 19).
var DefaultWaves = []int{1, 10, 50, 100}

const (
	DefaultMinWaveMinutes          = 1440
	DefaultFailureThresholdPercent = 2
	DefaultFailureThresholdMin     = 3
	// MinWaveMinutesProduction is the smallest wave duration outside development.
	MinWaveMinutesProduction = 60
	// MaxArtifactBytes bounds an uploaded agent binary.
	MaxArtifactBytes = 128 << 20
	// CurrentReleaseWindow is the sliding window over which the failures and offered devices of a completed
	// rollout (the current release) are counted (plan M2.1 decision 1).
	CurrentReleaseWindow = 7 * 24 * time.Hour
)

// Validation errors.
var (
	ErrInvalidVersion = errors.New("version must be a semantic version such as 1.4.2 (at most 64 characters)")
	ErrInvalidArch    = errors.New("arch must be amd64 or arm64")
	ErrInvalidWaves   = errors.New("waves must be 1 to 10 strictly increasing percentages between 1 and 100 ending with 100")
)

var versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

// ValidateVersion checks a release version.
func ValidateVersion(v string) error {
	if len(v) > 64 || !versionPattern.MatchString(v) {
		return ErrInvalidVersion
	}
	return nil
}

// ValidateArch checks an architecture.
func ValidateArch(a string) error {
	if !slices.Contains(Arches, a) {
		return ErrInvalidArch
	}
	return nil
}

// ValidateWaves checks the wave percentages of a rollout.
func ValidateWaves(w []int) error {
	if len(w) == 0 || len(w) > 10 || w[len(w)-1] != 100 {
		return ErrInvalidWaves
	}
	for i, p := range w {
		if p < 1 || p > 100 || (i > 0 && p <= w[i-1]) {
			return ErrInvalidWaves
		}
	}
	return nil
}

// ObjectKey is the object of an artifact in the bucket paddock-agent-artifacts.
func ObjectKey(version, arch string) string {
	return fmt.Sprintf("releases/%s/%s/paddockd", version, arch)
}

// Bucket is the rollout bucket of a device: FNV-1a (32 bit) of the canonical UUID text modulo 100. The SQL function
// paddock_rollout_bucket computes the same value.
func Bucket(device uuid.UUID) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(device.String()))
	return int(h.Sum32() % 100)
}

// Eligible reports whether a device is in the waves up to percent.
func Eligible(device uuid.UUID, percent int) bool { return Bucket(device) < percent }

// Threshold is the number of failed devices that halts a rollout: the larger of the minimum and the percentage of
// the eligible devices (rounded up).
func Threshold(eligible int64, percent, minimum int) int64 {
	return max(int64(minimum), (eligible*int64(percent)+99)/100)
}

// Rollout is the state the worker evaluates. For a completed rollout, Eligible and Failed are counted over
// CurrentReleaseWindow.
type Rollout struct {
	Waves            []int
	CurrentWave      int
	WaveStartedAt    time.Time
	MinWaveMinutes   int
	FailurePercent   int
	FailureMin       int
	Status           string
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

// Decide evaluates a rollout at now (plan M2b decision 22, M2.1 decision 1): a running or completed rollout halts
// when the failed devices reach the threshold; otherwise a running one advances when the current wave is older than
// the minimum wave duration, and completes after the last wave.
func Decide(r Rollout, now time.Time) Decision {
	if r.Status != RolloutRunning && r.Status != RolloutCompleted {
		return Keep
	}
	if r.Failed > 0 && r.Failed >= Threshold(r.Eligible, r.FailurePercent, r.FailureMin) {
		return Halt
	}
	if r.Status == RolloutCompleted {
		return Keep
	}
	if now.Sub(r.WaveStartedAt) < time.Duration(r.MinWaveMinutes)*time.Minute {
		return Keep
	}
	if r.CurrentWave+1 < len(r.Waves) {
		return Advance
	}
	return Complete
}

// Percent is the share of devices a rollout currently offers the release to: the current wave while running,
// everything once completed, nothing when halted.
func Percent(status string, waves []int, current int) int {
	switch status {
	case RolloutRunning:
		return waves[current]
	case RolloutCompleted:
		return 100
	default:
		return 0
	}
}

// Offer is what the gateway offers devices: the current rollout with its artifacts (Valkey ar:current, written by
// the worker, read by the gateway).
type Offer struct {
	Version     string              `json:"version"`
	Status      string              `json:"status"`
	Waves       []int               `json:"waves"`
	CurrentWave int                 `json:"current_wave_index"`
	Artifacts   map[string]Artifact `json:"artifacts"` // by arch
}

// Artifact is one signed agent binary.
type Artifact struct {
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	Minisig   string `json:"minisig"`
	ObjectKey string `json:"object_key"`
}

// For returns the artifact a device with arch and agent version should update to, if it is eligible.
func (o Offer) For(device uuid.UUID, arch, agentVersion string) (Artifact, bool) {
	a, ok := o.Artifacts[arch]
	if !ok || agentVersion == o.Version || !Eligible(device, Percent(o.Status, o.Waves, o.CurrentWave)) {
		return Artifact{}, false
	}
	return a, true
}
