package configrollout

import (
	"errors"
	"testing"
	"time"
)

func TestValidateWaveRules(t *testing.T) {
	for _, c := range []struct {
		success, stall int
		want           error
	}{
		{1, 1, nil}, {100, 720, nil}, {0, 24, ErrInvalidSuccess}, {101, 24, ErrInvalidSuccess},
		{90, 0, ErrInvalidStall}, {90, 721, ErrInvalidStall},
	} {
		s := Defaults()
		s.WaveSuccessThresholdPercent, s.StallWarningHours = c.success, c.stall
		if err := s.Validate(false); !errors.Is(err, c.want) {
			t.Errorf("%d/%d: %v, want %v", c.success, c.stall, err, c.want)
		}
	}
}

func TestJoinedIn(t *testing.T) {
	waves := []int{10, 50, 100}
	for _, c := range []struct {
		bucket, current int
		canary, want    bool
	}{
		{5, 0, false, true}, {10, 0, false, false}, {5, 1, false, false}, {10, 1, false, true}, {49, 1, false, true},
		{50, 1, false, false}, {50, 2, false, true}, {99, 2, false, true}, {80, 0, true, true}, {80, 1, true, false},
		{80, 2, true, false}, {5, 3, false, false}, {5, -1, false, false},
	} {
		if got := JoinedIn(c.bucket, waves, c.current, c.canary); got != c.want {
			t.Errorf("JoinedIn(%d, wave %d, canary %v) = %v, want %v", c.bucket, c.current, c.canary, got, c.want)
		}
	}
}

// TestDecideWaitsForApplies (A10-16): a nightly window with a daytime change — the wave's devices wait for their
// window, so the wave does not advance however long ago it started; the minimum duration counts from the first apply,
// and then the success threshold or the end of the waiting decides.
func TestDecideWaitsForApplies(t *testing.T) {
	now := time.Date(2026, 11, 9, 14, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) *time.Time { at := now.Add(-d); return &at }
	base := Rollout{Status: StatusRunning, Waves: []int{10, 50, 100}, WaveStartedAt: now.Add(-48 * time.Hour),
		MinWaveMinutes: 60, FailurePercent: 2, FailureMin: 3, Eligible: 10, SuccessPercent: 90,
		Waiting: 10, Wave: WaveCounts{Eligible: 10}}
	cases := []struct {
		name   string
		change func(*Rollout)
		want   Decision
	}{
		{"every device waits for its window", func(*Rollout) {}, Keep},
		{"no device applied, none waits (offline)", func(r *Rollout) { r.Waiting = 0 }, Keep},
		{"first apply too recent", func(r *Rollout) {
			r.FirstAppliedAt, r.Wave.Applied, r.Wave.Recent, r.Waiting, r.Wave.Succeeded = ago(59*time.Minute), 10, 10, 0, 10
		}, Keep},
		{"threshold reached without the minimum time", func(r *Rollout) {
			r.FirstAppliedAt, r.Wave.Applied, r.Wave.Recent, r.Waiting, r.Wave.Succeeded = ago(10*time.Minute), 9, 9, 1, 9
		}, Keep},
		{"all applied after the minimum time", func(r *Rollout) {
			r.FirstAppliedAt, r.Wave.Applied, r.Wave.Recent, r.Waiting, r.Wave.Succeeded = ago(time.Hour), 10, 10, 0, 10
		}, Advance},
		{"mixed wave below the threshold, some still waiting", func(r *Rollout) {
			r.FirstAppliedAt, r.Wave.Applied, r.Wave.Recent, r.Waiting, r.Wave.Succeeded = ago(2*time.Hour), 8, 8, 2, 8
		}, Keep},
		{"mixed wave at the threshold, one still waiting", func(r *Rollout) {
			r.FirstAppliedAt, r.Wave.Applied, r.Wave.Recent, r.Waiting, r.Wave.Succeeded = ago(2*time.Hour), 9, 9, 1, 9
		}, Advance},
		{"mixed wave below the threshold, nobody waiting (rest offline)", func(r *Rollout) {
			r.FirstAppliedAt, r.Wave.Applied, r.Wave.Recent, r.Waiting, r.Wave.Succeeded = ago(2*time.Hour), 3, 3, 0, 3
		}, Advance},
		{"failures count as applied", func(r *Rollout) {
			r.FirstAppliedAt, r.Wave.Applied, r.Wave.Recent, r.Waiting, r.Failed, r.Wave.Succeeded = ago(2*time.Hour), 9, 9, 1, 2, 7
		}, Advance},
		{"waiting devices are never failed", func(r *Rollout) { r.FailureMin, r.FailurePercent = 0, 0 }, Keep},
		{"failure stop unchanged while waiting", func(r *Rollout) { r.Failed = 3 }, Halt},
		{"last wave completes only after its applies", func(r *Rollout) {
			r.CurrentWave = 2
		}, Keep},
		{"last wave completes", func(r *Rollout) {
			r.CurrentWave, r.FirstAppliedAt, r.Wave.Applied, r.Wave.Recent, r.Waiting, r.Wave.Succeeded = 2, ago(time.Hour), 10, 10, 0, 10
		}, Complete},
		{"after a resume, applies before it do not count toward the threshold", func(r *Rollout) {
			r.FirstAppliedAt, r.Wave.Applied, r.Wave.Recent, r.Waiting, r.Wave.Succeeded = ago(2*time.Hour), 9, 0, 1, 9
		}, Keep},
		{"after a resume, failures it discarded are outstanding", func(r *Rollout) {
			r.FirstAppliedAt, r.Wave.Applied, r.Wave.Recent, r.Waiting, r.AwaitingRetry, r.Wave.Succeeded = ago(2*time.Hour), 7, 0, 0, 3, 7
		}, Keep},
		{"after a resume, the discarded failures were retried", func(r *Rollout) {
			r.FirstAppliedAt, r.Wave.Applied, r.Wave.Recent, r.Waiting, r.Wave.Succeeded = ago(2*time.Hour), 10, 3, 0, 10
		}, Advance},
		// A10-19 I2 replaces the A10-18 reading of this case: a discarded failure holds the wave whatever the share.
		{"after a resume, enough new applies but one discarded failure not retried", func(r *Rollout) {
			r.FirstAppliedAt, r.Wave.Applied, r.Wave.Recent, r.Waiting, r.AwaitingRetry, r.Wave.Succeeded = ago(2*time.Hour), 9, 9, 0, 1, 9
		}, Keep},
		{"a wave nobody joined counts from its start", func(r *Rollout) { r.Wave = WaveCounts{} }, Advance},
		{"a young wave nobody joined", func(r *Rollout) {
			r.Wave, r.WaveStartedAt = WaveCounts{}, now.Add(-time.Minute)
		}, Keep},
	}
	for _, c := range cases {
		r := base
		c.change(&r)
		if got := Decide(r, now); got != c.want {
			t.Errorf("%s: Decide = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestStalled(t *testing.T) {
	now := time.Date(2026, 11, 9, 14, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name     string
		status   string
		progress time.Duration
		hours    int
		warned   bool
		want     bool
	}{
		{"24 h without progress", StatusRunning, 24 * time.Hour, 24, false, true},
		{"just under 24 h", StatusRunning, 24*time.Hour - time.Second, 24, false, false},
		{"configured per rollout", StatusRunning, 3 * time.Hour, 2, false, true},
		{"warned once only", StatusRunning, 48 * time.Hour, 24, true, false},
		{"halted rollouts do not stall", StatusHalted, 48 * time.Hour, 24, false, false},
	} {
		r := Rollout{Status: c.status, Wave: WaveCounts{Eligible: 2}, Waiting: 2, WaveProgressAt: now.Add(-c.progress),
			StallWarningHours: c.hours, StallWarned: c.warned}
		if got := Stalled(r, now); got != c.want {
			t.Errorf("%s: Stalled = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestDecideAccounting is the unit half of the A10-19 accounting table (plan M13c / M11 amendment 2026-11-09 §7): one
// subtest per row U1–U13, min_wave_minutes 30, wave_success_threshold_percent 90, failure_threshold_min 1 unless the
// row says otherwise.
func TestDecideAccounting(t *testing.T) {
	now := time.Date(2026, 11, 9, 14, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) *time.Time { at := now.Add(-d); return &at }
	base := func() Rollout {
		return Rollout{Status: StatusRunning, Waves: []int{50, 100}, CurrentWave: 0, WaveStartedAt: now.Add(-48 * time.Hour),
			MinWaveMinutes: 30, FailurePercent: 0, FailureMin: 1, SuccessPercent: 90, WaveProgressAt: now,
			StallWarningHours: 24}
	}
	u3 := func(r *Rollout) {
		r.Eligible, r.Waiting, r.FirstAppliedAt = 10, 1, ago(31*time.Minute)
		r.Wave = WaveCounts{Eligible: 10, Applied: 9, Succeeded: 9, Recent: 9}
	}
	u6 := func(r *Rollout) {
		r.Eligible, r.AwaitingRetry, r.FirstAppliedAt = 11, 1, ago(31*time.Minute)
		r.Wave = WaveCounts{Eligible: 10, Applied: 10, Succeeded: 10, Recent: 10}
	}
	cases := []struct {
		id           string
		setup        func(*Rollout)
		want         Decision
		observed     *bool
		stalled      *bool
		stalledAfter time.Duration
	}{
		{id: "U1", setup: func(r *Rollout) {
			r.Eligible, r.Failed, r.FirstAppliedAt = 3, 3, ago(31*time.Minute)
			r.Wave = WaveCounts{Eligible: 3, Applied: 3, Recent: 3}
		}, want: Halt},
		{id: "U2", setup: func(r *Rollout) {
			r.Eligible, r.Failed, r.FailureMin, r.FirstAppliedAt = 3, 3, 5, ago(31*time.Minute)
			r.Wave = WaveCounts{Eligible: 3, Applied: 3, Recent: 3}
		}, want: Keep, observed: ptr(false)},
		{id: "U3", setup: u3, want: Advance, observed: ptr(true)},
		{id: "U4", setup: func(r *Rollout) {
			r.Eligible, r.Waiting, r.FirstAppliedAt = 11, 1, ago(31*time.Minute)
			r.Wave = WaveCounts{Eligible: 10, Applied: 8, Succeeded: 8, Recent: 8}
		}, want: Keep, observed: ptr(false)},
		{id: "U5", setup: func(r *Rollout) {
			r.Eligible, r.FirstAppliedAt = 11, ago(31*time.Minute)
			r.Wave = WaveCounts{Eligible: 10, Applied: 8, Succeeded: 8, Recent: 8}
		}, want: Advance, observed: ptr(true)},
		{id: "U6", setup: u6, want: Keep, observed: ptr(false)},
		{id: "U7", setup: func(r *Rollout) {
			r.CurrentWave, r.Eligible, r.AwaitingRetry, r.WaveStartedAt = 1, 4, 1, now.Add(-31*time.Minute)
		}, want: Keep, observed: ptr(false)},
		{id: "U8 -29 min", setup: func(r *Rollout) { r.Eligible, r.WaveStartedAt = 4, now.Add(-29*time.Minute) },
			want: Keep, observed: ptr(true)},
		{id: "U8 -30 min", setup: func(r *Rollout) { r.Eligible, r.WaveStartedAt = 4, now.Add(-30*time.Minute) },
			want: Advance, observed: ptr(true)},
		{id: "U9", setup: func(r *Rollout) {
			r.Eligible, r.FirstAppliedAt = 5, ago(30*time.Minute)
			r.Wave = WaveCounts{Eligible: 5, Applied: 5, Succeeded: 5}
		}, want: Advance, observed: ptr(true)},
		{id: "U10", setup: func(r *Rollout) {
			r.Eligible = 5
			r.Wave = WaveCounts{Eligible: 5, Applied: 5, Succeeded: 5}
		}, want: Keep, observed: ptr(false)},
		{id: "U11", setup: func(r *Rollout) { u3(r); r.FirstAppliedAt = ago(29 * time.Minute) },
			want: Keep, observed: ptr(true), stalled: ptr(false), stalledAfter: 1000 * time.Hour},
		{id: "U12 not warned", setup: u6, want: Keep, stalled: ptr(true), stalledAfter: 24 * time.Hour},
		{id: "U12 warned", setup: func(r *Rollout) { u6(r); r.StallWarned = true },
			want: Keep, stalled: ptr(false), stalledAfter: 24 * time.Hour},
		{id: "U13", setup: func(r *Rollout) { u3(r); r.CurrentWave = 1 }, want: Complete},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			r := base()
			c.setup(&r)
			if got := Decide(r, now); got != c.want {
				t.Errorf("Decide = %v, want %v", got, c.want)
			}
			if c.observed != nil && Observed(r) != *c.observed {
				t.Errorf("Observed = %v, want %v", Observed(r), *c.observed)
			}
			if c.stalled != nil {
				r.WaveProgressAt = now.Add(-c.stalledAfter)
				if got := Stalled(r, now); got != *c.stalled {
					t.Errorf("Stalled = %v, want %v", got, *c.stalled)
				}
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }
