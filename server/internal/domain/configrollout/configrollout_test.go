package configrollout

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/domain/declarative"
)

func TestValidateWaves(t *testing.T) {
	valid := [][]int{{100}, {1, 100}, {1, 10, 50, 100}, {10, 20, 30, 40, 50, 60, 70, 80, 90, 100}}
	for _, w := range valid {
		if err := ValidateWaves(w); err != nil {
			t.Errorf("%v rejected: %v", w, err)
		}
	}
	invalid := [][]int{nil, {}, {50}, {1, 10}, {0, 100}, {10, 10, 100}, {50, 10, 100}, {1, 101, 100}, {-1, 100},
		{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 100}}
	for _, w := range invalid {
		if err := ValidateWaves(w); !errors.Is(err, ErrInvalidWaves) {
			t.Errorf("%v accepted: %v", w, err)
		}
	}
}

func TestDefaultsAreValidAndOff(t *testing.T) {
	d := Defaults()
	if d.Enabled || d.MinWaveMinutes != 60 || d.FailureThresholdPercent != 2 || d.FailureThresholdMin != 3 {
		t.Fatalf("defaults %+v", d)
	}
	if err := d.Validate(false); err != nil {
		t.Fatalf("defaults invalid: %v", err)
	}
}

func TestDefaultWavesAreFresh(t *testing.T) {
	a := DefaultWaves()
	a[0] = 99
	if DefaultWaves()[0] != 1 {
		t.Fatal("default waves are shared")
	}
}

func TestValidateMinWaveMinutes(t *testing.T) {
	cases := []struct {
		minutes     int
		development bool
		ok          bool
	}{
		{15, false, true}, {14, false, false}, {1, false, false}, {0, false, false},
		{1, true, true}, {0, true, false}, {-5, true, false},
	}
	for _, c := range cases {
		s := Defaults()
		s.MinWaveMinutes = c.minutes
		err := s.Validate(c.development)
		if (err == nil) != c.ok || (!c.ok && !errors.Is(err, ErrInvalidMinWave)) {
			t.Errorf("minutes %d development %v: %v", c.minutes, c.development, err)
		}
	}
}

func TestValidateThresholds(t *testing.T) {
	for _, c := range []struct {
		percent, minimum int
		ok               bool
	}{{0, 0, true}, {100, 5, true}, {-1, 3, false}, {101, 3, false}, {2, -1, false}} {
		s := Defaults()
		s.FailureThresholdPercent, s.FailureThresholdMin = c.percent, c.minimum
		if err := s.Validate(false); (err == nil) != c.ok {
			t.Errorf("%d/%d: %v", c.percent, c.minimum, err)
		}
	}
}

func TestValidateRejectsInvalidWaves(t *testing.T) {
	s := Defaults()
	s.Waves = []int{1, 10}
	if err := s.Validate(true); !errors.Is(err, ErrInvalidWaves) {
		t.Fatalf("%v", err)
	}
}

func TestBucketReferenceValues(t *testing.T) {
	// FNV-1a of "<device>:<rollout>" computed independently; the SQL function must agree (TestConfigRolloutBucketMatchesSQL).
	if got := Bucket(uuid.Nil, uuid.Nil); got != 45 {
		t.Errorf("Bucket(nil, nil) = %d, want 45", got)
	}
	if got := Bucket(uuid.MustParse("ffffffff-ffff-ffff-ffff-ffffffffffff"), uuid.MustParse("01890000-0000-7000-8000-000000000001")); got != 25 {
		t.Errorf("Bucket(max, r) = %d, want 25", got)
	}
}

func TestBucketDiffersBetweenRollouts(t *testing.T) {
	r1, r2 := uuid.New(), uuid.New()
	same := 0
	for range 1000 {
		d := uuid.New()
		b1, b2 := Bucket(d, r1), Bucket(d, r2)
		if b1 < 0 || b1 > 99 {
			t.Fatalf("bucket %d out of range", b1)
		}
		if b1 == b2 {
			same++
		}
	}
	// Independent draws agree in about 1 % of the cases.
	if same > 100 {
		t.Fatalf("%d of 1000 devices kept their bucket between two rollouts", same)
	}
}

func TestEligible(t *testing.T) {
	for _, c := range []struct {
		bucket, percent int
		canary, want    bool
	}{{0, 1, false, true}, {1, 1, false, false}, {49, 50, false, true}, {50, 50, false, false}, {99, 100, false, true},
		{99, 1, true, true}, {10, 0, false, false}} {
		if got := Eligible(c.bucket, c.percent, c.canary); got != c.want {
			t.Errorf("Eligible(%d, %d, %v) = %v", c.bucket, c.percent, c.canary, got)
		}
	}
}

func TestPercent(t *testing.T) {
	waves := []int{1, 10, 100}
	for _, c := range []struct {
		status  string
		current int
		want    int
	}{{StatusRunning, 0, 1}, {StatusRunning, 1, 10}, {StatusHalted, 1, 10}, {StatusHalted, 2, 100}, {StatusCompleted, 0, 100},
		{StatusReverted, 1, 0}, {StatusRunning, 5, 0}} {
		if got := Percent(c.status, waves, c.current); got != c.want {
			t.Errorf("Percent(%s, %d) = %d, want %d", c.status, c.current, got, c.want)
		}
	}
	if !Open(StatusRunning) || !Open(StatusHalted) || Open(StatusCompleted) || Open(StatusReverted) {
		t.Error("Open")
	}
}

func TestThreshold(t *testing.T) {
	for _, c := range []struct {
		eligible         int64
		percent, minimum int
		want             int64
	}{{0, 2, 3, 3}, {100, 2, 3, 3}, {200, 2, 3, 4}, {201, 2, 3, 5}, {10, 0, 1, 1}, {10, 0, 0, 0}} {
		if got := Threshold(c.eligible, c.percent, c.minimum); got != c.want {
			t.Errorf("Threshold(%d, %d, %d) = %d, want %d", c.eligible, c.percent, c.minimum, got, c.want)
		}
	}
}

func TestDecide(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	base := Rollout{Status: StatusRunning, Waves: []int{10, 50, 100}, WaveStartedAt: now.Add(-30 * time.Minute),
		MinWaveMinutes: 60, FailurePercent: 2, FailureMin: 3, Eligible: 100}
	cases := []struct {
		name   string
		change func(*Rollout)
		want   Decision
	}{
		{"young wave", func(*Rollout) {}, Keep},
		{"old wave advances", func(r *Rollout) { r.WaveStartedAt = now.Add(-time.Hour) }, Advance},
		{"last wave completes", func(r *Rollout) { r.WaveStartedAt, r.CurrentWave = now.Add(-time.Hour), 2 }, Complete},
		{"failures below the threshold", func(r *Rollout) { r.Failed = 2 }, Keep},
		{"failures at the threshold halt", func(r *Rollout) { r.Failed = 3 }, Halt},
		{"halt wins over advance", func(r *Rollout) { r.Failed, r.WaveStartedAt = 3, now.Add(-time.Hour) }, Halt},
		{"zero threshold needs a failure", func(r *Rollout) { r.FailureMin, r.FailurePercent = 0, 0 }, Keep},
		{"halted is kept", func(r *Rollout) { r.Status, r.Failed, r.WaveStartedAt = StatusHalted, 9, now.Add(-time.Hour) }, Keep},
		{"completed is kept", func(r *Rollout) { r.Status, r.Failed = StatusCompleted, 9 }, Keep},
		{"reverted is kept", func(r *Rollout) { r.Status, r.WaveStartedAt = StatusReverted, now.Add(-time.Hour) }, Keep},
	}
	for _, c := range cases {
		r := base
		c.change(&r)
		if got := Decide(r, now); got != c.want {
			t.Errorf("%s: Decide = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestStagedKeysAndResourceIDs(t *testing.T) {
	plan := declarative.Plan{Changes: []declarative.Change{
		{Section: declarative.SectionDeviceGroups, Key: `["lab"]`, Action: declarative.ActionUpdate},
		{Section: declarative.SectionManagedFiles, Key: `["lab","/etc/motd"]`, Action: declarative.ActionCreate},
		{Section: declarative.SectionManagedFiles, Key: `[null,"/etc/motd"]`, Action: declarative.ActionUpdate},
		{Section: declarative.SectionManagedUnits, Key: `[null,"foo.service"]`, Action: declarative.ActionDelete},
		{Section: declarative.SectionPackageHolds, Key: `[null,"openssl"]`, Action: declarative.ActionCreate},
		{Section: declarative.SectionSettingsUpdates, Key: "", Action: declarative.ActionUpdate},
		{Section: declarative.SectionSettingsLogin, Key: "", Action: declarative.ActionUpdate},
	}}
	want := map[string]map[string]bool{
		declarative.SectionManagedFiles:    {`["lab","/etc/motd"]`: true, `[null,"/etc/motd"]`: true},
		declarative.SectionManagedUnits:    {`[null,"foo.service"]`: true},
		declarative.SectionPackageHolds:    {`[null,"openssl"]`: true},
		declarative.SectionSettingsUpdates: {"": true},
	}
	if got := StagedKeys(plan); !reflect.DeepEqual(got, want) {
		t.Errorf("StagedKeys = %v", got)
	}
	if got := StagedResourceIDs(plan); !reflect.DeepEqual(got, []string{"file:/etc/motd", "unit:foo.service", "updates"}) {
		t.Errorf("StagedResourceIDs = %v", got)
	}
	if !Touches(plan) || Touches(declarative.Plan{Changes: plan.Changes[:1]}) {
		t.Error("Touches")
	}
}

func TestSectionGroup(t *testing.T) {
	if SectionGroup(declarative.SectionPackageHolds) != SectionGroup(declarative.SectionSettingsUpdates) ||
		SectionGroup(declarative.SectionManagedFiles) == SectionGroup(declarative.SectionManagedUnits) ||
		SectionGroup(declarative.SectionManagedFiles) != declarative.SectionManagedFiles {
		t.Fatal("SectionGroup")
	}
}

// TestStagedKeysSkipGroupCascades (plan M11 amendment R6.13): the item changes of a renamed, deleted or created device
// group are never staged; other changes of the same plan are.
func TestStagedKeysSkipGroupCascades(t *testing.T) {
	plan := declarative.Plan{Changes: []declarative.Change{
		{Section: declarative.SectionDeviceGroups, Key: `["old"]`, Action: declarative.ActionDelete},
		{Section: declarative.SectionDeviceGroups, Key: `["new"]`, Action: declarative.ActionCreate},
		{Section: declarative.SectionDeviceGroups, Key: `["kept"]`, Action: declarative.ActionUpdate},
		{Section: declarative.SectionManagedFiles, Key: `["old","/etc/motd"]`, Action: declarative.ActionDelete},
		{Section: declarative.SectionManagedFiles, Key: `["new","/etc/motd"]`, Action: declarative.ActionCreate},
		{Section: declarative.SectionPackageHolds, Key: `["kept","openssl"]`, Action: declarative.ActionCreate},
	}}
	want := map[string]map[string]bool{declarative.SectionPackageHolds: {`["kept","openssl"]`: true}}
	if got := StagedKeys(plan); !reflect.DeepEqual(got, want) {
		t.Fatalf("StagedKeys = %v", got)
	}
	if got := StagedResourceIDs(plan); !reflect.DeepEqual(got, []string{"updates"}) {
		t.Fatalf("StagedResourceIDs = %v", got)
	}
	if !Touches(plan) || Touches(declarative.Plan{Changes: plan.Changes[:5]}) {
		t.Fatal("Touches")
	}
	if g, ok := KeyGroup(`["old","/etc/motd"]`); !ok || g != "old" {
		t.Fatal("KeyGroup")
	}
	if _, ok := KeyGroup(`[null,"/etc/motd"]`); ok {
		t.Fatal("KeyGroup of an item of every device")
	}
}
