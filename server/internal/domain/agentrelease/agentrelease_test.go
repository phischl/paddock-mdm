package agentrelease

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestValidate(t *testing.T) {
	for _, v := range append([]string{"1.0.0", "0.4.12-rc.1", "2.0.0+build.7"}, alphaSequence...) {
		if ValidateVersion(v) != nil {
			t.Errorf("%s rejected", v)
		}
	}
	for _, v := range []string{"", "1.0", "v1.0.0", "1.0.0/../x", "1.0.0 ", "1.0.0-" + string(make([]byte, 64))} {
		if ValidateVersion(v) == nil {
			t.Errorf("%q accepted", v)
		}
	}
	if ValidateArch("amd64") != nil || ValidateArch("arm64") != nil || ValidateArch("386") == nil {
		t.Error("arch validation")
	}
	if ValidatePackage("paddock-agent", "") != nil || ValidatePackage("paddock-supervisor", "") != nil ||
		ValidatePackage("fleet-osquery", "1.48.0") != nil || ValidatePackage("../x", "") == nil {
		t.Error("package validation")
	}
	// fleet-osquery needs its fleetd version, the others carry the release version.
	for _, c := range []struct{ name, version string }{{"fleet-osquery", ""}, {"fleet-osquery", "1.48"},
		{"fleet-osquery", "1.48.0/../x"}, {"paddock-agent", "1.48.0"}} {
		if ValidatePackage(c.name, c.version) == nil {
			t.Errorf("package %s version %q accepted", c.name, c.version)
		}
	}
	if k := PackageObjectKey("1.2.0", "paddock-agent", "", "amd64"); k != "packages/1.2.0/paddock-agent_1.2.0_amd64.deb" {
		t.Errorf("package object key %s", k)
	}
	if k := PackageObjectKey("1.2.0", "fleet-osquery", "1.48.0", "amd64"); k != "packages/1.2.0/fleet-osquery_1.48.0_amd64.deb" {
		t.Errorf("fleetd package object key %s", k)
	}
	for _, w := range [][]int{{100}, {1, 10, 50, 100}, {5, 100}} {
		if ValidateWaves(w) != nil {
			t.Errorf("waves %v rejected", w)
		}
	}
	for _, w := range [][]int{{}, {50}, {10, 10, 100}, {50, 10, 100}, {0, 100}, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 100}} {
		if ValidateWaves(w) == nil {
			t.Errorf("waves %v accepted", w)
		}
	}
}

func TestBucket(t *testing.T) {
	// Reference values (FNV-1a computed independently); the SQL function paddock_rollout_bucket must agree.
	for id, want := range map[string]int{
		"00000000-0000-0000-0000-000000000000": 57,
		"0190f000-0000-7000-8000-00000000000d": 94,
		"ffffffff-ffff-ffff-ffff-ffffffffffff": 33,
	} {
		if got := Bucket(uuid.MustParse(id)); got != want || got < 0 || got > 99 {
			t.Errorf("%s: %d", id, got)
		}
	}
	counts := make([]int, 100)
	for range 10000 {
		counts[Bucket(uuid.New())]++
	}
	for b, n := range counts {
		if n < 50 || n > 160 {
			t.Fatalf("bucket %d has %d of 10000 devices; the distribution is not uniform", b, n)
		}
	}
	if !Eligible(uuid.Nil, 100) || Eligible(uuid.Nil, 0) {
		t.Error("100 % must include and 0 % exclude every device")
	}
}

func TestThreshold(t *testing.T) {
	cases := []struct {
		eligible         int64
		percent, minimum int
		want             int64
	}{
		{2, 2, 1, 1}, {2, 2, 3, 3}, {1000, 2, 3, 20}, {101, 2, 3, 3}, {151, 2, 3, 4}, {0, 2, 0, 0},
	}
	for _, c := range cases {
		if got := Threshold(c.eligible, c.percent, c.minimum); got != c.want {
			t.Errorf("Threshold(%d, %d, %d) = %d, want %d", c.eligible, c.percent, c.minimum, got, c.want)
		}
	}
}

func TestDecide(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	base := Rollout{Waves: []int{1, 10, 100}, WaveStartedAt: now.Add(-time.Hour), MinWaveMinutes: 60, FailurePercent: 2,
		FailureMin: 3, Status: RolloutRunning, Eligible: 100}
	with := func(f func(*Rollout)) Rollout { r := base; f(&r); return r }
	cases := []struct {
		name string
		r    Rollout
		want Decision
	}{
		{"wave done", base, Advance},
		{"wave too young", with(func(r *Rollout) { r.WaveStartedAt = now.Add(-59 * time.Minute) }), Keep},
		{"last wave done", with(func(r *Rollout) { r.CurrentWave = 2 }), Complete},
		{"below threshold", with(func(r *Rollout) { r.Failed = 2 }), Advance},
		{"threshold reached", with(func(r *Rollout) { r.Failed = 3 }), Halt},
		{"one below the percentage threshold", with(func(r *Rollout) { r.Eligible = 1000; r.Failed = 19 }), Advance},
		{"at the percentage threshold", with(func(r *Rollout) { r.Eligible = 1000; r.Failed = 20 }), Halt},
		{"first failure with minimum 1 (gate S5)", with(func(r *Rollout) { r.FailureMin = 1; r.Eligible = 2; r.Failed = 1 }), Halt},
		{"no failures with minimum 0", with(func(r *Rollout) { r.FailureMin = 0; r.Eligible = 0 }), Advance},
		{"halted", with(func(r *Rollout) { r.Status = RolloutHalted; r.Failed = 3 }), Keep},
		{"completed below threshold", with(func(r *Rollout) { r.Status = RolloutCompleted; r.CurrentWave = 2; r.Failed = 2 }), Keep},
		{"completed at threshold", with(func(r *Rollout) { r.Status = RolloutCompleted; r.CurrentWave = 2; r.Failed = 3 }), Halt},
		{"completed at the percentage threshold", with(func(r *Rollout) {
			r.Status = RolloutCompleted
			r.CurrentWave = 2
			r.Eligible = 1000
			r.Failed = 20
		}), Halt},
		{"completed without failures", with(func(r *Rollout) { r.Status = RolloutCompleted; r.CurrentWave = 2; r.FailureMin = 0 }), Keep},
	}
	for _, c := range cases {
		if got := Decide(c.r, now); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestCurrentReleaseSince(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	week := now.Add(-CurrentReleaseWindow)
	if got := CurrentReleaseSince(now.Add(-30*24*time.Hour), now); !got.Equal(week) {
		t.Errorf("old rollout: %s, want the 7-day window %s", got, week)
	}
	resumed := now.Add(-time.Hour)
	if got := CurrentReleaseSince(resumed, now); !got.Equal(resumed) {
		t.Errorf("resumed an hour ago: %s, want the resume %s", got, resumed)
	}
}

func TestPercent(t *testing.T) {
	if Percent(RolloutRunning, []int{1, 10, 100}, 1) != 10 || Percent(RolloutCompleted, []int{1}, 0) != 100 ||
		Percent(RolloutHalted, []int{100}, 0) != 0 {
		t.Error("percent")
	}
}

// alphaSequence is the release order of Paddock's pre-releases (PDK-022).
var alphaSequence = []string{"0.1.0-alpha.1", "0.1.0-alpha.2", "0.1.0-beta.1", "0.1.0-rc.1", "0.1.0"}

// TestOfferForPreReleases: the offer compares the device's version only for equality (the supervisor refuses what is
// not newer), so a device on any other pre-release of the sequence is offered the release and one on it is not.
func TestOfferForPreReleases(t *testing.T) {
	in := uuid.MustParse("0190f000-0000-7000-8000-00000000000d")
	for _, release := range alphaSequence {
		o := Offer{Version: release, Status: RolloutCompleted, Waves: []int{100}, Artifacts: map[string]Artifact{"amd64": {SHA256: "ab"}}}
		for _, running := range alphaSequence {
			if _, ok := o.For(in, "amd64", running); ok != (running != release) {
				t.Errorf("release %s, device on %s: offered %v", release, running, ok)
			}
		}
	}
}

func TestOfferFor(t *testing.T) {
	in := uuid.MustParse("0190f000-0000-7000-8000-00000000000d") // bucket 94
	o := Offer{Version: "1.1.0", Status: RolloutRunning, Waves: []int{50, 100}, Artifacts: map[string]Artifact{"amd64": {SHA256: "ab"}}}
	if _, ok := o.For(in, "amd64", "1.0.0"); ok {
		t.Error("bucket 94 offered in a 50 % wave")
	}
	o.CurrentWave = 1
	if a, ok := o.For(in, "amd64", "1.0.0"); !ok || a.SHA256 != "ab" {
		t.Error("not offered in the 100 % wave")
	}
	if _, ok := o.For(in, "amd64", "1.1.0"); ok {
		t.Error("offered to a device that runs the version")
	}
	if _, ok := o.For(in, "arm64", "1.0.0"); ok {
		t.Error("offered without an artifact for the arch")
	}
	o.Status = RolloutHalted
	if _, ok := o.For(in, "amd64", "1.0.0"); ok {
		t.Error("offered by a halted rollout")
	}
}
