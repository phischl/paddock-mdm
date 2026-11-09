package app_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/configrollout"
	"github.com/phischl/paddock-mdm/server/internal/domain/software"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// windowRollout is a staged software rollout (waves 50 and 100, 30 minutes) whose devices report the staged entry.
type windowRollout struct {
	rolloutHarness
	r     storedRollout
	entry uuid.UUID
}

func newWindowRollout(t *testing.T) windowRollout {
	t.Helper()
	h := newRolloutHarness(t)
	_, catalog := softwareUseCases(h.writeHarness)
	admin := principal.With(context.Background(), h.account(t, principal.RoleOrgAdmin, true))
	enableRollouts(t, h.writeHarness, []int{50, 100}, nil)
	entry, err := catalog.Create(admin, app.EntryInput{Name: "Browser",
		Packages: []software.PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "browser"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.CreateAssignment(admin, app.AssignmentInput{CatalogEntryID: &entry.ID, Intent: "required"}); err != nil {
		t.Fatal(err)
	}
	return windowRollout{rolloutHarness: h, r: h.rollout(t, h.lastChangeSet(t).id), entry: entry.ID}
}

// waveDevice adds a device of the first wave that applied the rollout's bundle.
func (w windowRollout) waveDevice(t *testing.T, at time.Time) uuid.UUID {
	t.Helper()
	d := w.device(t, w.r.id, 50, true)
	w.report(t, d, w.r.id, 1, "applied", "enforce", "", at)
	return d
}

// software stores the device's status of the staged entry: pending/outside_window while it waits for its window.
func (w windowRollout) software(t *testing.T, d uuid.UUID, state, reason string, at time.Time) {
	t.Helper()
	w.exec(t, `INSERT INTO device_software_status (device_id, organization_id, catalog_entry_id, package, intent, state, reason, reported_at)
		VALUES ($1, $2, $3, 'browser', 'required', $4, $5, $6)
		ON CONFLICT (device_id, catalog_entry_id, scope, username) DO UPDATE SET state = EXCLUDED.state, reason = EXCLUDED.reason,
		reported_at = EXCLUDED.reported_at`, d, w.org, w.entry, state, reason, at)
}

func (w windowRollout) evaluate(t *testing.T, at time.Time) storedRollout {
	t.Helper()
	if err := w.worker.Evaluate(w.system, at); err != nil {
		t.Fatal(err)
	}
	return w.rollout(t, w.r.changeSet)
}

func (w windowRollout) detail(t *testing.T) app.ConfigRolloutDetail {
	t.Helper()
	d, err := w.api.Get(w.admin, w.r.id)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func near(a, b time.Time) bool { return a.Sub(b).Abs() < time.Millisecond }

// TestRolloutWaveWaitsForNightlyWindow (architect decision A10-16, agent contract 6): a daytime change to devices whose
// window opens at night does not advance the wave while every device waits, however long past min_wave_minutes the
// worker evaluates. The device list shows them waiting. Once the window opens and they apply, the minimum wave duration
// counts from the first apply the worker saw.
func TestRolloutWaveWaitsForNightlyWindow(t *testing.T) {
	w := newWindowRollout(t)
	base := time.Now()
	a, b := w.waveDevice(t, base), w.waveDevice(t, base)
	w.software(t, a, "pending", "outside_window", base)
	w.software(t, b, "pending", "outside_window", base)

	for _, at := range []time.Duration{0, 2 * time.Hour, 10 * time.Hour} {
		if got := w.evaluate(t, base.Add(at)); got.status != configrollout.StatusRunning || got.current != 0 {
			t.Fatalf("the wave moved while every device waits for its window (+%v): %+v", at, got)
		}
	}
	if n := len(w.events(t, audit.CodeConfigRolloutAdvanced)) + len(w.events(t, audit.CodeConfigRolloutCompleted)); n != 0 {
		t.Fatalf("%d wave events before any device applied", n)
	}
	if c := w.detail(t).Counts; c.Eligible != 2 || c.Applied != 0 || c.Pending != 2 || c.Failed != 0 {
		t.Fatalf("waiting devices are pending, never failed: %+v", c)
	}
	devices, err := w.api.ListDevices(w.admin, w.r.id, app.ConfigRolloutDeviceQuery{Page: app.ListPage{Sort: "hostname", Limit: 100}})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range devices.Items {
		if !d.InWave || !d.WaitingForWindow || d.ReportOutcome != app.RolloutReportApplied {
			t.Fatalf("device list of a waiting device %+v", d)
		}
	}

	opened := base.Add(11 * time.Hour)
	w.software(t, a, "installed", "", opened)
	w.software(t, b, "installed", "", opened)
	if got := w.evaluate(t, opened); got.current != 0 {
		t.Fatalf("advanced at the first apply: %+v", got)
	}
	d := w.detail(t)
	if d.WaveFirstAppliedAt == nil || !near(*d.WaveFirstAppliedAt, opened) || d.WaveApplied != 2 {
		t.Fatalf("first apply %v, applied %d, want %v and 2", d.WaveFirstAppliedAt, d.WaveApplied, opened)
	}
	if got := w.evaluate(t, opened.Add(29*time.Minute)); got.current != 0 {
		t.Fatalf("advanced before min_wave_minutes since the first apply: %+v", got)
	}
	if got := w.evaluate(t, opened.Add(31*time.Minute)); got.status != configrollout.StatusRunning || got.current != 1 {
		t.Fatalf("not advanced after the applies: %+v", got)
	}
	devices, err = w.api.ListDevices(w.admin, w.r.id, app.ConfigRolloutDeviceQuery{Page: app.ListPage{Sort: "hostname", Limit: 100}})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range devices.Items {
		if d.WaitingForWindow {
			t.Fatalf("a device that installed is still waiting: %+v", d)
		}
	}
	if d := w.detail(t); d.WaveFirstAppliedAt != nil || d.WaveApplied != 0 {
		t.Fatalf("the next wave kept the first apply of the previous one: %+v", d.ConfigRollout)
	}
}

// TestRolloutMixedWave (A10-16): with some devices of the wave applied and one still waiting, the wave advances only
// once the applied share reaches the rollout's wave_success_threshold_percent (default 90); the waiting device is
// pending and never counts toward the failure threshold.
func TestRolloutMixedWave(t *testing.T) {
	w := newWindowRollout(t)
	base := time.Now()
	waiting := w.waveDevice(t, base)
	w.software(t, waiting, "pending", "outside_window", base)
	for range 2 {
		w.software(t, w.waveDevice(t, base), "installed", "", base)
	}
	if got := w.evaluate(t, base); got.current != 0 {
		t.Fatalf("advanced at once: %+v", got)
	}
	if got := w.evaluate(t, base.Add(2*time.Hour)); got.status != configrollout.StatusRunning || got.current != 0 {
		t.Fatalf("advanced with 2 of 3 applied and one waiting below 90 %%: %+v", got)
	}
	d := w.detail(t)
	if d.WaveSuccessThresholdPercent != 90 || d.StallWarningHours != 24 {
		t.Fatalf("rollout parameters %d/%d, want the defaults 90/24", d.WaveSuccessThresholdPercent, d.StallWarningHours)
	}
	if c := d.Counts; c.Applied != 2 || c.Pending != 1 || c.Failed != 0 {
		t.Fatalf("counts %+v", c)
	}
	w.exec(t, "UPDATE config_rollout SET wave_success_threshold_percent = 60 WHERE id = $1", w.r.id)
	if got := w.evaluate(t, base.Add(2*time.Hour)); got.current != 1 {
		t.Fatalf("not advanced with 2 of 3 applied at a threshold of 60 %%: %+v", got)
	}
}

// TestRolloutStallWarning (A10-16): a wave whose devices wait for their window gets one config_rollout.stalled event
// of the system once it went stall_warning_hours without a new apply; the warning forces nothing. A new apply ends the
// stall.
func TestRolloutStallWarning(t *testing.T) {
	w := newWindowRollout(t)
	base := time.Now()
	a, b := w.waveDevice(t, base), w.waveDevice(t, base)
	w.software(t, a, "pending", "outside_window", base)
	w.software(t, b, "pending", "outside_window", base)

	w.evaluate(t, base.Add(23*time.Hour))
	if n := len(w.events(t, audit.CodeConfigRolloutStalled)); n != 0 {
		t.Fatalf("%d stall warnings before 24 h", n)
	}
	for _, at := range []time.Duration{24*time.Hour + time.Minute, 30 * time.Hour} {
		if got := w.evaluate(t, base.Add(at)); got.status != configrollout.StatusRunning || got.current != 0 {
			t.Fatalf("the stall warning moved the rollout: %+v", got)
		}
	}
	stalled := w.events(t, audit.CodeConfigRolloutStalled)
	if len(stalled) != 1 {
		t.Fatalf("%d stall warnings, want 1", len(stalled))
	}
	ev := stalled[0]
	if ev.Outcome != audit.OutcomeSuccess || ev.Actor.Type != audit.ActorSystem || ev.Params["wave"] != 0.0 ||
		ev.Params["stall_warning_hours"] != 24.0 || ev.Params["wave_eligible"] != 2.0 || ev.Params["wave_applied"] != 0.0 ||
		ev.Params["waiting"] != 2.0 || ev.Params["awaiting_retry"] != 0.0 || ev.Params["stalled_since"] == nil || ev.Params["rollout_id"] != w.r.id.String() {
		t.Fatalf("stall warning %+v", ev)
	}
	if d := w.detail(t); d.StallWarnedAt == nil {
		t.Fatal("the warned stall is not stored")
	}
	if n := w.count(t, "SELECT count(*) FROM device_software_status WHERE device_id = ANY($1) AND state = 'pending'", []uuid.UUID{a, b}); n != 2 {
		t.Fatalf("the warning changed what the devices run: %d pending", n)
	}

	resumed := base.Add(31 * time.Hour)
	w.software(t, a, "installed", "", resumed)
	w.evaluate(t, resumed)
	if d := w.detail(t); d.StallWarnedAt != nil || !near(d.WaveProgressAt, resumed) {
		t.Fatalf("a new apply did not end the stall: %+v", d.ConfigRollout)
	}
}

// TestRolloutResumeRestartsObservation (architect decision A10-18, plan M11 amendment R6.14 (d)): a resume clears the
// wave's first apply, so a wave whose device applied long before the halt keeps its full minimum duration after the
// resume instead of advancing in the first worker round.
func TestRolloutResumeRestartsObservation(t *testing.T) {
	w := newWindowRollout(t)
	base := time.Now()
	w.software(t, w.waveDevice(t, base.Add(-3*time.Hour)), "installed", "", base.Add(-3*time.Hour))
	w.device(t, w.r.id, 50, true) // offline: never reports
	w.evaluate(t, base.Add(-2*time.Hour))
	if d := w.detail(t); d.WaveFirstAppliedAt == nil {
		t.Fatal("the first apply before the halt was not recorded")
	}
	if _, err := w.api.Halt(w.admin, w.r.id, "pause"); err != nil {
		t.Fatal(err)
	}
	resumed, err := w.api.Resume(w.admin, w.r.id)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.WaveFirstAppliedAt != nil || resumed.WaveApplied != 0 {
		t.Fatalf("the resume kept the wave's first apply: %+v", resumed)
	}
	at := resumed.WaveStartedAt
	if got := w.evaluate(t, at.Add(time.Minute)); got.status != configrollout.StatusRunning || got.current != 0 {
		t.Fatalf("advanced right after the resume: %+v", got)
	}
	if got := w.evaluate(t, at.Add(30*time.Minute)); got.current != 0 {
		t.Fatalf("advanced before min_wave_minutes since the resume: %+v", got)
	}
	if got := w.evaluate(t, at.Add(32*time.Minute)); got.status != configrollout.StatusRunning || got.current != 1 {
		t.Fatalf("not advanced after a full observation period: %+v", got)
	}
}

// TestRolloutResumeAfterFailures (A10-18): a wave halted on failures and resumed does not advance because the failures
// before the resume no longer count. The failed devices stay outstanding until they retry, and the minimum duration
// counts anew from the resume.
func TestRolloutResumeAfterFailures(t *testing.T) {
	w := newWindowRollout(t)
	w.exec(t, "UPDATE config_rollout SET failure_threshold_min = 2, failure_threshold_percent = 0 WHERE id = $1", w.r.id)
	base := time.Now()
	w.software(t, w.waveDevice(t, base), "installed", "", base)
	f1, f2 := w.waveDevice(t, base), w.waveDevice(t, base)
	w.software(t, f1, "failed", "", base)
	w.software(t, f2, "failed", "", base)
	if got := w.evaluate(t, base); got.status != configrollout.StatusHalted {
		t.Fatalf("not halted on two failures: %+v", got)
	}
	resumed, err := w.api.Resume(w.admin, w.r.id)
	if err != nil {
		t.Fatal(err)
	}
	at := resumed.WaveStartedAt
	for _, after := range []time.Duration{time.Minute, 2 * time.Hour} {
		if got := w.evaluate(t, at.Add(after)); got.status != configrollout.StatusRunning || got.current != 0 {
			t.Fatalf("advanced on failures the resume discarded (+%v): %+v", after, got)
		}
	}
	if c := w.detail(t).Counts; c.Failed != 0 || c.Applied != 1 || c.Pending != 2 {
		t.Fatalf("counts after the resume %+v", c)
	}
	retried := time.Now()
	w.software(t, f1, "installed", "", retried)
	if got := w.evaluate(t, at.Add(2*time.Hour+time.Minute)); got.current != 0 {
		t.Fatalf("advanced with one discarded failure not retried: %+v", got)
	}
	w.software(t, f2, "installed", "", retried)
	if got := w.evaluate(t, at.Add(2*time.Hour+2*time.Minute)); got.status != configrollout.StatusRunning || got.current != 1 {
		t.Fatalf("not advanced after every failed device retried: %+v", got)
	}
}

// TestRolloutResumeAfterFailuresWaitsMinimum (A10-18): when every failed device retries right after the resume, the wave
// still waits for its minimum duration counted from the resume, not from the applies before the halt.
func TestRolloutResumeAfterFailuresWaitsMinimum(t *testing.T) {
	w := newWindowRollout(t)
	base := time.Now().Add(-2 * time.Hour)
	w.exec(t, `UPDATE config_rollout SET failure_threshold_min = 1, failure_threshold_percent = 0, evaluation_since = $2,
		wave_started_at = $2 WHERE id = $1`, w.r.id, base.Add(-time.Hour))
	f := w.waveDevice(t, base)
	w.software(t, w.waveDevice(t, base), "installed", "", base)
	w.software(t, f, "failed", "", base)
	if got := w.evaluate(t, base); got.status != configrollout.StatusHalted {
		t.Fatalf("not halted on the failure: %+v", got)
	}
	resumed, err := w.api.Resume(w.admin, w.r.id)
	if err != nil {
		t.Fatal(err)
	}
	at := resumed.WaveStartedAt
	w.software(t, f, "installed", "", time.Now())
	if got := w.evaluate(t, at.Add(time.Minute)); got.current != 0 {
		t.Fatalf("advanced right after the resume: %+v", got)
	}
	if got := w.evaluate(t, at.Add(32*time.Minute)); got.status != configrollout.StatusRunning || got.current != 1 {
		t.Fatalf("not advanced after the minimum duration since the resume: %+v", got)
	}
}

// TestRolloutNoStallWhileOnlyTimeOutstanding (A10-16 review 3): a wave whose devices all applied and that only waits for
// a min_wave_minutes longer than stall_warning_hours gets no stall warning.
func TestRolloutNoStallWhileOnlyTimeOutstanding(t *testing.T) {
	w := newWindowRollout(t)
	w.exec(t, "UPDATE config_rollout SET min_wave_minutes = 2880 WHERE id = $1", w.r.id)
	base := time.Now()
	for range 2 {
		w.software(t, w.waveDevice(t, base), "installed", "", base)
	}
	w.evaluate(t, base)
	if got := w.evaluate(t, base.Add(25*time.Hour)); got.status != configrollout.StatusRunning || got.current != 0 {
		t.Fatalf("advanced before min_wave_minutes: %+v", got)
	}
	if n := len(w.events(t, audit.CodeConfigRolloutStalled)); n != 0 {
		t.Fatalf("%d stall warnings for a wave that only waits for its minimum duration", n)
	}
}

// TestRolloutResumeIgnoresAppliesBeforeTheResume (A10-18): applies from before a halt do not count toward the wave's
// success threshold after the resume, so a wave that still has a device waiting for its window does not advance on them.
// Once nothing waits any more it advances.
func TestRolloutResumeIgnoresAppliesBeforeTheResume(t *testing.T) {
	w := newWindowRollout(t)
	w.exec(t, "UPDATE config_rollout SET wave_success_threshold_percent = 60 WHERE id = $1", w.r.id)
	base := time.Now().Add(-3 * time.Hour)
	waiting := w.waveDevice(t, base)
	w.software(t, waiting, "pending", "outside_window", base)
	for range 2 {
		w.software(t, w.waveDevice(t, base), "installed", "", base)
	}
	if _, err := w.api.Halt(w.admin, w.r.id, "pause"); err != nil {
		t.Fatal(err)
	}
	resumed, err := w.api.Resume(w.admin, w.r.id)
	if err != nil {
		t.Fatal(err)
	}
	at := resumed.WaveStartedAt
	w.evaluate(t, at.Add(time.Minute))
	if got := w.evaluate(t, at.Add(2*time.Hour)); got.status != configrollout.StatusRunning || got.current != 0 {
		t.Fatalf("advanced on applies from before the resume: %+v", got)
	}
	w.software(t, waiting, "installed", "", time.Now())
	if got := w.evaluate(t, at.Add(2*time.Hour+time.Minute)); got.status != configrollout.StatusRunning || got.current != 1 {
		t.Fatalf("not advanced once no device waits: %+v", got)
	}
}
