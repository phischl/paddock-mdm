package app_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/configrollout"
	"github.com/phischl/paddock-mdm/server/internal/domain/declarative"
	"github.com/phischl/paddock-mdm/server/internal/domain/software"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// accountingFile is the managed file the accounting rollout stages next to its software entries.
const accountingFile = "/etc/acme/accounting.conf"

// accountingRollout is the fixture of the A10-19 accounting table (§7): waves 50/100, min_wave_minutes 30,
// failure_threshold_min 1 (percent 0), wave_success_threshold_percent 90, one declarative change set that stages a
// managed file and the organization assignments of the catalog entries Browser and Editor.
type accountingRollout struct {
	rolloutHarness
	r              storedRollout
	browser, other uuid.UUID
	versions       map[uuid.UUID]int
}

func newAccountingRollout(t *testing.T) *accountingRollout {
	t.Helper()
	h := newRolloutHarness(t)
	_, catalog := softwareUseCases(h.writeHarness)
	account := h.account(t, principal.RoleOrgAdmin, true)
	admin := principal.With(context.Background(), account)
	ids := map[string]uuid.UUID{}
	for _, name := range []string{"Browser", "Editor"} {
		e, err := catalog.Create(admin, app.EntryInput{Name: name,
			Packages: []software.PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: strings.ToLower(name)}}})
		if err != nil {
			t.Fatal(err)
		}
		ids[name] = e.ID
	}
	enableRollouts(t, h.writeHarness, []int{50, 100}, nil)
	doc := h.export(t, account)
	if doc.ManagedFiles == nil {
		doc.ManagedFiles = &[]declarative.ManagedFile{}
	}
	if doc.SoftwareAssignments == nil {
		doc.SoftwareAssignments = &[]declarative.SoftwareAssignment{}
	}
	*doc.ManagedFiles = append(*doc.ManagedFiles,
		declarative.ManagedFile{Path: accountingFile, Mode: "0644", Owner: "root", Group: "root", Content: "x"})
	for _, name := range []string{"Browser", "Editor"} {
		*doc.SoftwareAssignments = append(*doc.SoftwareAssignments,
			declarative.SoftwareAssignment{Entry: name, Target: declarative.SoftwareTarget{Type: "organization"}, Intent: "required"})
	}
	if _, _, err := h.config.Apply(admin, raw(t, doc), ""); err != nil {
		t.Fatal(err)
	}
	a := &accountingRollout{rolloutHarness: h, r: h.rollout(t, h.lastChangeSet(t).id), browser: ids["Browser"], other: ids["Editor"],
		versions: map[uuid.UUID]int{}}
	if !a.r.present || a.r.status != configrollout.StatusRunning {
		t.Fatalf("no running rollout: %+v", a.r)
	}
	want := []string{"file:" + accountingFile, app.SoftwareResourcePrefix + a.browser.String(), app.SoftwareResourcePrefix + a.other.String()}
	slices.Sort(want)
	if got := a.detail(t).StagedResourceIDs; !slices.Equal(got, want) {
		t.Fatalf("staged resources %v, want %v", got, want)
	}
	a.exec(t, `UPDATE config_rollout SET failure_threshold_min = 1, failure_threshold_percent = 0, min_wave_minutes = 30,
		wave_success_threshold_percent = 90 WHERE id = $1`, a.r.id)
	return a
}

// device adds an active enforce device: earlier true puts its bucket below 50 (it joins in wave 0), false at or above
// 50 (it joins in wave 1).
func (a *accountingRollout) device(t *testing.T, earlier bool) uuid.UUID {
	t.Helper()
	return a.rolloutHarness.device(t, a.r.id, 50, earlier)
}

// apply stores a new enforced report of d on a bundle of the rollout, received at at: failed names the managed file
// as failed, and the software statuses of both entries are set as given (state/reason of Browser, then of Editor).
func (a *accountingRollout) apply(t *testing.T, d uuid.UUID, failedFile bool, browser, other [2]string, at time.Time) {
	t.Helper()
	a.versions[d]++
	failed := ""
	if failedFile {
		failed = "file:" + accountingFile
	}
	a.report(t, d, a.r.id, a.versions[d], "applied", "enforce", failed, at)
	for entry, s := range map[uuid.UUID][2]string{a.browser: browser, a.other: other} {
		a.exec(t, `INSERT INTO device_software_status (device_id, organization_id, catalog_entry_id, package, intent, state, reason, reported_at)
			VALUES ($1, $2, $3, 'pkg', 'required', $4, $5, $6)
			ON CONFLICT (device_id, catalog_entry_id, scope, username) DO UPDATE SET state = EXCLUDED.state, reason = EXCLUDED.reason,
			reported_at = EXCLUDED.reported_at`, d, a.org, entry, s[0], s[1], at)
	}
}

var (
	installed     = [2]string{"installed", ""}
	outsideWindow = [2]string{"pending", "outside_window"}
)

// ok stores a successful apply of d at at; fail one with the staged managed file failed.
func (a *accountingRollout) ok(t *testing.T, d uuid.UUID, at time.Time) {
	t.Helper()
	a.apply(t, d, false, installed, installed, at)
}

func (a *accountingRollout) fail(t *testing.T, d uuid.UUID, at time.Time) {
	t.Helper()
	a.apply(t, d, true, installed, installed, at)
}

func (a *accountingRollout) evaluate(t *testing.T, at time.Time) storedRollout {
	t.Helper()
	if err := a.worker.Evaluate(a.system, at); err != nil {
		t.Fatal(err)
	}
	return a.rollout(t, a.r.changeSet)
}

func (a *accountingRollout) detail(t *testing.T) app.ConfigRolloutDetail {
	t.Helper()
	d, err := a.api.Get(a.admin, a.r.id)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// advance moves the rollout to wave 1 by the administrator's override and returns the new wave's start.
func (a *accountingRollout) advance(t *testing.T) time.Time {
	t.Helper()
	r, err := a.api.Advance(a.admin, a.r.id)
	if err != nil {
		t.Fatal(err)
	}
	return r.WaveStartedAt
}

// resume resumes the halted rollout and returns the resume time (evaluation_since).
func (a *accountingRollout) resume(t *testing.T) time.Time {
	t.Helper()
	r, err := a.api.Resume(a.admin, a.r.id)
	if err != nil {
		t.Fatal(err)
	}
	return r.EvaluationSince
}

func (a *accountingRollout) devices(t *testing.T, q app.ConfigRolloutDeviceQuery) map[uuid.UUID]app.ConfigRolloutDevice {
	t.Helper()
	q.Page = app.ListPage{Sort: "hostname", Limit: 100}
	got, err := a.api.ListDevices(a.admin, a.r.id, q)
	if err != nil {
		t.Fatal(err)
	}
	out := map[uuid.UUID]app.ConfigRolloutDevice{}
	for _, d := range got.Items {
		out[d.DeviceID] = d
	}
	return out
}

func (a *accountingRollout) want(t *testing.T, got storedRollout, status string, wave int32, at string) {
	t.Helper()
	if got.status != status || got.current != wave {
		t.Fatalf("%s: %s in wave %d, want %s in wave %d", at, got.status, got.current, status, wave)
	}
}

func (a *accountingRollout) wantCounts(t *testing.T, want app.RolloutCounts) {
	t.Helper()
	if got := a.detail(t).Counts; got != want {
		t.Fatalf("counts %+v, want %+v", got, want)
	}
}

// a1 is the setup of row A1: the rollout in wave 1, device a of wave 0 failed the staged file, device b of wave 1
// applied and installed; the evaluation halts and the administrator resumes at the returned time.
func (a *accountingRollout) a1(t *testing.T, earlier int) (devs []uuid.UUID, b uuid.UUID, resumed time.Time) {
	t.Helper()
	a.advance(t)
	for range earlier {
		d := a.device(t, true)
		a.fail(t, d, time.Now())
		devs = append(devs, d)
	}
	b = a.device(t, false)
	a.ok(t, b, time.Now())
	a.want(t, a.evaluate(t, time.Now()), configrollout.StatusHalted, 1, "before the resume")
	return devs, b, a.resume(t)
}

// TestRolloutAccountingTable is the integration half of the A10-19 accounting table (plan M13c / M11 amendment
// 2026-11-09 §7): one subtest per row A1–A13, named by its ID. The binding invariant: a rollout never advances or
// completes without an observed success, and every device whose failure a resume discarded, in any reached wave, must
// re-apply successfully first.
func TestRolloutAccountingTable(t *testing.T) {
	t.Run("A1 wave-0 failure, halt, resume, +32 min: not completed", func(t *testing.T) {
		acc := newAccountingRollout(t)
		devs, b, at := acc.a1(t, 1)
		acc.want(t, acc.evaluate(t, at.Add(time.Minute)), configrollout.StatusRunning, 1, "T+1 min")
		acc.want(t, acc.evaluate(t, at.Add(32*time.Minute)), configrollout.StatusRunning, 1, "T+32 min")
		acc.wantCounts(t, app.RolloutCounts{Eligible: 2, Applied: 1, Pending: 1, AwaitingRetry: 1})
		list := acc.devices(t, app.ConfigRolloutDeviceQuery{})
		if d := list[devs[0]]; d.ReportOutcome != app.RolloutReportNone || !d.AwaitingRetry || len(d.FailedResourceIDs) != 0 {
			t.Fatalf("device a %+v", d)
		}
		if d := list[b]; d.ReportOutcome != app.RolloutReportApplied || d.AwaitingRetry {
			t.Fatalf("device b %+v", d)
		}
	})

	t.Run("A2 the discarded device retries successfully", func(t *testing.T) {
		acc := newAccountingRollout(t)
		devs, _, at := acc.a1(t, 1)
		acc.evaluate(t, at.Add(time.Minute))
		acc.ok(t, devs[0], at.Add(40*time.Minute))
		acc.want(t, acc.evaluate(t, at.Add(41*time.Minute)), configrollout.StatusCompleted, 1, "T+41 min")
	})

	t.Run("A3 the discarded device fails again", func(t *testing.T) {
		acc := newAccountingRollout(t)
		devs, _, at := acc.a1(t, 1)
		acc.evaluate(t, at.Add(time.Minute))
		acc.fail(t, devs[0], at.Add(40*time.Minute))
		acc.want(t, acc.evaluate(t, at.Add(41*time.Minute)), configrollout.StatusHalted, 1, "T+41 min")
	})

	t.Run("A3' fails again below the threshold", func(t *testing.T) {
		acc := newAccountingRollout(t)
		devs, _, at := acc.a1(t, 1)
		acc.exec(t, "UPDATE config_rollout SET failure_threshold_min = 2 WHERE id = $1", acc.r.id)
		acc.evaluate(t, at.Add(time.Minute))
		acc.fail(t, devs[0], at.Add(40*time.Minute))
		acc.want(t, acc.evaluate(t, at.Add(41*time.Minute)), configrollout.StatusRunning, 1, "T+41 min")
		acc.want(t, acc.evaluate(t, at.Add(71*time.Minute)), configrollout.StatusRunning, 1, "T+71 min")
		acc.wantCounts(t, app.RolloutCounts{Eligible: 2, Applied: 1, Failed: 1, AwaitingRetry: 1})
		d := acc.devices(t, app.ConfigRolloutDeviceQuery{})[devs[0]]
		if d.ReportOutcome != app.RolloutReportApplied || !slices.Equal(d.FailedResourceIDs, []string{"file:" + accountingFile}) ||
			!d.AwaitingRetry {
			t.Fatalf("device a %+v", d)
		}
	})

	t.Run("A4 a wave with failures only never advances", func(t *testing.T) {
		acc := newAccountingRollout(t)
		acc.exec(t, "UPDATE config_rollout SET failure_threshold_min = 5 WHERE id = $1", acc.r.id)
		base := time.Now()
		for range 3 {
			acc.fail(t, acc.device(t, true), base)
		}
		acc.evaluate(t, base)
		acc.want(t, acc.evaluate(t, base.Add(31*time.Minute)), configrollout.StatusRunning, 0, "+31 min")
		acc.wantCounts(t, app.RolloutCounts{Eligible: 3, Failed: 3})
		acc.want(t, acc.evaluate(t, base.Add(24*time.Hour+time.Minute)), configrollout.StatusRunning, 0, "+24 h")
		if n := len(acc.events(t, audit.CodeConfigRolloutStalled)); n != 1 {
			t.Fatalf("%d stall warnings, want 1", n)
		}
	})

	t.Run("A5 manual halt and resume of an applied wave", func(t *testing.T) {
		acc := newAccountingRollout(t)
		acc.ok(t, acc.device(t, true), time.Now())
		if _, err := acc.api.Halt(acc.admin, acc.r.id, "look"); err != nil {
			t.Fatal(err)
		}
		at := acc.resume(t)
		acc.want(t, acc.evaluate(t, at.Add(time.Minute)), configrollout.StatusRunning, 0, "+1 min")
		acc.want(t, acc.evaluate(t, at.Add(29*time.Minute)), configrollout.StatusRunning, 0, "+29 min")
		acc.want(t, acc.evaluate(t, at.Add(31*time.Minute)), configrollout.StatusRunning, 1, "+31 min")
	})

	t.Run("A6 an earlier-wave device waiting for its window", func(t *testing.T) {
		acc := newAccountingRollout(t)
		at := acc.advance(t)
		a := acc.device(t, true)
		acc.apply(t, a, false, outsideWindow, installed, at)
		acc.ok(t, acc.device(t, false), at)
		acc.device(t, false) // c: no report
		acc.evaluate(t, at)
		acc.want(t, acc.evaluate(t, at.Add(31*time.Minute)), configrollout.StatusRunning, 1, "T+31 min")
		acc.ok(t, a, at.Add(40*time.Minute))
		acc.want(t, acc.evaluate(t, at.Add(41*time.Minute)), configrollout.StatusCompleted, 1, "after a installed")
	})

	t.Run("A6' the share wins over an earlier-wave device waiting", func(t *testing.T) {
		acc := newAccountingRollout(t)
		at := acc.advance(t)
		acc.apply(t, acc.device(t, true), false, outsideWindow, installed, at)
		acc.ok(t, acc.device(t, false), at)
		acc.evaluate(t, at)
		acc.want(t, acc.evaluate(t, at.Add(31*time.Minute)), configrollout.StatusCompleted, 1, "T+31 min")
	})

	t.Run("A7 no eligible device", func(t *testing.T) {
		acc := newAccountingRollout(t)
		base := time.Now()
		acc.want(t, acc.evaluate(t, base.Add(31*time.Minute)), configrollout.StatusRunning, 1, "+31 min")
		acc.want(t, acc.evaluate(t, base.Add(62*time.Minute)), configrollout.StatusCompleted, 1, "+62 min")
	})

	t.Run("A8 a wave nobody joined still needs the retries", func(t *testing.T) {
		acc := newAccountingRollout(t)
		acc.advance(t)
		acc.fail(t, acc.device(t, true), time.Now())
		acc.want(t, acc.evaluate(t, time.Now()), configrollout.StatusHalted, 1, "before the resume")
		at := acc.resume(t)
		acc.want(t, acc.evaluate(t, at.Add(31*time.Minute)), configrollout.StatusRunning, 1, "T+31 min")
	})

	t.Run("A9 a discarded device that is retired no longer holds", func(t *testing.T) {
		acc := newAccountingRollout(t)
		devs, _, at := acc.a1(t, 1)
		acc.evaluate(t, at.Add(time.Minute))
		acc.exec(t, "UPDATE device SET state = 'retired' WHERE id = $1", devs[0])
		acc.want(t, acc.evaluate(t, at.Add(32*time.Minute)), configrollout.StatusCompleted, 1, "T+32 min")
		if c := acc.detail(t).Counts; c.AwaitingRetry != 0 {
			t.Fatalf("counts %+v", c)
		}
	})

	t.Run("A10 an offline device does not hold", func(t *testing.T) {
		acc := newAccountingRollout(t)
		base := time.Now()
		acc.ok(t, acc.device(t, true), base)
		acc.device(t, true)
		acc.evaluate(t, base)
		acc.want(t, acc.evaluate(t, base.Add(31*time.Minute)), configrollout.StatusRunning, 1, "+31 min")
	})

	t.Run("A10' every device offline", func(t *testing.T) {
		acc := newAccountingRollout(t)
		base := time.Now()
		acc.device(t, true)
		acc.device(t, true)
		acc.want(t, acc.evaluate(t, base.Add(31*time.Minute)), configrollout.StatusRunning, 0, "+31 min")
		acc.want(t, acc.evaluate(t, base.Add(24*time.Hour+time.Minute)), configrollout.StatusRunning, 0, "+24 h")
		if n := len(acc.events(t, audit.CodeConfigRolloutStalled)); n != 1 {
			t.Fatalf("%d stall warnings, want 1", n)
		}
	})

	t.Run("A11 an urgent staged assignment bypasses the window only", func(t *testing.T) {
		acc := newAccountingRollout(t)
		acc.exec(t, "UPDATE software_assignment SET urgent = true WHERE catalog_entry_id = $1", acc.browser)
		base := time.Now()
		urgent, waiting := acc.device(t, true), acc.device(t, true)
		acc.ok(t, urgent, base)
		acc.apply(t, waiting, false, installed, outsideWindow, base)
		acc.wantCounts(t, app.RolloutCounts{Eligible: 2, Applied: 1, Pending: 1, Waiting: 1})
		list := acc.devices(t, app.ConfigRolloutDeviceQuery{})
		if d := list[urgent]; d.ReportOutcome != app.RolloutReportApplied || d.WaitingForWindow {
			t.Fatalf("urgent device %+v", d)
		}
		if d := list[waiting]; d.ReportOutcome != app.RolloutReportApplied || !d.WaitingForWindow {
			t.Fatalf("waiting device %+v", d)
		}
	})

	t.Run("A12 device-list filters", func(t *testing.T) {
		acc := newAccountingRollout(t)
		devs, _, _ := acc.a1(t, 1)
		yes := true
		for name, q := range map[string]app.ConfigRolloutDeviceQuery{
			"awaiting_retry=true": {AwaitingRetry: &yes},
			"report_outcome=none": {ReportOutcomes: []string{app.RolloutReportNone}},
		} {
			got := acc.devices(t, q)
			d, ok := got[devs[0]]
			if len(got) != 1 || !ok || !d.InWave || d.WaitingForWindow || !d.AwaitingRetry {
				t.Fatalf("%s: %+v", name, got)
			}
		}
	})

	t.Run("A13 a shrinking retry list is stall progress", func(t *testing.T) {
		acc := newAccountingRollout(t)
		devs, _, at := acc.a1(t, 2)
		acc.evaluate(t, at.Add(time.Minute))
		acc.ok(t, devs[0], at.Add(10*time.Hour))
		acc.want(t, acc.evaluate(t, at.Add(10*time.Hour)), configrollout.StatusRunning, 1, "T+10 h")
		if d := acc.detail(t); d.Counts.AwaitingRetry != 1 || !near(d.WaveProgressAt, at.Add(10*time.Hour)) {
			t.Fatalf("after a1 retried: counts %+v, progress at %v", d.Counts, d.WaveProgressAt)
		}
		acc.evaluate(t, at.Add(25*time.Hour))
		if n := len(acc.events(t, audit.CodeConfigRolloutStalled)); n != 0 {
			t.Fatalf("%d stall warnings at T+25 h", n)
		}
		acc.want(t, acc.evaluate(t, at.Add(35*time.Hour)), configrollout.StatusRunning, 1, "T+35 h")
		stalled := acc.events(t, audit.CodeConfigRolloutStalled)
		if len(stalled) != 1 {
			t.Fatalf("%d stall warnings, want 1", len(stalled))
		}
		if p := stalled[0].Params; p["awaiting_retry"] != 1.0 || p["waiting"] != 0.0 || p["wave_applied"] != 1.0 {
			t.Fatalf("stall params %+v", p)
		}
	})
}
