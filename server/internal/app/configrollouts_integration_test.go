package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/configrollout"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// rolloutHarness is a writeHarness with the rollout use cases of the api and of the worker (role paddock_worker).
type rolloutHarness struct {
	writeHarness
	api, worker *app.ConfigRollouts
	admin       context.Context
	system      context.Context
}

func newRolloutHarness(t *testing.T) rolloutHarness {
	t.Helper()
	h := newWriteHarness(t)
	env := pgtest.SharedPaddock(t)
	workerPool, err := db.NewOrgPool(context.Background(), env.Worker, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(workerPool.Close)
	platform, err := db.NewPlatformPool(context.Background(), env.Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	runner := app.NewActionRunner(workerPool, platform, func(context.Context) string { return "corr-" + t.Name() })
	return rolloutHarness{
		writeHarness: h, api: app.NewConfigRollouts(h.runner, h.pool), worker: app.NewConfigRollouts(runner, workerPool),
		admin:  principal.With(context.Background(), h.account(t, principal.RoleOrgAdmin, false)),
		system: principal.With(context.Background(), principal.Principal{Kind: principal.KindSystem, Display: "worker", OrganizationID: h.org}),
	}
}

// stage creates a managed file with rollouts enabled and returns the rollout it started.
func (h rolloutHarness) stage(t *testing.T, path string) storedRollout {
	t.Helper()
	if _, err := h.files.CreateFile(h.admin, app.FileInput{Path: strPtr(path), Content: strPtr("x")}); err != nil {
		t.Fatal(err)
	}
	r := h.rollout(t, h.lastChangeSet(t).id)
	if !r.present || r.status != configrollout.StatusRunning {
		t.Fatalf("no running rollout: %+v", r)
	}
	return r
}

func (h rolloutHarness) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := h.super.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// device inserts an active device whose bucket in rollout is inside percent (in true) or outside it.
func (h rolloutHarness) device(t *testing.T, rollout uuid.UUID, percent int, in bool) uuid.UUID {
	t.Helper()
	for {
		d := uuid.Must(uuid.NewV7())
		if (configrollout.Bucket(d, rollout) < percent) == in {
			h.exec(t, "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, $3, 'active')", d, h.org, "h-"+d.String())
			return d
		}
	}
}

// report stores bundle version of device d carrying rollout (uuid.Nil: none), its report and a failed resource.
func (h rolloutHarness) report(t *testing.T, d, rollout uuid.UUID, version int, outcome, mode, failed string, at time.Time) {
	t.Helper()
	carries := uuid.NullUUID{UUID: rollout, Valid: rollout != uuid.Nil}
	h.exec(t, `INSERT INTO bundle (device_id, version, organization_id, content_sha256, envelope_sha256, object_key, schema_version, config_rollout_id)
		VALUES ($1, $2, $3, '\x00', '\x00', 'k', 2, $4)`, d, version, h.org, carries)
	h.exec(t, `INSERT INTO device_bundle_report (device_id, organization_id, version, outcome, mode, occurred_at) VALUES ($1, $2, $3, $4, $5, $6)`,
		d, h.org, version, outcome, mode, at)
	if failed != "" {
		h.exec(t, `INSERT INTO device_resource_status (device_id, organization_id, resource_id, status, bundle_version, occurred_at)
			VALUES ($1, $2, $3, 'failed', $4, $5) ON CONFLICT (device_id, resource_id) DO UPDATE SET bundle_version = excluded.bundle_version`,
			d, h.org, failed, version, at)
	}
}

// events returns the audit events of the test with code.
func (h rolloutHarness) events(t *testing.T, code audit.Code) []audit.Event {
	t.Helper()
	_, all := h.recorded(t, "corr-"+t.Name())
	var out []audit.Event
	for _, ev := range all {
		if ev.Code == code {
			out = append(out, ev)
		}
	}
	return out
}

func (h rolloutHarness) stateChanges(t *testing.T) int {
	t.Helper()
	return h.count(t, "SELECT count(*) FROM outbox WHERE organization_id = $1 AND subject = $2", h.org, "state."+h.org.String())
}

// TestConfigRolloutActions (plan M11 decision 32, amendment R6.13): halt needs a reason, resume, advance and complete
// change the status as allowed and are refused otherwise with invalid_state; each attempt is one audited event; an
// auditor is denied and a rollout of another organization is not_found. Rollouts are switched off after the start:
// the open rollout keeps its rules and every action still works.
func TestConfigRolloutActions(t *testing.T) {
	h := newRolloutHarness(t)
	enableRollouts(t, h.writeHarness, []int{10, 50, 100}, nil)
	r := h.stage(t, "/etc/acme/actions.conf")
	h.exec(t, "UPDATE organization_rollout_settings SET enabled = false WHERE organization_id = $1", h.org)

	if _, err := h.api.Halt(h.admin, r.id, " x "); !errors.Is(err, problem.InvalidRequest) {
		t.Fatalf("halt with a one-character reason = %v", err)
	}
	if _, err := h.api.Resume(h.admin, r.id); !errors.Is(err, problem.InvalidState) {
		t.Fatalf("resume of a running rollout = %v", err)
	}
	halted, err := h.api.Halt(h.admin, r.id, "  broken motd  ")
	if err != nil || halted.Status != configrollout.StatusHalted || halted.HaltedReason == nil || *halted.HaltedReason != "broken motd" {
		t.Fatalf("halt = %+v, %v", halted, err)
	}
	if _, err := h.api.Advance(h.admin, r.id); !errors.Is(err, problem.InvalidState) {
		t.Fatalf("advance of a halted rollout = %v", err)
	}
	resumed, err := h.api.Resume(h.admin, r.id)
	if err != nil || resumed.Status != configrollout.StatusRunning || resumed.HaltedReason != nil || !resumed.EvaluationSince.After(halted.EvaluationSince) {
		t.Fatalf("resume = %+v, %v", resumed, err)
	}
	before := h.stateChanges(t)
	for want := 1; want <= 2; want++ {
		adv, err := h.api.Advance(h.admin, r.id)
		if err != nil || int(adv.CurrentWaveIndex) != want {
			t.Fatalf("advance %d = %+v, %v", want, adv, err)
		}
	}
	if n := h.stateChanges(t); n != before+2 {
		t.Fatalf("%d state changes after two advances, want %d", n, before+2)
	}
	if _, err := h.api.Advance(h.admin, r.id); !errors.Is(err, problem.InvalidState) {
		t.Fatalf("advance in the last wave = %v", err)
	}

	auditor := principal.With(context.Background(), h.account(t, principal.RoleOrgAuditor, false))
	if _, err := h.api.Complete(auditor, r.id); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("complete by an auditor = %v", err)
	}
	other := newRolloutHarness(t)
	if _, err := other.api.Complete(other.admin, r.id); !errors.Is(err, problem.NotFound) {
		t.Fatalf("complete of another organization's rollout = %v", err)
	}
	if _, err := other.api.Get(other.admin, r.id); !errors.Is(err, problem.NotFound) {
		t.Fatalf("get of another organization's rollout = %v", err)
	}

	done, err := h.api.Complete(h.admin, r.id)
	if err != nil || done.Status != configrollout.StatusCompleted || done.EndedAt == nil || done.EndedReason == nil ||
		*done.EndedReason != "completed by org_admin admin" {
		t.Fatalf("complete = %+v, %v", done, err)
	}
	if _, err := h.api.Complete(h.admin, r.id); !errors.Is(err, problem.InvalidState) {
		t.Fatalf("complete of a completed rollout = %v", err)
	}

	want := map[audit.Code][]audit.Outcome{
		audit.CodeConfigRolloutHalted:   {audit.OutcomeFailure, audit.OutcomeSuccess},
		audit.CodeConfigRolloutResumed:  {audit.OutcomeFailure, audit.OutcomeSuccess},
		audit.CodeConfigRolloutAdvanced: {audit.OutcomeFailure, audit.OutcomeSuccess, audit.OutcomeSuccess, audit.OutcomeFailure},
		// The not_found of the other organization shares the test's correlation ID.
		audit.CodeConfigRolloutCompleted: {audit.OutcomeDenied, audit.OutcomeFailure, audit.OutcomeSuccess, audit.OutcomeFailure},
	}
	for code, outcomes := range want {
		events := h.events(t, code)
		if len(events) != len(outcomes) {
			t.Fatalf("%s: %d events, want %d", code, len(events), len(outcomes))
		}
		for i, ev := range events {
			if ev.Outcome != outcomes[i] || ev.Params["rollout_id"] != r.id.String() || ev.Target == nil || ev.Target.Type != "config_rollout" {
				t.Errorf("%s event %d: %s %v", code, i, ev.Outcome, ev.Params)
			}
		}
	}
	if p := h.events(t, audit.CodeConfigRolloutAdvanced)[2].Params; p["wave"] != 2.0 || p["percent"] != 100.0 || p["manual"] != true ||
		p["change_set_id"] != r.changeSet.String() {
		t.Errorf("advanced params %v", p)
	}
	if p := h.events(t, audit.CodeConfigRolloutHalted)[1].Params; p["reason"] != "broken motd" || p["wave"] != 0.0 {
		t.Errorf("halted params %v", p)
	}
	if p := h.events(t, audit.CodeConfigRolloutCompleted)[2].Params; p["manual"] != true || p["wave"] != 2.0 {
		t.Errorf("completed params %v", p)
	}
}

// TestConfigRolloutCompleteFromHalted: a halted rollout completes, and a new change set of its section stages again.
func TestConfigRolloutCompleteFromHalted(t *testing.T) {
	h := newRolloutHarness(t)
	enableRollouts(t, h.writeHarness, []int{50, 100}, nil)
	r := h.stage(t, "/etc/acme/halted.conf")
	if _, err := h.api.Halt(h.admin, r.id, "stop"); err != nil {
		t.Fatal(err)
	}
	before := h.stateChanges(t)
	if done, err := h.api.Complete(h.admin, r.id); err != nil || done.Status != configrollout.StatusCompleted {
		t.Fatalf("complete = %+v, %v", done, err)
	}
	if n := h.stateChanges(t); n != before+1 {
		t.Fatalf("%d state changes, want %d", n, before+1)
	}
	if next := h.stage(t, "/etc/acme/next.conf"); next.id == r.id {
		t.Fatal("no new rollout")
	}
}

// TestConfigRolloutEvaluate (plan M11 decision 33): the worker halts a running rollout once its failed devices reach
// the threshold, counting only failures of staged resources reported since the start; a halted rollout is not
// evaluated; after the minimum wave duration it advances and after the last wave it completes, each one event of the
// system with a state change.
func TestConfigRolloutEvaluate(t *testing.T) {
	h := newRolloutHarness(t)
	enableRollouts(t, h.writeHarness, []int{50, 100}, nil)
	r := h.stage(t, "/etc/acme/eval.conf")
	staged := "file:/etc/acme/eval.conf"
	now := time.Now()

	a, b, c := h.device(t, r.id, 50, true), h.device(t, r.id, 50, true), h.device(t, r.id, 50, true)
	h.report(t, a, r.id, 1, "applied", "enforce", staged, now)
	h.report(t, b, r.id, 1, "applied", "enforce", "unit:other.service", now)
	h.report(t, c, r.id, 1, "applied", "enforce", staged, now.Add(-2*time.Hour))
	// Threshold max(2, 4 % of 3) = 2: one failure since the start, the others do not count.
	if err := h.worker.Evaluate(h.system, now); err != nil {
		t.Fatal(err)
	}
	if got := h.rollout(t, r.changeSet); got.status != configrollout.StatusRunning {
		t.Fatalf("halted with one counted failure: %+v", got)
	}
	h.report(t, b, r.id, 2, "rejected", "enforce", "", now)
	if err := h.worker.Evaluate(h.system, now); err != nil {
		t.Fatal(err)
	}
	if got := h.rollout(t, r.changeSet); got.status != configrollout.StatusHalted {
		t.Fatalf("not halted at the threshold: %+v", got)
	}
	halted := h.events(t, audit.CodeConfigRolloutHalted)
	if len(halted) != 1 {
		t.Fatalf("%d halted events, want 1", len(halted))
	}
	ev := halted[0]
	if ev.Outcome != audit.OutcomeSuccess || ev.Actor.Type != audit.ActorSystem || ev.Params["reason"] != "2 failed devices reached the threshold of 2" ||
		ev.Params["eligible"] != 3.0 || ev.Params["failed"] != 2.0 || ev.Params["threshold"] != 2.0 || ev.Params["wave"] != 0.0 ||
		ev.Params["change_set_id"] != r.changeSet.String() {
		t.Fatalf("halted event %+v", ev)
	}
	// A halted rollout is not evaluated, not even after its wave duration.
	if err := h.worker.Evaluate(h.system, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n := len(h.events(t, audit.CodeConfigRolloutHalted)) + len(h.events(t, audit.CodeConfigRolloutAdvanced)); n != 1 {
		t.Fatalf("%d events after evaluating a halted rollout", n)
	}

	// Resumed, the old failures no longer count: the wave advances after 30 minutes, then completes.
	if _, err := h.api.Resume(h.admin, r.id); err != nil {
		t.Fatal(err)
	}
	if err := h.worker.Evaluate(h.system, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := h.rollout(t, r.changeSet); got.status != configrollout.StatusRunning || got.current != 0 {
		t.Fatalf("changed before the wave duration: %+v", got)
	}
	before := h.stateChanges(t)
	if err := h.worker.Evaluate(h.system, time.Now().Add(31*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := h.rollout(t, r.changeSet); got.status != configrollout.StatusRunning || got.current != 1 {
		t.Fatalf("not advanced: %+v", got)
	}
	adv := h.events(t, audit.CodeConfigRolloutAdvanced)
	if len(adv) != 1 || adv[0].Actor.Type != audit.ActorSystem || adv[0].Params["wave"] != 1.0 || adv[0].Params["percent"] != 100.0 ||
		adv[0].Params["manual"] != false {
		t.Fatalf("advanced events %+v", adv)
	}
	if err := h.worker.Evaluate(h.system, time.Now().Add(62*time.Minute)); err != nil {
		t.Fatal(err)
	}
	done := h.rollout(t, r.changeSet)
	if done.status != configrollout.StatusCompleted || done.endedReason == nil || *done.endedReason != "every wave passed" {
		t.Fatalf("not completed: %+v", done)
	}
	if n := h.stateChanges(t); n != before+2 {
		t.Fatalf("%d state changes, want %d", n, before+2)
	}
	comp := h.events(t, audit.CodeConfigRolloutCompleted)
	if len(comp) != 1 || comp[0].Params["manual"] != false || comp[0].Actor.Type != audit.ActorSystem {
		t.Fatalf("completed events %+v", comp)
	}
	counts, err := h.worker.StatusCounts(h.system)
	if err != nil || counts[configrollout.StatusCompleted] != 1 || counts[configrollout.StatusRunning] != 0 {
		t.Fatalf("status counts %v, %v", counts, err)
	}
}

// TestConfigRolloutCountsAndDevices (plan M11 decision 34, amendment R6.6): Get and List count the devices in the
// wave, ListDevices marks in_wave, carries_rollout, the report and the failed staged resources; a report-only report is
// its own state and never a failure.
func TestConfigRolloutCountsAndDevices(t *testing.T) {
	h := newRolloutHarness(t)
	canary := h.group(t, h.org)
	enableRollouts(t, h.writeHarness, []int{50, 100}, &canary)
	r := h.stage(t, "/etc/acme/counts.conf")
	staged := "file:/etc/acme/counts.conf"
	now := time.Now()
	applied, failed, reportOnly, pending := h.device(t, r.id, 50, true), h.device(t, r.id, 50, true), h.device(t, r.id, 50, true), h.device(t, r.id, 50, true)
	outside, canaryDevice := h.device(t, r.id, 50, false), h.device(t, r.id, 50, false)
	h.exec(t, "INSERT INTO device_group_member (organization_id, device_group_id, device_id) VALUES ($1, $2, $3)", h.org, canary, canaryDevice)
	h.report(t, applied, r.id, 1, "applied", "enforce", "unit:other.service", now)
	h.report(t, failed, r.id, 1, "applied", "enforce", staged, now)
	h.report(t, reportOnly, r.id, 1, "applied", "report_only", staged, now)
	h.report(t, outside, uuid.Nil, 1, "applied", "enforce", "", now)

	d, err := h.api.Get(h.admin, r.id)
	if err != nil {
		t.Fatal(err)
	}
	want := app.RolloutCounts{Eligible: 5, Applied: 1, Failed: 1, Pending: 3}
	if d.Counts != want || d.ChangeSet.ID != r.changeSet || len(d.StagedResourceIDs) != 1 || d.StagedResourceIDs[0] != staged {
		t.Fatalf("detail counts %+v, staged %v", d.Counts, d.StagedResourceIDs)
	}
	list, err := h.api.List(h.admin, app.ListPage{Sort: "-started_at", Limit: 25}, []string{configrollout.StatusRunning})
	if err != nil || list.Count != 1 || len(list.Items) != 1 || list.Items[0].Counts != want {
		t.Fatalf("list %+v, %v", list, err)
	}
	if none, err := h.api.List(h.admin, app.ListPage{Sort: "status", Limit: 25}, []string{configrollout.StatusCompleted}); err != nil || none.Count != 0 {
		t.Fatalf("completed filter %+v, %v", none, err)
	}

	devices, err := h.api.ListDevices(h.admin, r.id, app.ConfigRolloutDeviceQuery{Page: app.ListPage{Sort: "hostname", Limit: 100}})
	if err != nil || devices.Count != 6 {
		t.Fatalf("devices %+v, %v", devices, err)
	}
	byID := map[uuid.UUID]app.ConfigRolloutDevice{}
	for _, dev := range devices.Items {
		byID[dev.DeviceID] = dev
	}
	check := func(name string, id uuid.UUID, inWave, carries bool, outcome string, failedIDs int) {
		t.Helper()
		dev := byID[id]
		if dev.InWave != inWave || dev.CarriesRollout != carries || dev.ReportOutcome != outcome || len(dev.FailedResourceIDs) != failedIDs {
			t.Errorf("%s: %+v", name, dev)
		}
	}
	check("applied", applied, true, true, "applied", 0)
	check("failed", failed, true, true, "applied", 1)
	check("report-only", reportOnly, true, true, "report_only", 1)
	check("pending", pending, true, false, "none", 0)
	check("outside", outside, false, false, "applied", 0)
	check("canary", canaryDevice, true, false, "none", 0)

	inWave := false
	out, err := h.api.ListDevices(h.admin, r.id, app.ConfigRolloutDeviceQuery{Page: app.ListPage{Sort: "-in_wave", Limit: 10}, InWave: &inWave})
	if err != nil || out.Count != 1 || out.Items[0].DeviceID != outside {
		t.Fatalf("in_wave=false %+v, %v", out, err)
	}
	ro, err := h.api.ListDevices(h.admin, r.id, app.ConfigRolloutDeviceQuery{Page: app.ListPage{Sort: "report_outcome", Limit: 10},
		ReportOutcomes: []string{app.RolloutReportReportOnly, app.RolloutReportNone}})
	if err != nil || ro.Count != 3 || ro.Items[0].ReportOutcome != app.RolloutReportNone || ro.Items[2].ReportOutcome != app.RolloutReportReportOnly {
		t.Fatalf("report_outcome filter %+v, %v", ro, err)
	}
	sorted, err := h.api.ListDevices(h.admin, r.id, app.ConfigRolloutDeviceQuery{Page: app.ListPage{Sort: "-in_wave", Limit: 10, Offset: 5}})
	if err != nil || sorted.Count != 6 || len(sorted.Items) != 1 || sorted.Items[0].DeviceID != outside {
		t.Fatalf("-in_wave page 2 %+v, %v", sorted, err)
	}
	if _, err := h.api.ListDevices(h.admin, uuid.Must(uuid.NewV7()), app.ConfigRolloutDeviceQuery{Page: app.ListPage{Sort: "hostname", Limit: 10}}); !errors.Is(err, problem.NotFound) {
		t.Fatalf("unknown rollout = %v", err)
	}
	if _, err := h.api.Complete(h.admin, r.id); err != nil {
		t.Fatal(err)
	}
	if d, err := h.api.Get(h.admin, r.id); err != nil || d.Counts.Eligible != 6 {
		t.Fatalf("completed counts %+v, %v", d.Counts, err)
	}
}
