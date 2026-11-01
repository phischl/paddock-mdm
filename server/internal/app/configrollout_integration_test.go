package app_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/configrollout"
	"github.com/phischl/paddock-mdm/server/internal/domain/declarative"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// enableRollouts switches staged rollouts on for the harness organization (plan M11 decision 23).
func enableRollouts(t *testing.T, h writeHarness, waves []int, canary *uuid.UUID) {
	t.Helper()
	if _, err := h.super.Exec(context.Background(), `INSERT INTO organization_rollout_settings (organization_id, enabled, waves,
		min_wave_minutes, failure_threshold_percent, failure_threshold_min, canary_device_group_id) VALUES ($1, true, $2, 30, 4, 2, $3)
		ON CONFLICT (organization_id) DO UPDATE SET enabled = true, waves = excluded.waves, canary_device_group_id = excluded.canary_device_group_id`,
		h.org, waves, canary); err != nil {
		t.Fatal(err)
	}
}

// storedRollout is a config_rollout row as the tests read it.
type storedRollout struct {
	id, changeSet       uuid.UUID
	status, startedBy   string
	waves               []int32
	current, minutes    int32
	percent, minimum    int32
	canary              *uuid.UUID
	endedReason         *string
	endedAtSet, present bool
}

func (h writeHarness) rollout(t *testing.T, changeSet uuid.UUID) storedRollout {
	t.Helper()
	var r storedRollout
	err := h.super.QueryRow(context.Background(), `SELECT id, change_set_id, status, started_by, waves, current_wave_index,
		min_wave_minutes, failure_threshold_percent, failure_threshold_min, canary_device_group_id, ended_reason, ended_at IS NOT NULL
		FROM config_rollout WHERE change_set_id = $1`, changeSet).Scan(&r.id, &r.changeSet, &r.status, &r.startedBy, &r.waves,
		&r.current, &r.minutes, &r.percent, &r.minimum, &r.canary, &r.endedReason, &r.endedAtSet)
	if err == nil {
		r.present = true
	}
	return r
}

func (h writeHarness) rollouts(t *testing.T) int {
	t.Helper()
	return h.count(t, "SELECT count(*) FROM config_rollout WHERE organization_id = $1", h.org)
}

func (h writeHarness) lastEvent(t *testing.T) map[string]any {
	t.Helper()
	_, events := h.recorded(t, h.corr)
	return events[len(events)-1].Params
}

// TestConfigRolloutBucketMatchesSQL (plan M11 decision 28): the Go bucket equals paddock_config_rollout_bucket for
// 1 000 random (device, rollout) pairs and the edge UUIDs.
func TestConfigRolloutBucketMatchesSQL(t *testing.T) {
	h := newHarness(t)
	devices := []uuid.UUID{uuid.Nil, uuid.MustParse("ffffffff-ffff-ffff-ffff-ffffffffffff")}
	rollouts := []uuid.UUID{uuid.Nil, uuid.Must(uuid.NewV7())}
	for range 998 {
		devices, rollouts = append(devices, uuid.New()), append(rollouts, uuid.Must(uuid.NewV7()))
	}
	rows, err := h.super.Query(context.Background(),
		"SELECT paddock_config_rollout_bucket(d, r) FROM unnest($1::uuid[], $2::uuid[]) WITH ORDINALITY AS u(d, r, n) ORDER BY n",
		devices, rollouts)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	i := 0
	for rows.Next() {
		var got int
		if err := rows.Scan(&got); err != nil {
			t.Fatal(err)
		}
		if want := configrollout.Bucket(devices[i], rollouts[i]); got != want {
			t.Fatalf("%s/%s: SQL %d, Go %d", devices[i], rollouts[i], got, want)
		}
		i++
	}
	if err := rows.Err(); err != nil || i != len(devices) {
		t.Fatalf("%d of %d pairs compared: %v", i, len(devices), err)
	}
}

// TestConfigRolloutStaging (plan M11 decisions 25, 27 and 31): with rollouts enabled a managed file write is staged
// and starts a running rollout with the settings' parameters; without rollouts it stays immediate.
func TestConfigRolloutStaging(t *testing.T) {
	h := newWriteHarness(t)
	ctx := principal.With(context.Background(), h.account(t, principal.RoleOrgAdmin, false))
	if _, err := h.files.CreateFile(ctx, app.FileInput{Path: strPtr("/etc/acme/before.conf"), Content: strPtr("x")}); err != nil {
		t.Fatal(err)
	}
	if cs := h.lastChangeSet(t); h.rollout(t, cs.id).present || h.lastEvent(t)["rollout"] != app.RolloutImmediate {
		t.Fatal("a write with rollouts disabled started a rollout")
	}

	canary := h.group(t, h.org)
	enableRollouts(t, h, []int{50, 100}, &canary)
	if _, err := h.files.CreateFile(ctx, app.FileInput{Path: strPtr("/etc/acme/staged.conf"), Content: strPtr("x")}); err != nil {
		t.Fatal(err)
	}
	cs := h.lastChangeSet(t)
	r := h.rollout(t, cs.id)
	if !r.present || r.status != configrollout.StatusRunning || r.current != 0 || !slices.Equal(r.waves, []int32{50, 100}) ||
		r.minutes != 30 || r.percent != 4 || r.minimum != 2 || r.canary == nil || *r.canary != canary || r.startedBy != "org_admin admin" {
		t.Fatalf("rollout %+v", r)
	}
	if p := h.lastEvent(t); p["rollout"] != app.RolloutStaged || p["rollout_id"] != r.id.String() || p["change_set_id"] != cs.id.String() {
		t.Fatalf("event params %v", p)
	}
	rec, err := h.config.GetChangeSet(ctx, cs.id)
	if err != nil || rec.Rollout != app.RolloutStaged || rec.RolloutID == nil || *rec.RolloutID != r.id {
		t.Fatalf("change set %+v, %v", rec, err)
	}
}

// TestConfigRolloutOpenRolloutRules (ADR 0033 E1, amendment 2026-11-01): while a rollout is open, a write touching a
// staged key is rollout_conflict, one touching a section the rollout stages is rollout_running (a mixed change set as a
// whole), and one touching only other sections is immediate; every refusal is one audited failure.
func TestConfigRolloutOpenRolloutRules(t *testing.T) {
	h := newWriteHarness(t)
	admin := h.account(t, principal.RoleOrgAdmin, false)
	ctx := principal.With(context.Background(), admin)
	enableRollouts(t, h, []int{10, 100}, nil)
	group := h.group(t, h.org)
	staged, err := h.files.CreateFile(ctx, app.FileInput{DeviceGroupID: &group, Path: strPtr("/etc/acme/staged.conf"), Content: strPtr("x")})
	if err != nil {
		t.Fatal(err)
	}
	rollout := h.rollout(t, h.lastChangeSet(t).id)
	changeSets := h.changeSets(t)

	refused := func(name, code string, want error, fn func() error) {
		t.Helper()
		var err error
		got := h.during(t, func() { err = fn() })
		if !errors.Is(err, want) || !slices.Equal(got, []string{code + ":failure:" + want.(*problem.Error).Code}) {
			t.Errorf("%s = %v, actions %v", name, err, got)
		}
	}
	refused("update of the staged file", "managed_file.updated", problem.RolloutConflict, func() error {
		_, err := h.files.UpdateFile(ctx, staged.ID, app.FileInput{Content: strPtr("y")})
		return err
	})
	refused("second managed file", "managed_file.created", problem.RolloutRunning, func() error {
		_, err := h.files.CreateFile(ctx, app.FileInput{Path: strPtr("/etc/acme/second.conf"), Content: strPtr("x")})
		return err
	})
	// A mixed apply that adds a unit and another file is refused as a whole, never split.
	doc := h.export(t, admin)
	units := append(*doc.ManagedUnits, declarative.ManagedUnit{Unit: "mixed.service", Enabled: true, Active: true})
	files := append(*doc.ManagedFiles, declarative.ManagedFile{Path: "/etc/acme/mixed.conf", Mode: "0644", Owner: "root", Group: "root", Content: "m"})
	doc.ManagedUnits, doc.ManagedFiles = &units, &files
	refused("mixed apply", "config.applied", problem.RolloutRunning, func() error {
		_, _, err := h.config.Apply(ctx, raw(t, doc), "")
		return err
	})
	if _, err := h.config.Plan(ctx, raw(t, doc)); !errors.Is(err, problem.RolloutRunning) {
		t.Errorf("dry run of the mixed apply = %v, want rollout_running", err)
	}
	// A device group deletion is a write of every section it cascades into.
	refused("deletion of the staged file's group", "device_group.deleted", problem.RolloutConflict, func() error {
		return h.groups.Delete(ctx, group)
	})
	if n := h.changeSets(t); n != changeSets {
		t.Fatalf("%d change sets after refusals, want %d", n, changeSets)
	}

	// A unit is a rollout-able section the rollout does not stage: immediate, no rollout.
	if _, err := h.files.CreateUnit(ctx, app.UnitInput{Unit: strPtr("unrelated.service")}); err != nil {
		t.Fatal(err)
	}
	if p := h.lastEvent(t); p["rollout"] != app.RolloutImmediate || p["rollout_id"] != nil || h.rollouts(t) != 1 {
		t.Fatalf("unrelated unit: params %v, %d rollouts", p, h.rollouts(t))
	}

	// Switching rollouts off does not lift the rule of the open rollout.
	if _, err := h.super.Exec(context.Background(), "UPDATE organization_rollout_settings SET enabled = false WHERE organization_id = $1", h.org); err != nil {
		t.Fatal(err)
	}
	refused("second file with rollouts off", "managed_file.created", problem.RolloutRunning, func() error {
		_, err := h.files.CreateFile(ctx, app.FileInput{Path: strPtr("/etc/acme/off.conf"), Content: strPtr("x")})
		return err
	})
	enableRollouts(t, h, []int{10, 100}, nil)

	// A halted rollout keeps its keys staged.
	if _, err := h.super.Exec(context.Background(), "UPDATE config_rollout SET status = 'halted' WHERE id = $1", rollout.id); err != nil {
		t.Fatal(err)
	}
	refused("second file while halted", "managed_file.created", problem.RolloutRunning, func() error {
		_, err := h.files.CreateFile(ctx, app.FileInput{Path: strPtr("/etc/acme/halted.conf"), Content: strPtr("x")})
		return err
	})
	// Package holds and update settings are one section.
	if _, err := h.super.Exec(context.Background(), "UPDATE config_rollout SET status = 'completed' WHERE id = $1", rollout.id); err != nil {
		t.Fatal(err)
	}
	if _, err := h.updates.CreateHold(ctx, app.HoldInput{Package: "openssl"}); err != nil {
		t.Fatal(err)
	}
	refused("update settings while a hold is staged", "settings.updates_changed", problem.RolloutRunning, func() error {
		s, err := h.updates.GetSettings(ctx)
		if err != nil {
			return err
		}
		s.MaxRandomDelayMin++
		_, err = h.updates.UpdateSettings(ctx, s.Settings)
		return err
	})
}

// TestConfigRolloutUrgent (plan M11 decision 26): urgent needs a reason, enabled rollouts and a step-up (an API token
// never has one); an urgent write overlapping a staged key is still rollout_conflict; otherwise it is urgent and
// starts no rollout.
func TestConfigRolloutUrgent(t *testing.T) {
	h := newWriteHarness(t)
	admin := h.account(t, principal.RoleOrgAdmin, false)
	ctx := principal.With(context.Background(), admin)
	stepped := principal.With(context.Background(), h.account(t, principal.RoleOrgAdmin, true))
	urgent := app.WriteOptions{Urgent: true, Reason: "outage"}
	unit := func(c context.Context, name string, opts app.WriteOptions) ([]string, error) {
		var err error
		got := h.during(t, func() { _, err = h.files.CreateUnit(c, app.UnitInput{Unit: strPtr(name)}, opts) })
		return got, err
	}

	if got, err := unit(stepped, "disabled.service", urgent); !errors.Is(err, problem.InvalidRequest) ||
		!slices.Equal(got, []string{"managed_unit.created:failure:invalid_request"}) {
		t.Fatalf("urgent while rollouts are disabled = %v, %v", err, got)
	}
	enableRollouts(t, h, []int{10, 100}, nil)
	if got, err := unit(stepped, "noreason.service", app.WriteOptions{Urgent: true}); !errors.Is(err, problem.InvalidRequest) ||
		!slices.Equal(got, []string{"managed_unit.created:failure:invalid_request"}) {
		t.Fatalf("urgent without reason = %v, %v", err, got)
	}
	if got, err := unit(ctx, "nostepup.service", urgent); !errors.Is(err, problem.StepUpRequired) ||
		!slices.Equal(got, []string{"managed_unit.created:denied:step_up_required"}) {
		t.Fatalf("urgent without step-up = %v, %v", err, got)
	}
	token := h.account(t, principal.RoleOrgAdmin, true)
	token.APITokenID, token.APITokenName = uuid.Must(uuid.NewV7()), "ci"
	if _, err := unit(principal.With(context.Background(), token), "token.service", urgent); !errors.Is(err, problem.StepUpRequired) {
		t.Fatalf("urgent with an API token = %v", err)
	}
	if _, err := unit(stepped, "urgent.service", urgent); err != nil {
		t.Fatal(err)
	}
	cs := h.lastChangeSet(t)
	if p := h.lastEvent(t); p["rollout"] != app.RolloutUrgent || p["urgent_reason"] != "outage" || h.rollout(t, cs.id).present {
		t.Fatalf("urgent unit: params %v", p)
	}

	staged, err := h.files.CreateFile(ctx, app.FileInput{Path: strPtr("/etc/acme/staged.conf"), Content: strPtr("x")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.files.UpdateFile(stepped, staged.ID, app.FileInput{Content: strPtr("y")}, urgent); !errors.Is(err, problem.RolloutConflict) {
		t.Fatalf("urgent update of the staged file = %v, want rollout_conflict", err)
	}
	if _, err := h.files.CreateFile(stepped, app.FileInput{Path: strPtr("/etc/acme/fix.conf"), Content: strPtr("x")}, urgent); err != nil {
		t.Fatalf("urgent second file = %v", err)
	}
	if p := h.lastEvent(t); p["rollout"] != app.RolloutUrgent || h.rollouts(t) != 1 {
		t.Fatalf("urgent second file: params %v, %d rollouts", p, h.rollouts(t))
	}
}

// TestConfigRolloutRevertEndsRollout (plan M11 decision 21.3): the revert of the open rollout's change set is immediate,
// ends the rollout with status reverted and names it in the audit event; afterwards a new change set can be staged.
func TestConfigRolloutRevertEndsRollout(t *testing.T) {
	h := newWriteHarness(t)
	ctx := principal.With(context.Background(), h.account(t, principal.RoleOrgAdmin, false))
	if _, err := h.files.CreateFile(ctx, app.FileInput{Path: strPtr("/etc/acme/early.conf"), Content: strPtr("x")}); err != nil {
		t.Fatal(err)
	}
	early := h.lastChangeSet(t).id
	enableRollouts(t, h, []int{10, 100}, nil)
	if _, err := h.files.CreateFile(ctx, app.FileInput{Path: strPtr("/etc/acme/staged.conf"), Content: strPtr("x")}); err != nil {
		t.Fatal(err)
	}
	original := h.lastChangeSet(t).id
	r := h.rollout(t, original)
	// Any other revert follows the rules of every write: it touches a section the rollout stages.
	if _, err := revertPlan(ctx, h, early); !errors.Is(err, problem.RolloutRunning) {
		t.Fatalf("dry run of another file's revert = %v, want rollout_running", err)
	}
	plan, err := revertPlan(ctx, h, original)
	if err != nil {
		t.Fatalf("dry run of the rollout's revert = %v", err)
	}
	id, _, err := h.config.Revert(ctx, original, plan.SHA256(), app.RevertOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if p := h.lastEvent(t); p["rollout"] != app.RolloutImmediate || p["rollout_id"] != r.id.String() || p["rollout_status"] != configrollout.StatusReverted {
		t.Fatalf("revert params %v", p)
	}
	ended := h.rollout(t, original)
	if ended.status != configrollout.StatusReverted || !ended.endedAtSet || ended.endedReason == nil || *ended.endedReason != "reverted by change set "+id.String() {
		t.Fatalf("rollout after the revert %+v", ended)
	}
	if _, err := h.files.CreateFile(ctx, app.FileInput{Path: strPtr("/etc/acme/next.conf"), Content: strPtr("x")}); err != nil {
		t.Fatal(err)
	}
	if next := h.rollout(t, h.lastChangeSet(t).id); next.status != configrollout.StatusRunning {
		t.Fatalf("next rollout %+v", next)
	}
}

// TestConfigRolloutStats (plan M11 decision 27): eligible counts the active devices in the wave or the canary group;
// failed counts eligible devices whose newest report on a bundle of the rollout is a rejection or a failed staged
// resource.
func TestConfigRolloutStats(t *testing.T) {
	h := newWriteHarness(t)
	ctx := principal.With(context.Background(), h.account(t, principal.RoleOrgAdmin, false))
	canary := h.group(t, h.org)
	enableRollouts(t, h, []int{50, 100}, &canary)
	if _, err := h.files.CreateFile(ctx, app.FileInput{Path: strPtr("/etc/acme/staged.conf"), Content: strPtr("x")}); err != nil {
		t.Fatal(err)
	}
	r := h.rollout(t, h.lastChangeSet(t).id)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := h.super.Exec(context.Background(), sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	var in, out []uuid.UUID
	for len(in) < 3 || len(out) < 2 {
		d := uuid.Must(uuid.NewV7())
		exec("INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'h', 'active')", d, h.org)
		if configrollout.Bucket(d, r.id) < 50 {
			in = append(in, d)
		} else {
			out = append(out, d)
		}
	}
	exec("INSERT INTO device_group_member (organization_id, device_group_id, device_id) VALUES ($1, $2, $3)", h.org, canary, out[0])
	report := func(d uuid.UUID, outcome string, failedResource string) {
		exec(`INSERT INTO bundle (device_id, version, organization_id, content_sha256, envelope_sha256, object_key, schema_version, config_rollout_id)
			VALUES ($1, 1, $2, '\x00', '\x00', 'k', 2, $3)`, d, h.org, r.id)
		exec(`INSERT INTO device_bundle_report (device_id, organization_id, version, outcome, occurred_at) VALUES ($1, $2, 1, $3, now())`, d, h.org, outcome)
		if failedResource != "" {
			exec(`INSERT INTO device_resource_status (device_id, organization_id, resource_id, status, bundle_version, occurred_at)
				VALUES ($1, $2, $3, 'failed', 1, now())`, d, h.org, failedResource)
		}
	}
	report(in[0], "rejected", "")
	report(in[1], "applied", "file:/etc/acme/staged.conf")
	report(in[2], "applied", "unit:other.service")
	report(out[0], "applied", "file:/etc/acme/staged.conf")
	// As the worker that evaluates rollouts (PDK-158): its grants and row-level security apply.
	tx, err := h.super.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(context.Background(), "SELECT set_config('paddock.org_id', $1, true)", h.org.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(context.Background(), "SET LOCAL ROLE paddock_worker"); err != nil {
		t.Fatal(err)
	}
	var eligible, failed int64
	if err := tx.QueryRow(context.Background(), "SELECT * FROM paddock_config_rollout_stats($1, 50, $2, now() - interval '1 hour', $3)",
		r.id, canary, []string{"file:/etc/acme/staged.conf"}).Scan(&eligible, &failed); err != nil {
		t.Fatal(err)
	}
	wantEligible := int64(len(in) + 1)
	if eligible != wantEligible || failed != 3 {
		t.Fatalf("eligible %d failed %d, want %d and 3", eligible, failed, wantEligible)
	}
}
