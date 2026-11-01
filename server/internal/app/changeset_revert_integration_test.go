package app_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/declarative"
	"github.com/phischl/paddock-mdm/server/internal/domain/privilege"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

func fileContent(doc declarative.Document, path string) (string, bool) {
	for _, f := range *doc.ManagedFiles {
		if f.Path == path && f.DeviceGroup == nil {
			return f.Content, true
		}
	}
	return "", false
}

// TestChangeSetRevert (PDK-155, plan M11 decision 21): the dry run shows the inverse plan without applying or auditing
// it; the revert needs the confirmed plan, restores the before-state, keeps items created since, records a change set
// that references the original and one config.reverted event; a second revert, a change set without before-state
// and a foreign change set are refused.
func TestChangeSetRevert(t *testing.T) {
	h := newWriteHarness(t)
	admin := h.account(t, principal.RoleOrgAdmin, false)
	ctx := principal.With(context.Background(), admin)
	path, later := "/etc/acme/revert.conf", "/etc/acme/later.conf"
	if _, err := h.files.CreateFile(ctx, app.FileInput{Path: strPtr(path), Content: strPtr("first")}); err != nil {
		t.Fatal(err)
	}
	doc := h.export(t, admin)
	for i, f := range *doc.ManagedFiles {
		if f.Path == path {
			(*doc.ManagedFiles)[i].Content = "second"
		}
	}
	*doc.ManagedUnits = append(*doc.ManagedUnits, declarative.ManagedUnit{Unit: "acme-revert.service", Enabled: true, Active: true})
	original, _, err := h.config.Apply(ctx, raw(t, doc), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.files.CreateFile(ctx, app.FileInput{Path: strPtr(later), Content: strPtr("kept")}); err != nil {
		t.Fatal(err)
	}
	sets := h.changeSets(t)

	var plan declarative.Plan
	got := h.during(t, func() {
		_, plan, err = h.config.Revert(ctx, original, "", app.RevertOptions{DryRun: true})
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 || h.changeSets(t) != sets {
		t.Fatalf("dry run recorded actions %v or a change set", got)
	}
	if len(plan.Changes) != 2 || plan.Updated != 1 || plan.Deleted != 1 ||
		plan.Changes[0].Section != declarative.SectionManagedUnits || plan.Changes[0].Action != declarative.ActionDelete ||
		plan.Changes[1].Section != declarative.SectionManagedFiles || plan.Changes[1].Action != declarative.ActionUpdate {
		t.Fatalf("dry run plan %+v", plan)
	}
	if fc := plan.Changes[1].Fields; len(fc) != 1 || fc[0].Name != "content" || fc[0].After != declarative.ContentSummary("first") {
		t.Fatalf("content change %+v, want back to the before hash", fc)
	}
	if c, _ := fileContent(h.export(t, admin), path); c != "second" {
		t.Fatalf("the dry run changed the file to %q", c)
	}

	if _, _, err := h.config.Revert(ctx, original, "", app.RevertOptions{}); !errors.Is(err, problem.InvalidRequest) {
		t.Fatalf("revert without expected_plan = %v, want invalid_request", err)
	}
	got = h.during(t, func() {
		_, _, err = h.config.Revert(ctx, original, strings.Repeat("0", 64), app.RevertOptions{})
	})
	if !errors.Is(err, problem.PlanChanged) || !slices.Equal(got, []string{"config.reverted:failure:plan_changed"}) {
		t.Fatalf("stale plan = %v, actions %v", err, got)
	}

	var id uuid.UUID
	got = h.during(t, func() {
		id, _, err = h.config.Revert(ctx, original, plan.SHA256(), app.RevertOptions{Reason: "broke the kiosk"})
	})
	if err != nil || id == uuid.Nil || !slices.Equal(got, []string{"config.reverted:success:"}) {
		t.Fatalf("revert = %v, %v, actions %v", id, err, got)
	}
	cur := h.export(t, admin)
	if c, _ := fileContent(cur, path); c != "first" {
		t.Errorf("file content %q, want the before content", c)
	}
	if c, ok := fileContent(cur, later); !ok || c != "kept" {
		t.Errorf("the file created after the original is gone")
	}
	if slices.ContainsFunc(*cur.ManagedUnits, func(u declarative.ManagedUnit) bool { return u.Unit == "acme-revert.service" }) {
		t.Errorf("the created unit is still present")
	}
	orig, err := h.config.GetChangeSet(ctx, original)
	if err != nil || orig.RevertedBy == nil || *orig.RevertedBy != id {
		t.Fatalf("original reverted_by %v, %v, want %s", orig.RevertedBy, err, id)
	}
	rev, err := h.config.GetChangeSet(ctx, id)
	if err != nil || !rev.RevertsChangeSetID.Valid || rev.RevertsChangeSetID.UUID != original || !rev.BeforeAvailable {
		t.Fatalf("revert change set %+v, %v", rev, err)
	}
	var reason *string
	if err := h.super.QueryRow(context.Background(), "SELECT reason FROM change_set WHERE id = $1", id).Scan(&reason); err != nil || reason == nil || *reason != "broke the kiosk" {
		t.Fatalf("stored reason %v, %v", reason, err)
	}
	_, events := h.recorded(t, h.corr)
	ev := events[len(events)-1]
	if ev.Code != "config.reverted" || ev.Target == nil || ev.Target.Type != "change_set" || ev.Target.ID != id.String() ||
		ev.Params["change_set_id"] != id.String() || ev.Params["reverts_change_set_id"] != original.String() ||
		ev.Params["plan_sha256"] != plan.SHA256() || ev.Params["updated"] != float64(1) || ev.Params["deleted"] != float64(1) ||
		ev.Params["created"] != float64(0) || ev.Params["rollout"] != app.RolloutImmediate {
		t.Fatalf("config.reverted event %+v", ev)
	}

	if _, _, err := h.config.Revert(ctx, original, plan.SHA256(), app.RevertOptions{}); !errors.Is(err, problem.InvalidState) ||
		!strings.Contains(err.Error(), "already reverted by "+id.String()) {
		t.Fatalf("second revert = %v", err)
	}
	if _, _, err := h.config.Revert(ctx, original, "", app.RevertOptions{DryRun: true}); !errors.Is(err, problem.InvalidState) {
		t.Fatalf("dry run of a reverted change set = %v", err)
	}
	// A revert of a revert is an ordinary change set.
	if p, err := revertPlan(ctx, h, id); err != nil || p.Updated != 1 || p.Created != 1 {
		t.Fatalf("revert of the revert: %+v, %v", p, err)
	}

	legacy, purged := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	if _, err := h.super.Exec(context.Background(), `INSERT INTO change_set (id, organization_id, actor, source, created_n, updated_n, deleted_n, sections, plan, before_purged_at)
		VALUES ($1, $3, '{"type":"admin","display":"old"}', 'session', 0, 1, 0, '{managed_files}', '{"changes":[],"created":0,"updated":1,"deleted":0}', NULL),
		       ($2, $3, '{"type":"admin","display":"old"}', 'session', 0, 1, 0, '{managed_files}', '{"changes":[],"created":0,"updated":1,"deleted":0}', now())`,
		legacy, purged, h.org); err != nil {
		t.Fatal(err)
	}
	if _, err := revertPlan(ctx, h, legacy); !errors.Is(err, problem.InvalidState) ||
		!strings.Contains(err.Error(), "this change set was recorded before before-states were stored") {
		t.Fatalf("legacy change set = %v", err)
	}
	if _, err := revertPlan(ctx, h, purged); !errors.Is(err, problem.InvalidState) || !strings.Contains(err.Error(), "purged") {
		t.Fatalf("purged change set = %v", err)
	}

	other := uuid.Must(uuid.NewV7())
	if _, err := h.super.Exec(context.Background(), "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'Other', 'active')", other, "o"+other.String()[24:]); err != nil {
		t.Fatal(err)
	}
	foreign := admin
	foreign.OrganizationID = other
	if _, _, err := h.config.Revert(principal.With(context.Background(), foreign), id, "", app.RevertOptions{DryRun: true}); !errors.Is(err, problem.NotFound) {
		t.Fatalf("foreign change set = %v, want not_found", err)
	}
	if _, _, err := h.config.Revert(principal.With(context.Background(), foreign), uuid.Must(uuid.NewV7()), plan.SHA256(), app.RevertOptions{}); !errors.Is(err, problem.NotFound) {
		t.Fatalf("unknown change set = %v, want not_found", err)
	}
	auditor := h.account(t, principal.RoleOrgAuditor, false)
	if _, _, err := h.config.Revert(principal.With(context.Background(), auditor), id, "", app.RevertOptions{DryRun: true}); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("auditor dry run = %v, want forbidden", err)
	}
}

func revertPlan(ctx context.Context, h writeHarness, id uuid.UUID) (declarative.Plan, error) {
	_, p, err := h.config.Revert(ctx, id, "", app.RevertOptions{DryRun: true})
	return p, err
}

// TestChangeSetRevertOptions (plan M11 amendment R6.12, decision 26): urgent needs a reason, the reason has 2 to 500
// characters, urgent is refused while rollouts are disabled, and an urgent revert stores its reason as urgent_reason.
func TestChangeSetRevertOptions(t *testing.T) {
	h := newWriteHarness(t)
	admin := h.account(t, principal.RoleOrgAdmin, false)
	ctx := principal.With(context.Background(), admin)
	if _, err := h.files.CreateFile(ctx, app.FileInput{Path: strPtr("/etc/acme/urgent.conf"), Content: strPtr("x")}); err != nil {
		t.Fatal(err)
	}
	original := h.lastChangeSet(t).id
	plan, err := revertPlan(ctx, h, original)
	if err != nil || plan.Deleted != 1 {
		t.Fatalf("dry run %+v, %v", plan, err)
	}
	for _, opts := range []app.RevertOptions{{Urgent: true}, {Reason: "x"}, {Reason: strings.Repeat("r", 501)}} {
		if _, _, err := h.config.Revert(ctx, original, plan.SHA256(), opts); !errors.Is(err, problem.InvalidRequest) {
			t.Errorf("%+v = %v, want invalid_request", opts, err)
		}
	}
	// A reason PostgreSQL cannot store (NUL, invalid UTF-8, control characters) is refused before anything is
	// written, with exactly one failure event (PDK-155 review 1, B1).
	bad := []app.RevertOptions{{Reason: "ab\x00cd"}, {Urgent: true, Reason: "ab\x00cd"}, {Reason: "ab\xffcd"},
		{Urgent: true, Reason: "ab\x1bcd"}}
	for _, opts := range bad {
		got := h.during(t, func() {
			_, _, err = h.config.Revert(ctx, original, plan.SHA256(), opts)
		})
		if !errors.Is(err, problem.InvalidRequest) || !slices.Equal(got, []string{"config.reverted:failure:invalid_request"}) {
			t.Errorf("reason %q urgent %t = %v, actions %v", opts.Reason, opts.Urgent, err, got)
		}
		if _, _, err := h.config.Revert(ctx, original, "", app.RevertOptions{DryRun: true, Urgent: opts.Urgent, Reason: opts.Reason}); !errors.Is(err, problem.InvalidRequest) {
			t.Errorf("dry run with reason %q = %v, want invalid_request", opts.Reason, err)
		}
	}
	if _, _, err := h.config.Revert(ctx, original, "", app.RevertOptions{DryRun: true, Urgent: true}); !errors.Is(err, problem.InvalidRequest) {
		t.Errorf("dry run urgent without reason = %v, want invalid_request", err)
	}

	urgentOpts := app.RevertOptions{Urgent: true, Reason: "outage\n\tdetails"}
	if _, _, err := h.config.Revert(ctx, original, plan.SHA256(), urgentOpts); !errors.Is(err, problem.InvalidRequest) {
		t.Fatalf("urgent while rollouts are disabled = %v, want invalid_request", err)
	}
	enableRollouts(t, h, []int{100}, nil)
	id, _, err := h.config.Revert(principal.With(context.Background(), h.account(t, principal.RoleOrgAdmin, true)), original, plan.SHA256(), urgentOpts)
	if err != nil {
		t.Fatal(err)
	}
	var rollout string
	var reason, urgent *string
	if err := h.super.QueryRow(context.Background(), "SELECT rollout, reason, urgent_reason FROM change_set WHERE id = $1", id).Scan(&rollout, &reason, &urgent); err != nil ||
		rollout != app.RolloutUrgent || reason == nil || *reason != "outage\n\tdetails" || urgent == nil || *urgent != "outage\n\tdetails" {
		t.Fatalf("stored rollout %s reason %v urgent_reason %v, %v", rollout, reason, urgent, err)
	}
	_, events := h.recorded(t, h.corr)
	if ev := events[len(events)-1]; ev.Params["urgent_reason"] != "outage\n\tdetails" {
		t.Fatalf("event params %v", ev.Params)
	}
}

// TestChangeSetRevertStepUp (PDK-155): reverting a change set that turned a full profile into a restricted one makes
// it full again, which needs a step-up like the apply; without one it is denied and nothing changes.
func TestChangeSetRevertStepUp(t *testing.T) {
	h := newWriteHarness(t)
	steppedUp := h.account(t, principal.RoleOrgAdmin, true)
	admin := h.account(t, principal.RoleOrgAdmin, false)
	ctx := principal.With(context.Background(), admin)
	full, err := h.profiles.CreateProfile(principal.With(context.Background(), steppedUp),
		privilege.Profile{Name: "revert-full", Class: privilege.ClassFull, Lecture: privilege.LectureOnce})
	if err != nil {
		t.Fatal(err)
	}
	restricted := privilege.ClassRestricted
	if _, err := h.profiles.UpdateProfile(ctx, full.ID, app.ProfilePatch{Class: &restricted, Commands: &[]string{"/usr/bin/true"}}); err != nil {
		t.Fatal(err)
	}
	original := h.lastChangeSet(t).id

	if _, err := revertPlan(ctx, h, original); !errors.Is(err, problem.StepUpRequired) {
		t.Fatalf("dry run without step-up = %v, want step_up_required", err)
	}
	plan, err := revertPlan(principal.With(context.Background(), steppedUp), h, original)
	if err != nil {
		t.Fatal(err)
	}
	got := h.during(t, func() {
		_, _, err = h.config.Revert(ctx, original, plan.SHA256(), app.RevertOptions{})
	})
	if !errors.Is(err, problem.StepUpRequired) || !slices.Equal(got, []string{"config.reverted:denied:step_up_required"}) {
		t.Fatalf("revert without step-up = %v, actions %v", err, got)
	}
	if id, _, err := h.config.Revert(principal.With(context.Background(), steppedUp), original, plan.SHA256(), app.RevertOptions{}); err != nil || id == uuid.Nil {
		t.Fatalf("revert with step-up = %v, %v", id, err)
	}
	var class string
	if err := h.super.QueryRow(context.Background(), "SELECT class FROM permission_profile WHERE id = $1", full.ID).Scan(&class); err != nil || class != string(privilege.ClassFull) {
		t.Fatalf("class %s, %v, want full", class, err)
	}
}
