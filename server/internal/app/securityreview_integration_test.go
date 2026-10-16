package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/privilege"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

type reviewHarness struct {
	privilegesHarness
	files    *app.ManagedConfig
	review   *app.SecurityReview
	overview *app.Overview
	admin    *app.Admin
}

func newReviewHarness(t *testing.T) reviewHarness {
	t.Helper()
	h := newPrivilegesHarness(t)
	pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	// The admin commands run with the worker's role, as on the host.
	worker, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).Worker, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(worker.Close)
	return reviewHarness{privilegesHarness: h, files: app.NewManagedConfig(h.runner, pool), review: app.NewSecurityReview(pool),
		overview: app.NewOverview(pool), admin: app.NewAdmin(app.NewActionRunner(worker, nil, func(context.Context) string { return h.corr }), worker)}
}

func (h reviewHarness) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := h.super.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// TestConfirmationColumns: a stepped-up grant records when and by whom it was confirmed; a change that removes the
// grant clears it; an ordinary file has none (ADR 0034 decision 7).
func TestConfirmationColumns(t *testing.T) {
	h := newReviewHarness(t)
	steppedUp := h.account(t, principal.RoleOrgAdmin, true)
	ctx := principal.With(context.Background(), steppedUp)
	p, err := h.privileges.CreateProfile(ctx, privilege.Profile{Name: "shell", Class: privilege.ClassRestricted,
		Commands: []string{"/usr/bin/bash"}, Lecture: privilege.LectureOnce})
	if err != nil {
		t.Fatal(err)
	}
	if p.RootGrantConfirmedAt == nil || !p.RootGrantConfirmedBy.Valid || p.RootGrantConfirmedBy.UUID != steppedUp.ID {
		t.Fatalf("created profile %+v", p)
	}
	name := "shell-2"
	if p, err = h.privileges.UpdateProfile(ctx, p.ID, app.ProfilePatch{Name: &name}); err != nil || p.RootGrantConfirmedAt == nil {
		t.Fatalf("rename keeps the confirmation: %+v, %v", p, err)
	}
	harmless := []string{"/usr/bin/systemctl restart nginx.service"}
	if p, err = h.privileges.UpdateProfile(ctx, p.ID, app.ProfilePatch{Commands: &harmless}); err != nil ||
		p.RootGrantConfirmedAt != nil || p.RootGrantConfirmedBy.Valid {
		t.Fatalf("a profile without root keeps a confirmation: %+v, %v", p, err)
	}
	path, mode, content := "/etc/cron.d/backup", "0644", "x"
	f, err := h.files.CreateFile(ctx, app.FileInput{Path: &path, Mode: &mode, Content: &content})
	if err != nil || f.SensitiveConfirmedAt == nil || f.SensitiveConfirmedBy.UUID != steppedUp.ID {
		t.Fatalf("sensitive file %+v, %v", f, err)
	}
	ordinary := "/etc/myapp/app.conf"
	if f, err = h.files.UpdateFile(ctx, f.ID, app.FileInput{Path: &ordinary}); err != nil || f.SensitiveConfirmedAt != nil {
		t.Fatalf("file moved to an ordinary path: %+v, %v", f, err)
	}
}

// TestSecurityReview: the review lists unconfirmed root grants with their assignments, unconfirmed sensitive files
// and files on denied paths, caps every list at 100 with the true total, and the overview counts the same; the
// confirmations remove items and follow the role and step-up rules.
func TestSecurityReview(t *testing.T) {
	h := newReviewHarness(t)
	admin := h.account(t, principal.RoleOrgAdmin, false)
	steppedUp := h.account(t, principal.RoleOrgAdmin, true)
	operator := h.account(t, principal.RoleOrgOperator, true)
	ctx := func(p principal.Principal) context.Context { return principal.With(context.Background(), p) }

	full, ordinaryProfile, sensitive, ordinaryFile := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	h.exec(t, `INSERT INTO permission_profile (id, organization_id, name, class, commands) VALUES
		($1, $3, 'legacy shell', 'restricted', '{/usr/bin/bash}'), ($2, $3, 'nginx', 'restricted', '{/usr/bin/systemctl restart nginx.service}')`,
		full, ordinaryProfile, h.org)
	h.exec(t, `INSERT INTO profile_assignment (id, organization_id, profile_id, subject_type) VALUES (gen_random_uuid(), $1, $2, 'global')`, h.org, full)
	h.exec(t, `INSERT INTO managed_file (id, organization_id, path, mode, content) VALUES
		($1, $3, '/etc/cron.d/legacy', '0644', 'x'), ($2, $3, '/etc/myapp/app.conf', '0644', 'y')`, sensitive, ordinaryFile, h.org)
	h.exec(t, `INSERT INTO managed_file (id, organization_id, path, mode, content)
		SELECT gen_random_uuid(), $1, '/etc/ld.so.conf.d/' || lpad(n::text, 3, '0') || '.conf', '0644', 'z' FROM generate_series(1, 101) n`, h.org)

	r, err := h.review.Get(ctx(h.account(t, principal.RoleOrgAuditor, false)))
	if err != nil {
		t.Fatal(err)
	}
	if r.RootGrantTotal != 1 || r.RootGrants[0].Profile.ID != full || r.RootGrants[0].Assignments != 1 {
		t.Fatalf("root grants %+v", r.RootGrants)
	}
	if r.SensitiveTotal != 1 || r.Sensitive[0].ID != sensitive {
		t.Fatalf("sensitive files %+v", r.Sensitive)
	}
	if r.DeniedTotal != 101 || len(r.Denied) != app.SecurityReviewCap || r.Denied[0].Path != "/etc/ld.so.conf.d/001.conf" {
		t.Fatalf("denied files: total %d, %d listed, first %s", r.DeniedTotal, len(r.Denied), r.Denied[0].Path)
	}
	o, err := h.overview.Get(ctx(admin))
	if err != nil || o.SecurityReview != (app.SecurityReviewCounts{RootGrants: 1, SensitiveFiles: 1, DeniedFiles: 101}) {
		t.Fatalf("overview counts %+v, %v", o.SecurityReview, err)
	}

	got := h.during(t, func() {
		if _, err := h.privileges.ConfirmRootGrant(ctx(admin), full); !errors.Is(err, problem.StepUpRequired) {
			t.Errorf("confirm without step-up = %v", err)
		}
		if _, err := h.privileges.ConfirmRootGrant(ctx(operator), full); !errors.Is(err, problem.Forbidden) {
			t.Errorf("confirm by an operator = %v", err)
		}
		if _, err := h.privileges.ConfirmRootGrant(ctx(steppedUp), ordinaryProfile); !errors.Is(err, problem.InvalidState) {
			t.Errorf("confirm an ordinary profile = %v", err)
		}
	})
	want := []string{"permission_profile.root_grant_confirmed:denied:step_up_required", "permission_profile.root_grant_confirmed:denied:forbidden",
		"permission_profile.root_grant_confirmed:failure:invalid_state"}
	if len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("actions %v", got)
	}
	confirmed, err := h.privileges.ConfirmRootGrant(ctx(steppedUp), full)
	if err != nil || confirmed.RootGrantConfirmedAt == nil || confirmed.RootGrantConfirmedBy.UUID != steppedUp.ID {
		t.Fatalf("confirm = %+v, %v", confirmed, err)
	}
	if ev := h.lastEvent(t); ev.Params["name"] != "legacy shell" || ev.Params["effective_class"] != "full" || !ev.Actor.StepUp {
		t.Fatalf("confirm event %+v", ev)
	}

	if _, err := h.files.ConfirmSensitive(ctx(admin), sensitive); !errors.Is(err, problem.StepUpRequired) {
		t.Fatalf("confirm a file without step-up = %v", err)
	}
	if _, err := h.files.ConfirmSensitive(ctx(operator), sensitive); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("confirm a file by an operator = %v", err)
	}
	if _, err := h.files.ConfirmSensitive(ctx(steppedUp), ordinaryFile); !errors.Is(err, problem.InvalidState) {
		t.Fatalf("confirm an ordinary file = %v", err)
	}
	if f, err := h.files.ConfirmSensitive(ctx(steppedUp), sensitive); err != nil || f.SensitiveConfirmedAt == nil {
		t.Fatalf("confirm a sensitive file = %+v, %v", f, err)
	}
	if ev := h.lastEvent(t); ev.Params["path"] != "/etc/cron.d/legacy" || ev.Params["tier"] != "sensitive" {
		t.Fatalf("confirm file event %+v", ev)
	}
	if r, err = h.review.Get(ctx(admin)); err != nil || r.RootGrantTotal != 0 || r.SensitiveTotal != 0 || r.DeniedTotal != 101 {
		t.Fatalf("review after the confirmations %+v, %v", r.Counts(), err)
	}
}

// TestSecurityReviewCommand: paddock-server admin security-review records the review only in organizations that
// have something to review, and again on every run.
func TestSecurityReviewCommand(t *testing.T) {
	h := newReviewHarness(t)
	clean := uuid.Must(uuid.NewV7())
	h.exec(t, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'Clean', 'active')", clean, "c"+clean.String()[24:])
	h.exec(t, "INSERT INTO managed_file (id, organization_id, path, mode, content) VALUES (gen_random_uuid(), $1, '/etc/ld.so.preload', '0644', 'x')", h.org)
	for run := 1; run <= 2; run++ {
		reviews, err := h.admin.SecurityReviewAll(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		var mine, other bool
		for _, r := range reviews {
			mine = mine || (r.Slug == "t"+h.org.String()[24:] && r.Counts == app.SecurityReviewCounts{DeniedFiles: 1})
			other = other || (r.Slug == "c"+clean.String()[24:] && r.Counts == app.SecurityReviewCounts{})
		}
		if !mine || !other {
			t.Fatalf("run %d: reviews %+v", run, reviews)
		}
		var events, cleanEvents int
		if err := h.super.QueryRow(context.Background(), `SELECT count(*) FILTER (WHERE organization_id = $1), count(*) FILTER (WHERE organization_id = $2)
			FROM action WHERE code = 'organization.security_review_required'`, h.org, clean).Scan(&events, &cleanEvents); err != nil {
			t.Fatal(err)
		}
		if events != run || cleanEvents != 0 {
			t.Fatalf("run %d: %d events, %d in the clean organization", run, events, cleanEvents)
		}
	}
}
