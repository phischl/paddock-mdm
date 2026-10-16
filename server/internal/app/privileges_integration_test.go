package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/privilege"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

type privilegesHarness struct {
	tokenHarness
	privileges *app.Privileges
}

func newPrivilegesHarness(t *testing.T) privilegesHarness {
	t.Helper()
	h := newTokenHarness(t)
	pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return privilegesHarness{tokenHarness: h, privileges: app.NewPrivileges(h.runner, pool)}
}

// lastEvent returns the last audit event recorded with the harness' correlation ID.
func (h privilegesHarness) lastEvent(t *testing.T) audit.Event {
	t.Helper()
	_, events := h.recorded(t, h.corr)
	if len(events) == 0 {
		t.Fatal("no event recorded")
	}
	return events[len(events)-1]
}

// TestEffectiveClassStepUp: creating, changing the grant of, assigning and re-scoping a profile that is effectively
// Full needs a step-up; a rename does not, and an API token never has one (ADR 0034 decisions 1 and 3).
func TestEffectiveClassStepUp(t *testing.T) {
	h := newPrivilegesHarness(t)
	admin := h.account(t, principal.RoleOrgAdmin, false)
	steppedUp := h.account(t, principal.RoleOrgAdmin, true)
	ctx := func(p principal.Principal) context.Context { return principal.With(context.Background(), p) }
	shell := privilege.Profile{Name: "shell", Class: privilege.ClassRestricted, Commands: []string{"/usr/bin/bash"},
		RequirePassword: true, TimestampTimeoutMin: 5, Lecture: privilege.LectureOnce}

	got := h.during(t, func() {
		if _, err := h.privileges.CreateProfile(ctx(admin), shell); !errors.Is(err, problem.StepUpRequired) {
			t.Errorf("create without step-up = %v", err)
		}
	})
	if len(got) != 1 || got[0] != "permission_profile.created:denied:step_up_required" {
		t.Fatalf("actions %v", got)
	}
	created, err := h.privileges.CreateProfile(ctx(steppedUp), shell)
	if err != nil {
		t.Fatalf("create with step-up = %v", err)
	}
	ev := h.lastEvent(t)
	if ev.Params["effective_class"] != "full" || ev.Params["root_equivalent"] != true || !ev.Actor.StepUp {
		t.Fatalf("created event %+v", ev)
	}

	name := "shell-renamed"
	if _, err := h.privileges.UpdateProfile(ctx(admin), created.ID, app.ProfilePatch{Name: &name}); err != nil {
		t.Fatalf("rename without step-up = %v", err)
	}
	lecture := privilege.LectureAlways
	if _, err := h.privileges.UpdateProfile(ctx(admin), created.ID, app.ProfilePatch{Lecture: &lecture}); err != nil {
		t.Fatalf("lecture change without step-up = %v", err)
	}
	more := []string{"/usr/bin/bash", "/usr/bin/python3"}
	if _, err := h.privileges.UpdateProfile(ctx(admin), created.ID, app.ProfilePatch{Commands: &more}); !errors.Is(err, problem.StepUpRequired) {
		t.Fatalf("adding a command without step-up = %v", err)
	}
	full := privilege.ClassFull
	if _, err := h.privileges.UpdateProfile(ctx(admin), created.ID, app.ProfilePatch{Class: &full}); !errors.Is(err, problem.StepUpRequired) {
		t.Fatalf("class full without step-up = %v", err)
	}
	harmless := []string{"/usr/bin/systemctl restart nginx.service"}
	if _, err := h.privileges.UpdateProfile(ctx(admin), created.ID, app.ProfilePatch{Commands: &harmless}); err != nil {
		t.Fatalf("dropping the root grant without step-up = %v", err)
	}
	if _, err := h.privileges.UpdateProfile(ctx(admin), created.ID, app.ProfilePatch{Commands: &more}); !errors.Is(err, problem.StepUpRequired) {
		t.Fatalf("restoring the root grant without step-up = %v", err)
	}
	if _, err := h.privileges.UpdateProfile(ctx(steppedUp), created.ID, app.ProfilePatch{Commands: &more}); err != nil {
		t.Fatalf("restoring the root grant with step-up = %v", err)
	}

	assignment := app.NewAssignment{ProfileID: created.ID, SubjectType: privilege.SubjectGlobal}
	if _, err := h.privileges.CreateAssignment(ctx(admin), assignment); !errors.Is(err, problem.StepUpRequired) {
		t.Fatalf("assignment without step-up = %v", err)
	}
	a, err := h.privileges.CreateAssignment(ctx(steppedUp), assignment)
	if err != nil {
		t.Fatalf("assignment with step-up = %v", err)
	}
	if ev := h.lastEvent(t); ev.Params["effective_class"] != "full" {
		t.Fatalf("assignment event %+v", ev)
	}
	group := uuid.Must(uuid.NewV7())
	if _, err := h.super.Exec(context.Background(), "INSERT INTO device_group (id, organization_id, name) VALUES ($1, $2, 'laptops')", group, h.org); err != nil {
		t.Fatal(err)
	}
	if _, err := h.privileges.UpdateAssignmentScope(ctx(admin), a.ID, &group); !errors.Is(err, problem.StepUpRequired) {
		t.Fatalf("scope change without step-up = %v", err)
	}
	if _, err := h.privileges.UpdateAssignmentScope(ctx(steppedUp), a.ID, &group); err != nil {
		t.Fatalf("scope change with step-up = %v", err)
	}

	// An API token cannot complete a step-up; an ordinary profile needs none.
	token := h.create(t, steppedUp, "ci", principal.RoleOrgOperator)
	tp, _, err := h.tokens.Authenticate(context.Background(), token.Secret, "")
	if err != nil {
		t.Fatal(err)
	}
	other := shell
	other.Name = "token-shell"
	if _, err := h.privileges.CreateProfile(ctx(tp), other); !errors.Is(err, problem.StepUpRequired) ||
		!strings.Contains(problem.From(err).Detail, "API tokens cannot complete a step-up") {
		t.Fatalf("token creating a root-equivalent profile = %v", err)
	}
	ordinary := privilege.Profile{Name: "nginx", Class: privilege.ClassRestricted, Commands: harmless, Lecture: privilege.LectureOnce}
	if _, err := h.privileges.CreateProfile(ctx(tp), ordinary); err != nil {
		t.Fatalf("token creating an ordinary profile = %v", err)
	}
	if ev := h.lastEvent(t); ev.Params["effective_class"] != "restricted" {
		t.Fatalf("ordinary event %+v", ev)
	}
}

// TestProfileUpdateSeesConcurrentDemotion: a change that waits for a concurrent demotion of an effectively Full
// profile decides on the demoted row and never writes the root-equivalent command back (plan M8s decision 7j).
func TestProfileUpdateSeesConcurrentDemotion(t *testing.T) {
	h := newPrivilegesHarness(t)
	steppedUp := h.account(t, principal.RoleOrgAdmin, true)
	operator := h.account(t, principal.RoleOrgOperator, false)
	created, err := h.privileges.CreateProfile(principal.With(context.Background(), steppedUp), privilege.Profile{
		Name: "shell", Class: privilege.ClassRestricted, Commands: []string{"/usr/bin/bash"}, Lecture: privilege.LectureOnce})
	if err != nil {
		t.Fatal(err)
	}

	// The demotion holds the row lock while the operator's lecture change starts.
	ctx := context.Background()
	demote, err := h.super.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = demote.Rollback(ctx) }()
	if _, err := demote.Exec(ctx, "UPDATE permission_profile SET commands = '{/usr/bin/systemctl restart nginx.service}' WHERE id = $1", created.ID); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		lecture := privilege.LectureAlways
		_, err := h.privileges.UpdateProfile(principal.With(context.Background(), operator), created.ID, app.ProfilePatch{Lecture: &lecture})
		done <- err
	}()
	watch, err := pgx.Connect(ctx, pgtest.SharedPaddock(t).Super)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = watch.Close(ctx) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting int
		if err := watch.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query LIKE '%permission_profile%'`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the operator's change did not wait for the demotion")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := demote.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("lecture change after the demotion = %v", err)
	}
	var commands []string
	if err := h.super.QueryRow(ctx, "SELECT commands FROM permission_profile WHERE id = $1", created.ID).Scan(&commands); err != nil {
		t.Fatal(err)
	}
	if len(commands) != 1 || commands[0] != "/usr/bin/systemctl restart nginx.service" {
		t.Fatalf("commands after the concurrent change: %v", commands)
	}
}
