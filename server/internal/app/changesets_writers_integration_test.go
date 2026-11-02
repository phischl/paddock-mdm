package app_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/declarative"
	"github.com/phischl/paddock-mdm/server/internal/domain/loginsettings"
	"github.com/phischl/paddock-mdm/server/internal/domain/privilege"
	"github.com/phischl/paddock-mdm/server/internal/domain/updates"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// TestChangeSetEveryWrappedWriter (PDK-154 review m1): one write per wrapped use case records exactly one change set
// and one audit event that names it.
func TestChangeSetEveryWrappedWriter(t *testing.T) {
	h := newWriteHarness(t)
	admin := h.account(t, principal.RoleOrgAdmin, true)
	ctx := principal.With(context.Background(), admin)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	group, err := h.groups.Create(ctx, "wrap", nil, app.DeviceGroupPolicy{})
	must(err)
	unit, err := h.files.CreateUnit(ctx, app.UnitInput{Unit: strPtr("wrap.service")})
	must(err)
	hold, err := h.updates.CreateHold(ctx, app.HoldInput{Package: "vim"})
	must(err)
	profile, err := h.profiles.CreateProfile(ctx, privilege.Profile{Name: "wrap", Class: privilege.ClassNone, Lecture: privilege.LectureAlways})
	must(err)
	assignment, err := h.profiles.CreateAssignment(ctx, app.NewAssignment{ProfileID: profile.ID, SubjectType: privilege.SubjectGlobal})
	must(err)
	login := h.export(t, admin).Settings.Login
	upd := h.export(t, admin).Settings.Updates

	for _, tc := range []struct {
		name, code string
		write      func() error
	}{
		{"unit update", "managed_unit.updated", func() error {
			_, err := h.files.UpdateUnit(ctx, unit.ID, app.UnitInput{Active: boolPtr(false)})
			return err
		}},
		{"unit delete", "managed_unit.deleted", func() error { return h.files.DeleteUnit(ctx, unit.ID) }},
		{"hold update", "package_hold.updated", func() error {
			_, err := h.updates.UpdateHold(ctx, hold.ID, nil, "pinned")
			return err
		}},
		{"hold delete", "package_hold.deleted", func() error { return h.updates.DeleteHold(ctx, hold.ID) }},
		{"update settings", "settings.updates_changed", func() error {
			s := updates.Settings{SecurityDailyAt: "01:15", RegularSchedule: upd.RegularSchedule, RegularUpdatesEnabled: upd.RegularUpdatesEnabled,
				MaxRandomDelayMin: upd.MaxRandomDelayMin, StalenessWarningH: upd.StalenessWarningH, StalenessCriticalH: upd.StalenessCriticalH}
			_, err := h.updates.UpdateSettings(ctx, s)
			return err
		}},
		{"login settings", "settings.login_changed", func() error {
			_, err := app.NewLoginSettings(h.runner, h.pool).Update(ctx, loginsettings.Settings{
				HelloEnabled: !login.HelloEnabled, HelloPinMinLength: login.HelloPinMinLength, UserLockSessionAction: login.UserLockSessionAction,
				BreakGlassAccounts: login.BreakGlassAccounts, SudoersDAllowlist: login.SudoersDAllowlist, SudoLectureText: login.SudoLectureText,
				LocalAdminUsername: login.LocalAdminUsername, LocalAdminRotationDays: login.LocalAdminRotationDays,
				RotateAfterRevealHours: login.RotateAfterRevealHours, NoticeText: login.NoticeText, BootPinMinLength: login.BootPinMinLength,
			})
			return err
		}},
		{"profile update", "permission_profile.updated", func() error {
			_, err := h.profiles.UpdateProfile(ctx, profile.ID, app.ProfilePatch{Lecture: lecturePtr(privilege.LectureNever)})
			return err
		}},
		{"assignment update", "profile_assignment.updated", func() error {
			_, err := h.profiles.UpdateAssignmentScope(ctx, assignment.ID, &group.ID)
			return err
		}},
		{"assignment delete", "profile_assignment.deleted", func() error { return h.profiles.DeleteAssignment(ctx, assignment.ID) }},
		{"profile delete", "permission_profile.deleted", func() error { return h.profiles.DeleteProfile(ctx, profile.ID) }},
		{"group update", "device_group.updated", func() error {
			_, err := h.groups.Update(ctx, group.ID, nil, strPtr("renamed description"), app.DeviceGroupPolicyPatch{})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := h.changeSets(t)
			got := h.during(t, func() {
				if err := tc.write(); err != nil {
					t.Fatal(err)
				}
			})
			if len(got) != 1 || got[0] != tc.code+":success:" || h.changeSets(t) != before+1 {
				t.Fatalf("actions %v, change sets %d (was %d)", got, h.changeSets(t), before)
			}
			_, events := h.recorded(t, h.corr)
			if ev := events[len(events)-1]; ev.Params["change_set_id"] != h.lastChangeSet(t).id.String() {
				t.Fatalf("event %s params %v", ev.Code, ev.Params)
			}
		})
	}
}

func lecturePtr(l privilege.Lecture) *privilege.Lecture { return &l }

// TestChangeSetApplyStoresBefore (PDK-154 review M1): PUT /config with a changed file stores the previous content and
// row ID as before-state while the plan shows a hash only.
func TestChangeSetApplyStoresBefore(t *testing.T) {
	h := newWriteHarness(t)
	admin := h.account(t, principal.RoleOrgAdmin, false)
	ctx := principal.With(context.Background(), admin)
	path, first := "/etc/acme/applied", "before content"
	created, err := h.files.CreateFile(ctx, app.FileInput{Path: &path, Content: &first})
	if err != nil {
		t.Fatal(err)
	}
	doc := h.export(t, admin)
	for i, f := range *doc.ManagedFiles {
		if f.Path == path {
			(*doc.ManagedFiles)[i].Content = "after content"
		}
	}
	id, plan, err := h.config.Apply(ctx, raw(t, doc), "")
	if err != nil || plan.Updated != 1 {
		t.Fatalf("Apply = %v, %+v, %v", id, plan, err)
	}
	cs := h.lastChangeSet(t)
	var item struct{ ID, Content string }
	if cs.id != id || json.Unmarshal(cs.before[declarative.SectionManagedFiles][fileKey(nil, path)], &item) != nil ||
		item.Content != first || item.ID != created.ID.String() {
		t.Fatalf("before-state %s", cs.before[declarative.SectionManagedFiles])
	}
	for _, fc := range cs.plan.Changes[0].Fields {
		if fc.Name == "content" && (fmt.Sprint(fc.Before) == first || fmt.Sprint(fc.After) == "after content" ||
			!strings.HasPrefix(fmt.Sprint(fc.After), "sha256:")) {
			t.Fatalf("plan content field %+v", fc)
		}
	}
}

// TestChangeSetSubjectDeletion (PDK-154 review B1): deleting a user or a user group with an assignment records one
// change set that holds the assignment's before-state, and it is not attributed to another writer.
func TestChangeSetSubjectDeletion(t *testing.T) {
	h := newWriteHarness(t)
	dir := newDirectory()
	admin := h.account(t, principal.RoleOrgAdmin, false)
	ctx := principal.With(context.Background(), admin)
	profile, err := h.profiles.CreateProfile(ctx, privilege.Profile{Name: "subj", Class: privilege.ClassNone, Lecture: privilege.LectureAlways})
	if err != nil {
		t.Fatal(err)
	}
	user, group := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	suffix := h.org.String()[24:]
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO app_user (id, organization_id, authentik_pk, username, source) VALUES ($1, $2, $3, $4, 'local')", []any{user, h.org, "u" + suffix, "bob-" + suffix + "@acme.test"}},
		{"INSERT INTO user_group (id, organization_id, slug, name, source, authentik_pk) VALUES ($1, $2, $3, 'Devs', 'local', $4)", []any{group, h.org, "devs-" + suffix, "g" + suffix}},
	} {
		if _, err := h.super.Exec(context.Background(), stmt.sql, stmt.args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, subject := range []struct {
		typ    privilege.SubjectType
		id     uuid.UUID
		delete func() error
		code   string
	}{
		{privilege.SubjectUser, user, func() error { return app.NewUsers(h.runner, h.pool, dir).Delete(ctx, user) }, "user.deleted"},
		{privilege.SubjectGroup, group, func() error { return app.NewUserGroups(h.runner, h.pool, dir).Delete(ctx, group) }, "user_group.deleted"},
	} {
		if _, err := h.profiles.CreateAssignment(ctx, app.NewAssignment{ProfileID: profile.ID, SubjectType: subject.typ, SubjectID: &subject.id}); err != nil {
			t.Fatal(err)
		}
		before := h.changeSets(t)
		got := h.during(t, func() {
			if err := subject.delete(); err != nil {
				t.Fatal(err)
			}
		})
		if len(got) != 1 || got[0] != subject.code+":success:" || h.changeSets(t) != before+1 {
			t.Fatalf("%s: actions %v, change sets %d (was %d)", subject.code, got, h.changeSets(t), before)
		}
		cs := h.lastChangeSet(t)
		if len(cs.plan.Changes) != 1 || cs.plan.Changes[0].Section != declarative.SectionProfileAssignments || cs.plan.Deleted != 1 {
			t.Fatalf("%s: plan %+v", subject.code, cs.plan)
		}
		items := cs.before[declarative.SectionProfileAssignments]
		if len(items) != 1 {
			t.Fatalf("%s: before %v", subject.code, cs.before)
		}
		for _, raw := range items {
			var item struct{ ID, Profile string }
			if json.Unmarshal(raw, &item) != nil || item.Profile != "subj" || item.ID == "" {
				t.Fatalf("%s: assignment before-state %s", subject.code, raw)
			}
		}
		_, events := h.recorded(t, h.corr)
		if ev := events[len(events)-1]; ev.Params["change_set_id"] != cs.id.String() {
			t.Fatalf("%s: event params %v", subject.code, ev.Params)
		}
	}
}

// TestSyncRenameWaitsForConfigApplyLock (PDK-154 review B1): a synced user's rename changes the username that keys
// its assignments, so it takes the apply lock like every writer of the document; while another transaction holds the
// lock, the rename waits.
func TestSyncRenameWaitsForConfigApplyLock(t *testing.T) {
	s := newSyncHarness(t)
	suffix := s.org.String()[24:]
	erin := ports.IdentityUser{PK: "e" + suffix, Username: "erin@up-" + suffix + ".test", Name: "Erin"}
	s.dir.users = []ports.IdentityUser{erin}
	none := func(string) bool { return false }
	if _, err := s.sync.SyncUsers(s.system(), none); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	tx, err := s.super.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	released := false
	t.Cleanup(func() {
		if !released {
			_ = tx.Rollback(ctx)
		}
	})
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended('config_apply:' || $1::text, 0))", s.org.String()); err != nil {
		t.Fatal(err)
	}
	erin.Name = "Erin E."
	s.dir.users = []ports.IdentityUser{erin}
	done := make(chan error, 1)
	go func() {
		_, err := s.sync.SyncUsers(s.system(), none)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("the sync finished while the apply lock was held: %v", err)
	case <-time.After(500 * time.Millisecond):
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	released = true
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the sync did not continue after the apply lock was released")
	}
	if n := s.count(t, "SELECT count(*) FROM app_user WHERE authentik_pk = $1 AND display_name = 'Erin E.'", erin.PK); n != 1 {
		t.Fatal("the rename was not applied")
	}
}
