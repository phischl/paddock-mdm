package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/declarative"
	"github.com/phischl/paddock-mdm/server/internal/domain/privilege"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// writeHarness bundles the per-resource use cases that record change sets (plan M11 decisions 18 and 19).
type writeHarness struct {
	configHarness
	files    *app.ManagedConfig
	groups   *app.DeviceGroups
	profiles *app.Privileges
	privacy  *app.Privacy
	watched  *app.WatchedUnits
	updates  *app.Updates
	pool     *db.OrgPool
}

func newWriteHarness(t *testing.T) writeHarness {
	t.Helper()
	h := newConfigHarness(t)
	pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return writeHarness{configHarness: h, pool: pool, files: app.NewManagedConfig(h.runner, pool), groups: app.NewDeviceGroups(h.runner, pool),
		profiles: app.NewPrivileges(h.runner, pool), privacy: app.NewPrivacy(h.runner, pool), watched: app.NewWatchedUnits(h.runner, pool),
		updates: app.NewUpdates(h.runner, pool)}
}

// storedChange is a change set row with its before-states.
type storedChange struct {
	id     uuid.UUID
	plan   declarative.Plan
	before map[string]map[string]json.RawMessage
}

func (h writeHarness) lastChangeSet(t *testing.T) storedChange {
	t.Helper()
	var out storedChange
	var plan, before []byte
	if err := h.super.QueryRow(context.Background(),
		"SELECT id, plan, before FROM change_set WHERE organization_id = $1 ORDER BY id DESC LIMIT 1", h.org).Scan(&out.id, &plan, &before); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(plan, &out.plan); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(before, &out.before); err != nil {
		t.Fatal(err)
	}
	return out
}

func (h writeHarness) changeSets(t *testing.T) int {
	t.Helper()
	return h.count(t, "SELECT count(*) FROM change_set WHERE organization_id = $1", h.org)
}

func fileKey(group *string, path string) string {
	k, _ := json.Marshal([]any{group, path})
	return string(k)
}

// TestChangeSetEveryFileWrite (PDK-154): creating, changing and deleting a managed file each record one change set
// and exactly one audit event, which names it; the before-state holds the full previous item with its row ID.
func TestChangeSetEveryFileWrite(t *testing.T) {
	h := newWriteHarness(t)
	admin := h.account(t, principal.RoleOrgAdmin, false)
	ctx := principal.With(context.Background(), admin)
	path, content, next := "/etc/acme/motd", "managed by paddock", "changed by paddock"
	key := fileKey(nil, path)

	var f = struct{ id uuid.UUID }{}
	got := h.during(t, func() {
		created, err := h.files.CreateFile(ctx, app.FileInput{Path: &path, Content: &content})
		if err != nil {
			t.Fatal(err)
		}
		f.id = created.ID
	})
	if len(got) != 1 || got[0] != "managed_file.created:success:" {
		t.Fatalf("actions %v, want exactly the managed_file.created event", got)
	}
	cs := h.lastChangeSet(t)
	if len(cs.plan.Changes) != 1 || cs.plan.Changes[0].Action != declarative.ActionCreate || cs.plan.Created != 1 || len(cs.before) != 0 {
		t.Fatalf("create change set: plan %+v, before %v", cs.plan, cs.before)
	}
	_, events := h.recorded(t, h.corr)
	if ev := events[len(events)-1]; ev.Params["change_set_id"] != cs.id.String() || ev.Params["rollout"] != app.RolloutImmediate {
		t.Fatalf("create event params %v", ev.Params)
	}

	if _, err := h.files.UpdateFile(ctx, f.id, app.FileInput{Content: &next}); err != nil {
		t.Fatal(err)
	}
	cs = h.lastChangeSet(t)
	var item struct {
		ID      string `json:"id"`
		Content string `json:"content"`
	}
	if len(cs.plan.Changes) != 1 || cs.plan.Changes[0].Action != declarative.ActionUpdate || cs.plan.Updated != 1 ||
		json.Unmarshal(cs.before[declarative.SectionManagedFiles][key], &item) != nil || item.Content != content || item.ID != f.id.String() {
		t.Fatalf("update change set: plan %+v, before %s", cs.plan, cs.before[declarative.SectionManagedFiles][key])
	}
	for _, fc := range cs.plan.Changes[0].Fields {
		if fc.Name == "content" && (fc.Before == content || fc.After == next) {
			t.Fatalf("the plan shows file content: %+v", fc)
		}
	}

	if err := h.files.DeleteFile(ctx, f.id); err != nil {
		t.Fatal(err)
	}
	cs = h.lastChangeSet(t)
	item.Content = ""
	if len(cs.plan.Changes) != 1 || cs.plan.Changes[0].Action != declarative.ActionDelete || cs.plan.Deleted != 1 ||
		json.Unmarshal(cs.before[declarative.SectionManagedFiles][key], &item) != nil || item.Content != next || item.ID != f.id.String() {
		t.Fatalf("delete change set: plan %+v, before %v", cs.plan, cs.before)
	}
	if n := h.changeSets(t); n != 3 {
		t.Fatalf("%d change sets, want 3", n)
	}
}

// TestChangeSetNotRecordedWithoutChange: a refused write and a write that changes nothing leave no change set, and
// their audit event names none.
func TestChangeSetNotRecordedWithoutChange(t *testing.T) {
	h := newWriteHarness(t)
	admin := h.account(t, principal.RoleOrgAdmin, false)
	ctx := principal.With(context.Background(), admin)
	bad := "/proc/forbidden"
	if _, err := h.files.CreateFile(ctx, app.FileInput{Path: &bad}); !errors.Is(err, problem.PathNotAllowed) {
		t.Fatalf("CreateFile = %v", err)
	}
	if _, err := h.files.CreateFile(principal.With(context.Background(), h.account(t, principal.RoleOrgAuditor, false)),
		app.FileInput{Path: strPtr("/etc/acme/x")}); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("auditor CreateFile = %v", err)
	}
	cur, err := h.privacy.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.privacy.Update(ctx, cur); err != nil {
		t.Fatal(err)
	}
	if n := h.changeSets(t); n != 0 {
		t.Fatalf("%d change sets after refused and unchanged writes", n)
	}
	_, events := h.recorded(t, h.corr)
	for _, ev := range events {
		if _, ok := ev.Params["change_set_id"]; ok {
			t.Fatalf("event %s names a change set: %v", ev.Code, ev.Params)
		}
	}
}

// TestChangeSetDeviceGroupDeleteCascade (PDK-154): deleting a device group with a managed file and an assignment
// records one change set with the group deletion and one deletion per cascaded item, before-states included.
func TestChangeSetDeviceGroupDeleteCascade(t *testing.T) {
	h := newWriteHarness(t)
	admin := h.account(t, principal.RoleOrgAdmin, false)
	ctx := principal.With(context.Background(), admin)
	group, err := h.groups.Create(ctx, "lab", nil, app.DeviceGroupPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	name := "lab"
	if _, err := h.files.CreateFile(ctx, app.FileInput{DeviceGroupID: &group.ID, Path: strPtr("/etc/acme/lab"), Content: strPtr("lab only")}); err != nil {
		t.Fatal(err)
	}
	profile, err := h.profiles.CreateProfile(ctx, privilege.Profile{Name: "nobody", Class: privilege.ClassNone, Lecture: privilege.LectureAlways})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.profiles.CreateAssignment(ctx, app.NewAssignment{ProfileID: profile.ID, SubjectType: privilege.SubjectGlobal, DeviceGroupID: &group.ID}); err != nil {
		t.Fatal(err)
	}
	before := h.changeSets(t)

	got := h.during(t, func() {
		if err := h.groups.Delete(ctx, group.ID); err != nil {
			t.Fatal(err)
		}
	})
	if len(got) != 1 || got[0] != "device_group.deleted:success:" || h.changeSets(t) != before+1 {
		t.Fatalf("actions %v, change sets %d (was %d)", got, h.changeSets(t), before)
	}
	cs := h.lastChangeSet(t)
	var sections []string
	for _, c := range cs.plan.Changes {
		if c.Action != declarative.ActionDelete {
			t.Fatalf("non-delete change %+v", c)
		}
		sections = append(sections, c.Section)
	}
	slices.Sort(sections)
	if !slices.Equal(sections, []string{"device_groups", "managed_files", "profile_assignments"}) || cs.plan.Deleted != 3 {
		t.Fatalf("change sections %v, plan %+v", sections, cs.plan)
	}
	for section, n := range map[string]int{"device_groups": 1, "managed_files": 1, "profile_assignments": 1} {
		if len(cs.before[section]) != n {
			t.Fatalf("before[%s] = %v, want %d item", section, cs.before[section], n)
		}
	}
	var file struct{ Content, ID string }
	if err := json.Unmarshal(cs.before["managed_files"][fileKey(&name, "/etc/acme/lab")], &file); err != nil || file.Content != "lab only" || file.ID == "" {
		t.Fatalf("cascaded file before-state %+v (%v)", file, err)
	}
}

// TestChangeSetSettingsSections (plan M11 amendment 2026-10-31 R2.5): the settings sections record change sets too;
// their before-state is the settings object.
func TestChangeSetSettingsSections(t *testing.T) {
	h := newWriteHarness(t)
	admin := h.account(t, principal.RoleOrgAdmin, true)
	ctx := principal.With(context.Background(), admin)

	if _, err := h.privacy.Update(ctx, app.PrivacySettings{RetiredInventoryDays: 30, AuditSearchRecorded: true, InventoryViewRecorded: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.files.SetOperatorRoots(ctx, []string{"/opt/acme/"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.watched.Set(ctx, []string{"wazuh-agent.service"}); err != nil {
		t.Fatal(err)
	}
	if n := h.changeSets(t); n != 3 {
		t.Fatalf("%d change sets, want one per settings write", n)
	}
	if _, err := h.privacy.Update(ctx, app.PrivacySettings{RetiredInventoryDays: 60, AuditSearchRecorded: true, InventoryViewRecorded: true}); err != nil {
		t.Fatal(err)
	}
	cs := h.lastChangeSet(t)
	var privacy declarative.PrivacySettings
	if len(cs.plan.Changes) != 1 || cs.plan.Changes[0].Section != declarative.SectionSettingsPrivacy || cs.plan.Changes[0].Action != declarative.ActionUpdate ||
		json.Unmarshal(cs.before[declarative.SectionSettingsPrivacy][""], &privacy) != nil || privacy.RetiredInventoryDays != 30 {
		t.Fatalf("privacy change set: plan %+v, before %v", cs.plan, cs.before)
	}

	if _, err := h.watched.Set(ctx, []string{"edr.service"}); err != nil {
		t.Fatal(err)
	}
	cs = h.lastChangeSet(t)
	var units []string
	if json.Unmarshal(cs.before[declarative.SectionSettingsWatched][""], &units) != nil || !slices.Equal(units, []string{"wazuh-agent.service"}) {
		t.Fatalf("watched units before-state %s", cs.before[declarative.SectionSettingsWatched][""])
	}
	if _, err := h.files.SetOperatorRoots(ctx, []string{"/usr/local/etc/acme/"}); err != nil {
		t.Fatal(err)
	}
	cs = h.lastChangeSet(t)
	var roots declarative.ManagedFileSettings
	if json.Unmarshal(cs.before[declarative.SectionSettingsManaged][""], &roots) != nil || !slices.Equal(roots.OperatorRoots, []string{"/opt/acme/"}) {
		t.Fatalf("operator roots before-state %s", cs.before[declarative.SectionSettingsManaged][""])
	}
}

// TestChangeSetBeforeAvailable: the change set API reports whether before-states are stored, filters by rollout and
// never shows another organization's change sets.
func TestChangeSetBeforeAvailable(t *testing.T) {
	h := newWriteHarness(t)
	admin := h.account(t, principal.RoleOrgAdmin, false)
	ctx := principal.With(context.Background(), admin)
	legacy := uuid.Must(uuid.NewV7())
	if _, err := h.super.Exec(context.Background(), `INSERT INTO change_set (id, organization_id, actor, source, created_n, updated_n, deleted_n, sections, plan)
		VALUES ($1, $2, '{"type":"admin","display":"old"}', 'session', 1, 0, 0, '{device_groups}', '{"changes":[],"created":1,"updated":0,"deleted":0}')`, legacy, h.org); err != nil {
		t.Fatal(err)
	}
	if _, err := h.files.CreateFile(ctx, app.FileInput{Path: strPtr("/etc/acme/new"), Content: strPtr("x")}); err != nil {
		t.Fatal(err)
	}
	fresh := h.lastChangeSet(t).id

	old, err := h.config.GetChangeSet(ctx, legacy)
	if err != nil || old.BeforeAvailable || old.Rollout != app.RolloutImmediate || old.RevertedBy != nil {
		t.Fatalf("legacy change set %+v, %v", old, err)
	}
	cur, err := h.config.GetChangeSet(ctx, fresh)
	if err != nil || !cur.BeforeAvailable {
		t.Fatalf("new change set %+v, %v", cur, err)
	}
	list, err := h.config.ListChangeSets(ctx, app.ChangeSetQuery{Page: app.ListPage{Sort: "-applied_at", Limit: 10}, Rollouts: []string{"immediate"}})
	if err != nil || list.Count != 2 {
		t.Fatalf("rollout=immediate = %+v, %v", list, err)
	}
	if list, err = h.config.ListChangeSets(ctx, app.ChangeSetQuery{Page: app.ListPage{Sort: "-applied_at", Limit: 10}, Rollouts: []string{"staged", "urgent"}}); err != nil || list.Count != 0 {
		t.Fatalf("rollout=staged,urgent = %+v, %v", list, err)
	}

	other := uuid.Must(uuid.NewV7())
	if _, err := h.super.Exec(context.Background(), "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'Other', 'active')", other, "o"+other.String()[24:]); err != nil {
		t.Fatal(err)
	}
	foreign := admin
	foreign.OrganizationID = other
	if _, err := h.config.GetChangeSet(principal.With(context.Background(), foreign), fresh); !errors.Is(err, problem.NotFound) {
		t.Fatalf("foreign change set = %v, want not_found", err)
	}
}

// TestChangeSetBeforePurge (plan M11 amendment 2026-10-29): the retention pass clears before-states older than 90
// retention days, keeps the change set and records one retention.purged event; younger ones and a second pass
// change nothing.
func TestChangeSetBeforePurge(t *testing.T) {
	w := newRetentionWorld(t)
	ctx := context.Background()
	now := time.Now().UTC()
	org := w.organization(t, 0, now)
	insert := func(age time.Duration) uuid.UUID {
		id := uuid.Must(uuid.NewV7())
		if _, err := w.super.Exec(ctx, `INSERT INTO change_set (id, organization_id, applied_at, actor, source, created_n, updated_n, deleted_n, sections, plan, before)
			VALUES ($1, $2, $3, '{"type":"admin","display":"a"}', 'session', 0, 1, 0, '{managed_files}', '{"changes":[]}', '{"managed_files":{}}')`,
			id, org, now.Add(-age)); err != nil {
			t.Fatal(err)
		}
		return id
	}
	old, young := insert(100*time.Second), insert(80*time.Second)
	other := w.organization(t, 0, now)
	foreign := uuid.Must(uuid.NewV7())
	if _, err := w.super.Exec(ctx, `INSERT INTO change_set (id, organization_id, applied_at, actor, source, created_n, updated_n, deleted_n, sections, plan, before)
		VALUES ($1, $2, $3, '{"type":"admin","display":"a"}', 'session', 0, 1, 0, '{managed_files}', '{"changes":[]}', '{"managed_files":{}}')`,
		foreign, other, now.Add(-100*time.Second)); err != nil {
		t.Fatal(err)
	}

	if n, err := w.retention.PurgeChangeSetBefore(principal.With(ctx, principal.Principal{Kind: principal.KindAdmin, OrganizationID: org, Role: principal.RoleOrgAdmin}), now); !errors.Is(err, problem.Unauthenticated) || n != 0 {
		t.Fatalf("admin purge = %d, %v", n, err)
	}
	n, err := w.retention.PurgeChangeSetBefore(systemCtx(org), now)
	if err != nil || n != 1 {
		t.Fatalf("purged %d (%v), want 1", n, err)
	}
	var oldBefore, youngBefore []byte
	var purgedAt *time.Time
	if err := w.super.QueryRow(ctx, "SELECT before, before_purged_at FROM change_set WHERE id = $1", old).Scan(&oldBefore, &purgedAt); err != nil {
		t.Fatal(err)
	}
	if oldBefore != nil || purgedAt == nil {
		t.Fatalf("expired change set: before %s, purged_at %v", oldBefore, purgedAt)
	}
	if err := w.super.QueryRow(ctx, "SELECT before FROM change_set WHERE id = $1", young).Scan(&youngBefore); err != nil || youngBefore == nil {
		t.Fatalf("young change set lost its before-state: %s, %v", youngBefore, err)
	}
	var events int
	if err := w.super.QueryRow(ctx, "SELECT count(*) FROM action WHERE organization_id = $1 AND code = 'retention.purged' AND params->>'store' = $2",
		org, app.StoreChangeSetBefore).Scan(&events); err != nil || events != 1 {
		t.Fatalf("%d retention.purged events (%v), want 1", events, err)
	}
	var foreignBefore []byte
	var foreignEvents int
	if err := w.super.QueryRow(ctx, "SELECT before FROM change_set WHERE id = $1", foreign).Scan(&foreignBefore); err != nil || foreignBefore == nil {
		t.Fatalf("another organization lost its before-state: %s, %v", foreignBefore, err)
	}
	if err := w.super.QueryRow(ctx, "SELECT count(*) FROM action WHERE organization_id = $1 AND code = 'retention.purged'", other).Scan(&foreignEvents); err != nil || foreignEvents != 0 {
		t.Fatalf("another organization got %d retention.purged events (%v)", foreignEvents, err)
	}
	if n, err := w.retention.PurgeChangeSetBefore(systemCtx(org), now); err != nil || n != 0 {
		t.Fatalf("second purge %d (%v), want 0", n, err)
	}
}
