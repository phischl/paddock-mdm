package declarative_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/oasdiff/yaml"

	"github.com/phischl/paddock-mdm/server/internal/domain/declarative"
)

var update = flag.Bool("update", false, "rewrite the golden files of testdata/")

func ptr[T any](v T) *T { return &v }

// current is a configuration with one item of every section.
func current() declarative.Document {
	return declarative.Document{
		APIVersion: declarative.APIVersion, Kind: declarative.Kind,
		Settings: &declarative.Settings{
			Login: &declarative.LoginSettings{
				HelloEnabled: true, HelloPinMinLength: 6, UserLockSessionAction: "lock_screen", BreakGlassAccounts: []string{},
				SudoersDAllowlist: []string{"README"}, SudoLectureText: "Be careful.", LocalAdminUsername: "paddock-admin",
				LocalAdminRotationDays: 30, NoticeText: "", BootPinMinLength: 8,
			},
			Updates: &declarative.UpdateSettings{
				SecurityDailyAt: "03:00", RegularSchedule: "Sat 04:00", RegularUpdatesEnabled: true, MaxRandomDelayMin: 60,
				StalenessWarningH: 24, StalenessCriticalH: 168,
			},
		},
		DeviceGroups: &[]declarative.DeviceGroup{{Name: "laptops", Description: ""}, {Name: "servers", Description: "racks"}},
		PermissionProfiles: &[]declarative.PermissionProfile{{
			Name: "ops", Class: "restricted", Commands: []string{"/usr/bin/systemctl restart *"}, RequirePassword: true,
			TimestampTimeoutMin: 5, Lecture: "once",
		}},
		ManagedFiles: &[]declarative.ManagedFile{
			{Path: "/etc/motd", Mode: "0644", Owner: "root", Group: "root", Content: "hello"},
			{Path: "/etc/laptop.conf", DeviceGroup: ptr("laptops"), Mode: "0600", Owner: "root", Group: "root", Content: "x=1"},
		},
		ManagedUnits: &[]declarative.ManagedUnit{{Unit: "foo.service", DeviceGroup: ptr("laptops"), Enabled: true, Active: true}},
		PackageHolds: &[]declarative.PackageHold{{Package: "firefox", Reason: "breaks kiosk"}},
		ProfileAssignments: &[]declarative.ProfileAssignment{
			{Profile: "ops", Subject: declarative.Subject{Type: "global"}},
			{Profile: "ops", Subject: declarative.Subject{Type: "group", Slug: "devs"}, DeviceGroup: ptr("laptops")},
		},
	}
}

// golden compares the plan with testdata/<name>.golden (go test -update rewrites it).
func golden(t *testing.T, name string, plan declarative.Plan) {
	t.Helper()
	got, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path) //nolint:gosec // fixed test data path
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("plan differs from %s:\n%s", path, got)
	}
}

func TestDiffOfTheSameDocumentIsEmpty(t *testing.T) {
	raw, err := json.Marshal(current())
	if err != nil {
		t.Fatal(err)
	}
	if err := declarative.ValidateJSON(raw); err != nil {
		t.Fatalf("an exported document violates the schema: %v", err)
	}
	decoded, err := declarative.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	plan := declarative.Diff(current(), decoded)
	if len(plan.Changes) != 0 || plan.Created+plan.Updated+plan.Deleted != 0 {
		t.Fatalf("export → import changes: %+v", plan)
	}
	if raw, _ := json.Marshal(plan); string(raw) != `{"changes":[],"created":0,"updated":0,"deleted":0}` {
		t.Fatalf("empty plan JSON %s", raw)
	}
}

func TestDiffAbsentSectionsAreUntouched(t *testing.T) {
	desired := declarative.Document{APIVersion: declarative.APIVersion, Kind: declarative.Kind}
	if plan := declarative.Diff(current(), desired); len(plan.Changes) != 0 {
		t.Fatalf("a document without sections changes %+v", plan)
	}
	desired.Settings = &declarative.Settings{}
	if plan := declarative.Diff(current(), desired); len(plan.Changes) != 0 {
		t.Fatalf("empty settings change %+v", plan)
	}
}

func TestDiffEverySection(t *testing.T) {
	d := current()
	d.Settings.Login.HelloEnabled = false
	d.Settings.Updates.SecurityDailyAt = "02:30"
	d.DeviceGroups = &[]declarative.DeviceGroup{{Name: "laptops", Description: "notebooks"}, {Name: "kiosks"}}
	(*d.PermissionProfiles)[0].Commands = []string{"/usr/bin/systemctl restart *", "/usr/bin/journalctl"}
	d.ManagedFiles = &[]declarative.ManagedFile{
		{Path: "/etc/motd", Mode: "0644", Owner: "root", Group: "root", Content: "hello world"},
		{Path: "/etc/issue.net", Mode: "0644", Owner: "root", Group: "root", Content: ""},
	}
	d.ManagedUnits = &[]declarative.ManagedUnit{{Unit: "foo.service", DeviceGroup: ptr("laptops"), Enabled: true, Active: false}}
	d.PackageHolds = &[]declarative.PackageHold{}
	d.ProfileAssignments = &[]declarative.ProfileAssignment{
		{Profile: "ops", Subject: declarative.Subject{Type: "global"}},
		{Profile: "ops", Subject: declarative.Subject{Type: "user", Username: "alice@example.org"}},
	}
	plan := declarative.Diff(current(), d)
	if plan.Created != 3 || plan.Updated != 6 || plan.Deleted != 4 {
		t.Errorf("counts %d/%d/%d, want 3 created, 6 updated, 4 deleted", plan.Created, plan.Updated, plan.Deleted)
	}
	golden(t, "every_section", plan)
	if got := strings.Join(plan.SectionsOf(), ","); got != "device_groups,permission_profiles,managed_files,managed_units,package_holds,profile_assignments,settings.updates,settings.login" {
		t.Errorf("sections %s", got)
	}
}

// TestDiffPrivacySettings: settings.privacy is a settings section like settings.updates (plan M10 decision 9): a
// changed field is one update, an unchanged section no change, an absent section untouched.
func TestDiffPrivacySettings(t *testing.T) {
	cur := current()
	cur.Settings.Privacy = &declarative.PrivacySettings{RetiredInventoryDays: 30}
	want := current()
	want.Settings.Privacy = &declarative.PrivacySettings{RetiredInventoryDays: 14}
	plan := declarative.Diff(cur, want)
	if len(plan.Changes) != 1 || plan.Updated != 1 {
		t.Fatalf("plan %+v", plan)
	}
	c := plan.Changes[0]
	if c.Section != declarative.SectionSettingsPrivacy || c.Action != declarative.ActionUpdate || c.Key != "" ||
		len(c.Fields) != 1 || c.Fields[0] != (declarative.FieldChange{Name: "retired_inventory_days", Before: 30, After: 14}) {
		t.Fatalf("change %+v", c)
	}
	if plan := declarative.Diff(cur, cur); len(plan.Changes) != 0 {
		t.Fatalf("same settings: %+v", plan)
	}
	want.Settings.Privacy = nil
	if plan := declarative.Diff(cur, want); len(plan.Changes) != 0 {
		t.Fatalf("absent section: %+v", plan)
	}
	if got := declarative.Path(declarative.SectionSettingsPrivacy, 0); got != "/settings/privacy" {
		t.Fatalf("Path = %s", got)
	}
}

func TestDiffRenameIsDeleteAndCreate(t *testing.T) {
	d := current()
	(*d.ManagedFiles)[0].Path = "/etc/motd.d/paddock"
	d.DeviceGroups = &[]declarative.DeviceGroup{{Name: "notebooks"}, {Name: "servers", Description: "racks"}}
	plan := declarative.Diff(current(), d)
	golden(t, "rename", plan)
	if plan.Created != 2 || plan.Deleted != 2 || plan.Updated != 0 {
		t.Errorf("counts %d/%d/%d, want 2 created, 0 updated, 2 deleted", plan.Created, plan.Updated, plan.Deleted)
	}
}

func TestDiffShowsFileContentAsHash(t *testing.T) {
	d := current()
	d.ManagedFiles = &[]declarative.ManagedFile{{Path: "/etc/motd", Mode: "0644", Owner: "root", Group: "root", Content: "secret-ish"}}
	plan := declarative.Diff(current(), d)
	raw, _ := json.Marshal(plan)
	if strings.Contains(string(raw), "secret-ish") || strings.Contains(string(raw), "hello") {
		t.Fatalf("plan carries file content: %s", raw)
	}
	if want := declarative.ContentSummary("secret-ish"); !strings.Contains(string(raw), want) || !strings.HasSuffix(want, "(10 bytes)") {
		t.Fatalf("plan %s lacks %s", raw, want)
	}
}

func TestDecodeFillsDefaults(t *testing.T) {
	d, err := declarative.Decode([]byte(`{"api_version":"paddock/v1","kind":"OrganizationConfig",
		"permission_profiles":[{"name":"p","class":"none"}],"managed_files":[{"path":"/etc/a","content":""}],
		"managed_units":[{"unit":"a.service"}],"package_holds":[{"package":"vim"}],"device_groups":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if p := (*d.PermissionProfiles)[0]; !p.RequirePassword || p.TimestampTimeoutMin != 5 || p.Lecture != "once" || p.Commands == nil {
		t.Errorf("profile defaults %+v", p)
	}
	if f := (*d.ManagedFiles)[0]; f.Mode != "0644" || f.Owner != "root" || f.Group != "root" || f.DeviceGroup != nil {
		t.Errorf("file defaults %+v", f)
	}
	if u := (*d.ManagedUnits)[0]; !u.Enabled || !u.Active {
		t.Errorf("unit defaults %+v", u)
	}
	if h := (*d.PackageHolds)[0]; h.Version != nil || h.Reason != "" {
		t.Errorf("hold defaults %+v", h)
	}
	if d.DeviceGroups == nil || len(*d.DeviceGroups) != 0 || d.Settings != nil || d.ProfileAssignments != nil {
		t.Errorf("sections: present empty device_groups and absent others expected, got %+v", d)
	}
}

func TestValidateJSONNamesThePaths(t *testing.T) {
	for name, c := range map[string]struct {
		doc  string
		want []string
	}{
		"mode": {`{"api_version":"paddock/v1","kind":"OrganizationConfig","managed_files":[{"path":"/etc/a","content":"","mode":"999"}]}`,
			[]string{"/managed_files/0/mode"}},
		"header":        {`{"api_version":"paddock/v2","kind":"OrganizationConfig"}`, []string{"/api_version"}},
		"unknown field": {`{"api_version":"paddock/v1","kind":"OrganizationConfig","devices":[]}`, []string{"/"}},
		"partial settings": {`{"api_version":"paddock/v1","kind":"OrganizationConfig","settings":{"updates":{"security_daily_at":"03:00"}}}`,
			[]string{"/settings/updates"}},
		"privacy days too low": {`{"api_version":"paddock/v1","kind":"OrganizationConfig","settings":{"privacy":{"retired_inventory_days":0,"audit_search_recorded":false,"inventory_view_recorded":false}}}`,
			[]string{"/settings/privacy/retired_inventory_days"}},
		"privacy days too high": {`{"api_version":"paddock/v1","kind":"OrganizationConfig","settings":{"privacy":{"retired_inventory_days":366,"audit_search_recorded":false,"inventory_view_recorded":false}}}`,
			[]string{"/settings/privacy/retired_inventory_days"}},
		"partial privacy": {`{"api_version":"paddock/v1","kind":"OrganizationConfig","settings":{"privacy":{"retired_inventory_days":14}}}`,
			[]string{"/settings/privacy"}},
		"subject": {`{"api_version":"paddock/v1","kind":"OrganizationConfig","profile_assignments":[{"profile":"p","subject":{"type":"group"}}]}`,
			[]string{"/profile_assignments/0/subject"}},
		"not json": {`{`, []string{"/"}},
	} {
		t.Run(name, func(t *testing.T) {
			err := declarative.ValidateJSON([]byte(c.doc))
			var verr *declarative.ValidationError
			if !errors.As(err, &verr) {
				t.Fatalf("ValidateJSON = %v, want a ValidationError", err)
			}
			for _, w := range c.want {
				found := false
				for _, v := range verr.Violations {
					found = found || strings.HasPrefix(v.Path, w)
				}
				if !found {
					t.Errorf("violations %v lack %s", verr.Violations, w)
				}
			}
			if len(verr.Violations) > declarative.MaxViolations {
				t.Errorf("%d violations", len(verr.Violations))
			}
		})
	}
	var many strings.Builder
	many.WriteString(`{"api_version":"paddock/v1","kind":"OrganizationConfig","managed_files":[`)
	for i := range 30 {
		if i > 0 {
			many.WriteByte(',')
		}
		many.WriteString(`{"path":1}`)
	}
	many.WriteString(`]}`)
	var verr *declarative.ValidationError
	if err := declarative.ValidateJSON([]byte(many.String())); !errors.As(err, &verr) || len(verr.Violations) != declarative.MaxViolations {
		t.Fatalf("30 bad items: %v", err)
	}
}

func TestDuplicates(t *testing.T) {
	d := current()
	*d.ManagedFiles = append(*d.ManagedFiles, (*d.ManagedFiles)[1])
	verr := declarative.Duplicates(d)
	if verr == nil || len(verr.Violations) != 1 || verr.Violations[0].Path != "/managed_files/2" {
		t.Fatalf("Duplicates = %v", verr)
	}
	if declarative.Duplicates(current()) != nil {
		t.Fatal("current() has duplicates")
	}
}

// TestSchemaCopyIsCurrent: the embedded schema is a byte-identical copy of api/schema/paddock.v1.json (make gen).
func TestSchemaCopyIsCurrent(t *testing.T) {
	want, err := os.ReadFile("../../../../api/schema/paddock.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(declarative.Schema, want) {
		t.Fatal("server/internal/domain/declarative/paddock.v1.json differs from api/schema/paddock.v1.json: run make gen")
	}
}

// TestExampleIsValid: examples/paddock.yml passes the schema and decodes with every section present.
func TestExampleIsValid(t *testing.T) {
	raw, err := os.ReadFile("../../../../examples/paddock.yml")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := yaml.YAMLToJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := declarative.ValidateJSON(doc); err != nil {
		t.Fatalf("examples/paddock.yml violates the schema: %v", err)
	}
	d, err := declarative.Decode(doc)
	if err != nil {
		t.Fatal(err)
	}
	if d.Settings == nil || d.Settings.Login == nil || d.Settings.Updates == nil || d.DeviceGroups == nil || d.PermissionProfiles == nil ||
		d.ManagedFiles == nil || d.ManagedUnits == nil || d.PackageHolds == nil || d.ProfileAssignments == nil {
		t.Fatalf("the example lacks a section: %+v", d)
	}
	if declarative.Duplicates(d) != nil {
		t.Fatal("the example has duplicate keys")
	}
}

// collisionDoc holds the items whose names contain the characters an old string key joined parts with (review 1 of
// PDK-008): a global assignment of profile "lab:ops" and the assignment of profile "ops" in group "lab", and a
// group "a:b" next to group "a".
func collisionDoc() declarative.Document {
	return declarative.Document{
		APIVersion: declarative.APIVersion, Kind: declarative.Kind,
		DeviceGroups: &[]declarative.DeviceGroup{{Name: "lab"}, {Name: "a"}, {Name: "a:b"}},
		PermissionProfiles: &[]declarative.PermissionProfile{
			{Name: "lab:ops", Class: "none", Commands: []string{}, Lecture: "once"},
			{Name: "ops", Class: "none", Commands: []string{}, Lecture: "once"},
			{Name: "b:ops", Class: "none", Commands: []string{}, Lecture: "once"},
			{Name: "x for global", Class: "none", Commands: []string{}, Lecture: "once"},
		},
		ProfileAssignments: &[]declarative.ProfileAssignment{
			{Profile: "lab:ops", Subject: declarative.Subject{Type: "global"}},
			{Profile: "ops", Subject: declarative.Subject{Type: "global"}, DeviceGroup: ptr("lab")},
			{Profile: "ops", Subject: declarative.Subject{Type: "global"}, DeviceGroup: ptr("a:b")},
			{Profile: "b:ops", Subject: declarative.Subject{Type: "global"}, DeviceGroup: ptr("a")},
			{Profile: "x", Subject: declarative.Subject{Type: "global"}},
			{Profile: "x for global", Subject: declarative.Subject{Type: "global"}},
		},
		ManagedUnits: &[]declarative.ManagedUnit{
			{Unit: "b:x.service", DeviceGroup: ptr("a"), Enabled: true, Active: true},
			{Unit: "x.service", DeviceGroup: ptr("a:b"), Enabled: true, Active: true},
		},
	}
}

// TestPlanSHA256 (plan M6c amendment 2026-10-08): the same change gives the same hash, also after a JSON round trip
// of the document; another change gives another hash.
func TestPlanSHA256(t *testing.T) {
	d := current()
	d.Settings.Updates.SecurityDailyAt = "02:30"
	first := declarative.Diff(current(), d)
	raw, _ := json.Marshal(d)
	decoded, err := declarative.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if again := declarative.Diff(current(), decoded); again.SHA256() != first.SHA256() || len(first.SHA256()) != 64 {
		t.Fatalf("hashes %s and %s", first.SHA256(), again.SHA256())
	}
	d.Settings.Updates.SecurityDailyAt = "02:31"
	if other := declarative.Diff(current(), d); other.SHA256() == first.SHA256() {
		t.Fatal("different plans have the same hash")
	}
}

func TestKeysOfItemsWithSeparatorsInNamesStayDistinct(t *testing.T) {
	d := collisionDoc()
	if verr := declarative.Duplicates(d); verr != nil {
		t.Fatalf("distinct items reported as duplicates: %v", verr)
	}
	keys := map[string]bool{}
	for _, a := range *d.ProfileAssignments {
		keys[a.Key().String()] = true
	}
	for _, u := range *d.ManagedUnits {
		keys[u.Key().String()] = true
	}
	if len(keys) != 8 {
		t.Fatalf("keys collide: %v", keys)
	}
	if got := (*d.ProfileAssignments)[1].Key().String(); got != `["lab","ops","global",null]` {
		t.Fatalf("key %s", got)
	}
	// (b) An unchanged document is a no-op.
	if plan := declarative.Diff(collisionDoc(), collisionDoc()); len(plan.Changes) != 0 {
		t.Fatalf("unchanged document: %+v", plan)
	}
	// (a) Keeping only the group-scoped "ops" deletes the global "lab:ops" instead of updating it.
	keep := collisionDoc()
	*keep.ProfileAssignments = (*keep.ProfileAssignments)[1:]
	plan := declarative.Diff(collisionDoc(), keep)
	if plan.Deleted != 1 || plan.Updated != 0 || plan.Created != 0 || plan.Changes[0].Key != `[null,"lab:ops","global",null]` {
		t.Fatalf("plan %+v", plan)
	}
	// (c) Group "a:b" with unit "x.service" and group "a" with unit "b:x.service" are different items.
	units := collisionDoc()
	*units.ManagedUnits = (*units.ManagedUnits)[:1]
	plan = declarative.Diff(collisionDoc(), units)
	if plan.Deleted != 1 || plan.Changes[0].Key != `["a:b","x.service"]` {
		t.Fatalf("plan %+v", plan)
	}
}

// TestBeforeItems (plan M11 decision 18): the before-state has the full item of every update and deletion, by section
// and key, and nothing for a creation.
func TestBeforeItems(t *testing.T) {
	d := current()
	d.Settings.Updates.SecurityDailyAt = "02:30"
	d.ManagedFiles = &[]declarative.ManagedFile{
		{Path: "/etc/motd", Mode: "0644", Owner: "root", Group: "root", Content: "hello world"},
		{Path: "/etc/issue.net", Mode: "0644", Owner: "root", Group: "root", Content: "new"},
	}
	d.PackageHolds = &[]declarative.PackageHold{}
	plan := declarative.Diff(current(), d)
	before := declarative.BeforeItems(current(), plan)

	motd, ok := before[declarative.SectionManagedFiles][`[null,"/etc/motd"]`].(declarative.ManagedFile)
	if !ok || motd.Content != "hello" {
		t.Errorf("updated file before-state %+v", before[declarative.SectionManagedFiles])
	}
	if _, ok := before[declarative.SectionManagedFiles][`[null,"/etc/issue.net"]`]; ok {
		t.Error("a created file has a before-state")
	}
	if got, ok := before[declarative.SectionManagedFiles][`["laptops","/etc/laptop.conf"]`].(declarative.ManagedFile); !ok || got.Content != "x=1" {
		t.Errorf("deleted file before-state %+v", got)
	}
	if hold, ok := before[declarative.SectionPackageHolds][`[null,"firefox"]`].(declarative.PackageHold); !ok || hold.Reason != "breaks kiosk" {
		t.Errorf("deleted hold before-state %+v", before[declarative.SectionPackageHolds])
	}
	if u, ok := before[declarative.SectionSettingsUpdates][""].(declarative.UpdateSettings); !ok || u.SecurityDailyAt != "03:00" {
		t.Errorf("settings before-state %+v", before[declarative.SectionSettingsUpdates])
	}
	if len(declarative.BeforeItems(current(), declarative.Diff(current(), current()))) != 0 {
		t.Error("an empty plan has before-states")
	}
}

func beforeJSON(t *testing.T, items map[string]map[string]any) map[string]map[string]json.RawMessage {
	t.Helper()
	out := map[string]map[string]json.RawMessage{}
	for section, byKey := range items {
		out[section] = map[string]json.RawMessage{}
		for key, item := range byKey {
			raw, err := json.Marshal(item)
			if err != nil {
				t.Fatal(err)
			}
			out[section][key] = raw
		}
	}
	return out
}

// TestRevert (plan M11 decision 21.2, amendment R6.12): the revert of a plan undoes its creations, updates and
// deletions, keeps items created since and replaces an item whose deleted key was created again since.
func TestRevert(t *testing.T) {
	changed := current()
	changed.Settings.Updates.SecurityDailyAt = "02:30"
	changed.ManagedFiles = &[]declarative.ManagedFile{
		{Path: "/etc/motd", Mode: "0644", Owner: "root", Group: "root", Content: "hello world"},
		{Path: "/etc/laptop.conf", DeviceGroup: ptr("laptops"), Mode: "0600", Owner: "root", Group: "root", Content: "x=1"},
		{Path: "/etc/issue.net", Mode: "0644", Owner: "root", Group: "root", Content: "new"},
	}
	changed.PackageHolds = &[]declarative.PackageHold{}
	original := declarative.Diff(current(), changed)
	before := beforeJSON(t, declarative.BeforeItems(current(), original))

	// Since the original: another file was created and the deleted hold was created again with another reason.
	later := changed
	files := append(slices.Clone(*changed.ManagedFiles), declarative.ManagedFile{Path: "/etc/since", Mode: "0644", Owner: "root", Group: "root", Content: "kept"})
	later.ManagedFiles = &files
	later.PackageHolds = &[]declarative.PackageHold{{Package: "firefox", Reason: "again"}}

	desired, err := declarative.Revert(later, original, before)
	if err != nil {
		t.Fatal(err)
	}
	plan := declarative.Diff(later, desired)
	got := map[string]string{}
	for _, c := range plan.Changes {
		got[c.Section+" "+c.Key] = c.Action
	}
	want := map[string]string{
		`managed_files [null,"/etc/motd"]`:      declarative.ActionUpdate,
		`managed_files [null,"/etc/issue.net"]`: declarative.ActionDelete,
		`package_holds [null,"firefox"]`:        declarative.ActionUpdate,
		`settings.updates `:                     declarative.ActionUpdate,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("revert plan %v, want %v", got, want)
	}
	if (*desired.PackageHolds)[0].Reason != "breaks kiosk" || len(*desired.PackageHolds) != 1 {
		t.Errorf("re-created hold not replaced: %+v", *desired.PackageHolds)
	}
	if desired.Settings.Updates.SecurityDailyAt != "03:00" || later.Settings.Updates.SecurityDailyAt != "02:30" {
		t.Errorf("settings: desired %s, later %s", desired.Settings.Updates.SecurityDailyAt, later.Settings.Updates.SecurityDailyAt)
	}
	if len(*later.ManagedFiles) != 4 || (*later.PackageHolds)[0].Reason != "again" {
		t.Error("Revert modified its input")
	}

	// Without changes since the original, the revert gives back exactly the configuration before it.
	if p := declarative.Diff(current(), mustRevert(t, changed, original, before)); len(p.Changes) != 0 {
		t.Errorf("revert without later changes differs from the configuration before the original: %+v", p)
	}

	delete(before[declarative.SectionManagedFiles], `[null,"/etc/motd"]`)
	if _, err := declarative.Revert(later, original, before); !errors.Is(err, declarative.ErrBeforeMissing) {
		t.Errorf("missing before-state: %v", err)
	}
}

func mustRevert(t *testing.T, d declarative.Document, plan declarative.Plan, before map[string]map[string]json.RawMessage) declarative.Document {
	t.Helper()
	out, err := declarative.Revert(d, plan, before)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
