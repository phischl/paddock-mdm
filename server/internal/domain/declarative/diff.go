package declarative

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strconv"
)

// Sections of a document as they appear in a plan.
const (
	SectionDeviceGroups       = "device_groups"
	SectionPermissionProfiles = "permission_profiles"
	SectionManagedFiles       = "managed_files"
	SectionManagedUnits       = "managed_units"
	SectionPackageHolds       = "package_holds"
	SectionProfileAssignments = "profile_assignments"
	SectionSettingsUpdates    = "settings.updates"
	SectionSettingsLogin      = "settings.login"
)

// Sections returns the sections in application order (plan M6c decision 14); deletions run in reverse order first.
func Sections() []string {
	return []string{SectionDeviceGroups, SectionPermissionProfiles, SectionManagedFiles, SectionManagedUnits,
		SectionPackageHolds, SectionProfileAssignments, SectionSettingsUpdates, SectionSettingsLogin}
}

// Actions of a change.
const (
	ActionCreate = "create"
	ActionUpdate = "update"
	ActionDelete = "delete"
)

// Plan is the difference between the current and the desired configuration, in application order.
type Plan struct {
	Changes []Change `json:"changes"`
	Created int      `json:"created"`
	Updated int      `json:"updated"`
	Deleted int      `json:"deleted"`
}

// Change is the creation, update or deletion of one item (or one settings section, key "").
type Change struct {
	Section string        `json:"section"`
	Key     string        `json:"key"`
	Action  string        `json:"action"`
	Fields  []FieldChange `json:"fields"`
}

// FieldChange is one field of a change; Before is nil for creations, After nil for deletions.
type FieldChange struct {
	Name   string `json:"name"`
	Before any    `json:"before"`
	After  any    `json:"after"`
}

// SHA256 is the hex SHA-256 of the plan's JSON encoding: the value a client confirms with expected_plan (plan M6c
// amendment 2026-10-08). The encoding is deterministic: the changes are in application order and every value is a
// string, number, boolean, list of strings or null.
func (p Plan) SHA256() string {
	raw, err := json.Marshal(p)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

// SectionsOf returns the sections a plan changes, in application order.
func (p Plan) SectionsOf() []string {
	out := []string{}
	for _, s := range Sections() {
		if slices.ContainsFunc(p.Changes, func(c Change) bool { return c.Section == s }) {
			out = append(out, s)
		}
	}
	return out
}

type field struct {
	name  string
	value any
}

// entry is one item of a section: its key, its fields and its position in the document.
type entry struct {
	key    Key
	fields []field
	index  int
}

// section returns whether the section is present in d and its entries.
func section(d Document, name string) (bool, []entry) {
	switch name {
	case SectionDeviceGroups:
		return entries(d.DeviceGroups, DeviceGroup.Key, DeviceGroup.fields)
	case SectionPermissionProfiles:
		return entries(d.PermissionProfiles, PermissionProfile.Key, PermissionProfile.fields)
	case SectionManagedFiles:
		return entries(d.ManagedFiles, ManagedFile.Key, ManagedFile.fields)
	case SectionManagedUnits:
		return entries(d.ManagedUnits, ManagedUnit.Key, ManagedUnit.fields)
	case SectionPackageHolds:
		return entries(d.PackageHolds, PackageHold.Key, PackageHold.fields)
	case SectionProfileAssignments:
		return entries(d.ProfileAssignments, ProfileAssignment.Key, ProfileAssignment.fields)
	case SectionSettingsUpdates:
		if d.Settings == nil || d.Settings.Updates == nil {
			return false, nil
		}
		return true, []entry{{fields: d.Settings.Updates.fields()}}
	case SectionSettingsLogin:
		if d.Settings == nil || d.Settings.Login == nil {
			return false, nil
		}
		return true, []entry{{fields: d.Settings.Login.fields()}}
	}
	return false, nil
}

func entries[T any](items *[]T, key func(T) Key, fields func(T) []field) (bool, []entry) {
	if items == nil {
		return false, nil
	}
	out := make([]entry, len(*items))
	for i, it := range *items {
		out[i] = entry{key: key(it), fields: fields(it), index: i}
	}
	return true, out
}

// Index maps every section of d to the position of each key (Key.String) in the document (paths of error messages).
func Index(d Document) map[string]map[string]int {
	out := map[string]map[string]int{}
	for _, s := range Sections() {
		present, items := section(d, s)
		if !present {
			continue
		}
		out[s] = map[string]int{}
		for _, e := range items {
			out[s][e.key.String()] = e.index
		}
	}
	return out
}

// Duplicates reports items of d that repeat the key of an earlier item of their section.
func Duplicates(d Document) *ValidationError {
	var out []Violation
	for _, s := range Sections() {
		_, items := section(d, s)
		seen := map[Key]bool{}
		for _, e := range items {
			if seen[e.key] && len(out) < MaxViolations {
				out = append(out, Violation{Path: Path(s, e.index), Message: "duplicate key " + e.key.String()})
			}
			seen[e.key] = true
		}
	}
	if len(out) == 0 {
		return nil
	}
	return &ValidationError{Violations: out}
}

// Path is the JSON pointer of an item of a section ("/managed_files/2", "/settings/login").
func Path(section string, index int) string {
	switch section {
	case SectionSettingsUpdates:
		return "/settings/updates"
	case SectionSettingsLogin:
		return "/settings/login"
	}
	return "/" + section + "/" + strconv.Itoa(index)
}

// Diff computes the changes that turn current into desired. Only sections present in desired are compared; the
// changes are in application order (deletions first, in reverse section order; then creations and updates by
// section), within a section sorted by key.
func Diff(current, desired Document) Plan {
	plan := Plan{Changes: []Change{}}
	sections := Sections()
	for i := len(sections) - 1; i >= 0; i-- {
		s := sections[i]
		present, want := section(desired, s)
		if !present || isSettings(s) {
			continue
		}
		_, have := section(current, s)
		keep := map[Key]bool{}
		for _, e := range want {
			keep[e.key] = true
		}
		for _, e := range sorted(have) {
			if !keep[e.key] {
				plan.Changes = append(plan.Changes, Change{Section: s, Key: e.key.String(), Action: ActionDelete, Fields: changed(e.fields, nil)})
				plan.Deleted++
			}
		}
	}
	for _, s := range sections {
		present, want := section(desired, s)
		if !present {
			continue
		}
		_, have := section(current, s)
		byKey := map[Key]entry{}
		for _, e := range have {
			byKey[e.key] = e
		}
		for _, e := range sorted(want) {
			old, exists := byKey[e.key]
			switch {
			case !exists && !isSettings(s):
				plan.Changes = append(plan.Changes, Change{Section: s, Key: e.key.String(), Action: ActionCreate, Fields: changed(nil, e.fields)})
				plan.Created++
			default:
				if fc := changed(old.fields, e.fields); len(fc) > 0 {
					plan.Changes = append(plan.Changes, Change{Section: s, Key: e.key.String(), Action: ActionUpdate, Fields: fc})
					plan.Updated++
				}
			}
		}
	}
	return plan
}

func isSettings(s string) bool { return s == SectionSettingsLogin || s == SectionSettingsUpdates }

func sorted(items []entry) []entry {
	out := slices.Clone(items)
	slices.SortStableFunc(out, func(a, b entry) int {
		switch {
		case a.key.String() < b.key.String():
			return -1
		case a.key.String() > b.key.String():
			return 1
		}
		return 0
	})
	return out
}

// changed lists the fields that differ between before and after; nil before or after lists every field of the other.
func changed(before, after []field) []FieldChange {
	out := []FieldChange{}
	switch {
	case before == nil:
		for _, f := range after {
			out = append(out, FieldChange{Name: f.name, After: f.value})
		}
	case after == nil:
		for _, f := range before {
			out = append(out, FieldChange{Name: f.name, Before: f.value})
		}
	default:
		old := map[string]any{}
		for _, f := range before {
			old[f.name] = f.value
		}
		for _, f := range after {
			if !reflect.DeepEqual(old[f.name], f.value) {
				out = append(out, FieldChange{Name: f.name, Before: old[f.name], After: f.value})
			}
		}
	}
	return out
}

// Key is the natural key of an item, compared as a tuple of its parts: names may contain any character, so the parts
// are never joined into one string (review 1 of PDK-008). Group is the device group of a group-scoped item
// (HasGroup false: every device of the organization); Subject parts belong to profile assignments only.
type Key struct {
	scoped, assignment bool
	HasGroup           bool
	Group, Name        string
	SubjectType        string
	Subject            string // slug or username; "" for global
}

// String is the key as plans show it: the JSON array of its parts, every part quoted, the device group null for every
// device and the subject null for global, e.g. ["laptops"], [null,"/etc/motd"], ["lab","ops","group","devs"]; "" for settings.
func (k Key) String() string {
	if k == (Key{}) {
		return "" // a settings section has no key
	}
	var parts []any
	if k.scoped {
		if k.HasGroup {
			parts = append(parts, k.Group)
		} else {
			parts = append(parts, nil)
		}
	}
	parts = append(parts, k.Name)
	if k.assignment {
		parts = append(parts, k.SubjectType)
		if k.Subject == "" {
			parts = append(parts, nil)
		} else {
			parts = append(parts, k.Subject)
		}
	}
	raw, _ := json.Marshal(parts) // strings and nil always encode
	return string(raw)
}

// scopedKey is the key of a group-scoped item.
func scopedKey(group *string, name string) Key {
	k := Key{scoped: true, Name: name}
	if group != nil {
		k.HasGroup, k.Group = true, *group
	}
	return k
}

func optional[T any](v *T) any {
	if v == nil {
		return nil
	}
	return *v
}

func list(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// ContentSummary is how a plan shows the content of a managed file: its SHA-256 and length.
func ContentSummary(content string) string {
	return fmt.Sprintf("sha256:%x (%d bytes)", sha256.Sum256([]byte(content)), len(content))
}

// Key is the natural key of a device group: its name.
func (g DeviceGroup) Key() Key { return Key{Name: g.Name} }

func (g DeviceGroup) fields() []field {
	return []field{{"name", g.Name}, {"description", g.Description}}
}

// Key is the natural key of a permission profile: its name.
func (p PermissionProfile) Key() Key { return Key{Name: p.Name} }

func (p PermissionProfile) fields() []field {
	return []field{{"name", p.Name}, {"class", p.Class}, {"commands", list(p.Commands)}, {"require_password", p.RequirePassword},
		{"timestamp_timeout_min", p.TimestampTimeoutMin}, {"lecture", p.Lecture}}
}

// Key is the natural key of a managed file: device group and path.
func (f ManagedFile) Key() Key { return scopedKey(f.DeviceGroup, f.Path) }

func (f ManagedFile) fields() []field {
	return []field{{"path", f.Path}, {"device_group", optional(f.DeviceGroup)}, {"mode", f.Mode}, {"owner", f.Owner},
		{"group", f.Group}, {"content", ContentSummary(f.Content)}}
}

// Key is the natural key of a managed unit: device group and unit.
func (u ManagedUnit) Key() Key { return scopedKey(u.DeviceGroup, u.Unit) }

func (u ManagedUnit) fields() []field {
	return []field{{"unit", u.Unit}, {"device_group", optional(u.DeviceGroup)}, {"enabled", u.Enabled}, {"active", u.Active}}
}

// Key is the natural key of a package hold: device group and package.
func (h PackageHold) Key() Key { return scopedKey(h.DeviceGroup, h.Package) }

func (h PackageHold) fields() []field {
	return []field{{"package", h.Package}, {"version", optional(h.Version)}, {"device_group", optional(h.DeviceGroup)},
		{"reason", h.Reason}}
}

// String is the plan form of a subject: global, group:<slug> or user:<username>.
func (s Subject) String() string {
	switch s.Type {
	case SubjectGroup:
		return SubjectGroup + ":" + s.Slug
	case SubjectUser:
		return SubjectUser + ":" + s.Username
	}
	return s.Type
}

// Key is the natural key of a profile assignment: device group, profile and subject.
func (a ProfileAssignment) Key() Key {
	k := scopedKey(a.DeviceGroup, a.Profile)
	k.assignment, k.SubjectType = true, a.Subject.Type
	switch a.Subject.Type {
	case SubjectGroup:
		k.Subject = a.Subject.Slug
	case SubjectUser:
		k.Subject = a.Subject.Username
	}
	return k
}

func (a ProfileAssignment) fields() []field {
	return []field{{"profile", a.Profile}, {"subject", a.Subject.String()}, {"device_group", optional(a.DeviceGroup)}}
}

func (s UpdateSettings) fields() []field {
	return []field{{"security_daily_at", s.SecurityDailyAt}, {"regular_schedule", s.RegularSchedule},
		{"regular_updates_enabled", s.RegularUpdatesEnabled}, {"max_random_delay_min", s.MaxRandomDelayMin},
		{"staleness_warning_h", s.StalenessWarningH}, {"staleness_critical_h", s.StalenessCriticalH}}
}

func (s LoginSettings) fields() []field {
	return []field{{"hello_enabled", s.HelloEnabled}, {"hello_pin_min_length", s.HelloPinMinLength},
		{"user_lock_session_action", s.UserLockSessionAction}, {"break_glass_accounts", list(s.BreakGlassAccounts)},
		{"sudoers_d_allowlist", list(s.SudoersDAllowlist)}, {"sudo_lecture_text", s.SudoLectureText},
		{"local_admin_username", s.LocalAdminUsername}, {"local_admin_rotation_days", s.LocalAdminRotationDays},
		{"rotate_after_reveal_hours", optional(s.RotateAfterRevealHours)}, {"notice_text", s.NoticeText},
		{"boot_pin_min_length", s.BootPinMinLength}}
}
