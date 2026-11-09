package configrollout

import (
	"reflect"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/domain/declarative"
)

// TestStagedSoftwareAssignments (plan M13c decision 3): assignment changes are staged, sources and entries never;
// the assignments of a deleted device group are cascades and not staged. An entry has no cascade (amendment
// 2026-11-09, A10-12): the deletion of its assignment is staged next to the entry's change.
func TestStagedSoftwareAssignments(t *testing.T) {
	plan := declarative.Plan{Changes: []declarative.Change{
		{Section: declarative.SectionDeviceGroups, Key: `["gone"]`, Action: declarative.ActionDelete},
		{Section: declarative.SectionSoftwareSources, Key: `["vendor"]`, Action: declarative.ActionUpdate},
		{Section: declarative.SectionSoftwareCatalog, Key: `["Old"]`, Action: declarative.ActionUpdate},
		{Section: declarative.SectionSoftwareCatalog, Key: `["Browser"]`, Action: declarative.ActionUpdate},
		{Section: declarative.SectionSoftwareAssignments, Key: `[null,"Old","organization",null]`, Action: declarative.ActionDelete},
		{Section: declarative.SectionSoftwareAssignments, Key: `["gone","Browser","device_group",null]`, Action: declarative.ActionDelete},
		{Section: declarative.SectionSoftwareAssignments, Key: `[null,"Browser","organization",null]`, Action: declarative.ActionUpdate},
		{Section: declarative.SectionSoftwareAssignments, Key: `[null,"Editor","user","ada@example.com"]`, Action: declarative.ActionCreate},
	}}
	want := map[string]map[string]bool{declarative.SectionSoftwareAssignments: {
		`[null,"Old","organization",null]`: true, `[null,"Browser","organization",null]`: true,
		`[null,"Editor","user","ada@example.com"]`: true,
	}}
	if got := StagedKeys(plan); !reflect.DeepEqual(got, want) {
		t.Fatalf("StagedKeys = %v", got)
	}
	if got := StagedEntries(plan); !reflect.DeepEqual(got, []string{"Browser", "Editor", "Old"}) {
		t.Fatalf("StagedEntries = %v", got)
	}
	if got := StagedResourceIDs(plan); got != nil {
		t.Fatalf("StagedResourceIDs = %v, want the software resources resolved by the caller", got)
	}
	if SectionGroup(declarative.SectionSoftwareAssignments) != declarative.SectionSoftwareAssignments {
		t.Fatal("SectionGroup")
	}
}

func TestKeyEntry(t *testing.T) {
	for key, want := range map[string]string{
		`["lab","Browser","device_group",null]`: "Browser",
		`[null,"Browser","organization",null]`:  "Browser",
		`[null,"/etc/motd"]`:                    "",
		`["Browser"]`:                           "",
		"":                                      "",
	} {
		if got := KeyEntry(key); got != want {
			t.Errorf("KeyEntry(%s) = %q, want %q", key, got, want)
		}
	}
}
