package software

import (
	"reflect"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/bundle"
)

func id(n byte) uuid.UUID { return uuid.UUID{15: n} }

func ver(s string) *string { return &s }

func eff(n byte, pkg, intent, rule string, version *string) Effective {
	return Effective{CatalogEntryID: id(n), Package: pkg, Source: "src" + string(rune('0'+n)), Intent: intent, UpdateRule: rule, Version: version}
}

func TestMergeIntents(t *testing.T) {
	for _, tc := range []struct {
		name      string
		in        []Effective
		want      []Resolved
		holds     []bundle.Hold
		conflicts []Conflict
	}{
		{
			name: "required latest and hold with version",
			in:   []Effective{eff(1, "nano", IntentRequired, UpdateLatest, nil), eff(2, "nano", IntentHold, UpdateLatest, ver("1.0"))},
			want: []Resolved{{id(1), "nano", "src1", IntentRequired, ver("1.0")}}, holds: []bundle.Hold{{Package: "nano", Version: ver("1.0")}},
		},
		{
			name:      "two pinned versions",
			in:        []Effective{eff(1, "nano", IntentRequired, UpdatePinned, ver("2.0")), eff(2, "nano", IntentRequired, UpdatePinned, ver("1.0"))},
			want:      []Resolved{{id(1), "nano", "src1", IntentRequired, ver("1.0")}},
			conflicts: []Conflict{{Package: "nano", Versions: []*string{ver("1.0"), ver("2.0")}, Chosen: ver("1.0")}},
		},
		{
			name: "available alone",
			in:   []Effective{eff(1, "gimp", IntentAvailable, UpdateLatest, nil), eff(2, "gimp", IntentAvailable, UpdateLatest, nil)},
			want: []Resolved{{id(1), "gimp", "src1", IntentAvailable, nil}},
		},
		{
			name: "hold beats available",
			in:   []Effective{eff(1, "gimp", IntentAvailable, UpdateLatest, nil), eff(2, "gimp", IntentHold, UpdateLatest, ver("2.10"))},
			want: []Resolved{{id(2), "gimp", "src2", IntentHold, ver("2.10")}}, holds: []bundle.Hold{{Package: "gimp", Version: ver("2.10")}},
		},
		{
			name: "required beats available",
			in:   []Effective{eff(1, "gimp", IntentAvailable, UpdateLatest, nil), eff(2, "gimp", IntentRequired, UpdateLatest, nil)},
			want: []Resolved{{id(2), "gimp", "src2", IntentRequired, nil}},
		},
		{
			name: "uninstall beats available",
			in:   []Effective{eff(1, "gimp", IntentUninstall, UpdateLatest, nil), eff(2, "gimp", IntentAvailable, UpdateLatest, nil)},
			want: []Resolved{{id(1), "gimp", "src1", IntentUninstall, nil}},
		},
		{
			name: "forbid beats available",
			in:   []Effective{eff(1, "gimp", IntentAvailable, UpdateLatest, nil), eff(2, "gimp", IntentForbid, UpdateLatest, nil)},
			want: []Resolved{{id(2), "gimp", "src2", IntentForbid, nil}},
		},
		{
			name: "forbid beats required",
			in:   []Effective{eff(1, "nano", IntentRequired, UpdatePinned, ver("1.0")), eff(2, "nano", IntentForbid, UpdateLatest, nil)},
			want: []Resolved{{id(2), "nano", "src2", IntentForbid, nil}},
		},
		{
			name: "forbid beats uninstall",
			in:   []Effective{eff(1, "nano", IntentUninstall, UpdateLatest, nil), eff(2, "nano", IntentForbid, UpdateLatest, nil)},
			want: []Resolved{{id(2), "nano", "src2", IntentForbid, nil}},
		},
		{
			name: "uninstall beats hold",
			in:   []Effective{eff(1, "nano", IntentHold, UpdateLatest, ver("1.0")), eff(2, "nano", IntentUninstall, UpdateLatest, nil)},
			want: []Resolved{{id(2), "nano", "src2", IntentUninstall, nil}},
		},
		{
			name: "uninstall beats required",
			in:   []Effective{eff(1, "nano", IntentRequired, UpdateLatest, nil), eff(2, "nano", IntentUninstall, UpdateLatest, nil)},
			want: []Resolved{{id(2), "nano", "src2", IntentUninstall, nil}},
		},
		{
			name: "hold and hold with version",
			in:   []Effective{eff(1, "nano", IntentHold, UpdateLatest, nil), eff(2, "nano", IntentHold, UpdateLatest, ver("1.0"))},
			want: []Resolved{{id(1), "nano", "src1", IntentHold, ver("1.0")}}, holds: []bundle.Hold{{Package: "nano", Version: ver("1.0")}},
		},
		{
			name: "hold without version",
			in:   []Effective{eff(1, "nano", IntentHold, UpdateLatest, nil)},
			want: []Resolved{{id(1), "nano", "src1", IntentHold, nil}}, holds: []bundle.Hold{{Package: "nano"}},
		},
		{
			name: "two holds, smallest version",
			in:   []Effective{eff(1, "nano", IntentHold, UpdateLatest, ver("2.0")), eff(2, "nano", IntentHold, UpdateLatest, ver("1.0"))},
			want: []Resolved{{id(1), "nano", "src1", IntentHold, ver("1.0")}}, holds: []bundle.Hold{{Package: "nano", Version: ver("1.0")}},
			conflicts: []Conflict{{Package: "nano", Versions: []*string{ver("1.0"), ver("2.0")}, Chosen: ver("1.0")}},
		},
		{
			name: "required pinned and the same version twice",
			in:   []Effective{eff(1, "nano", IntentRequired, UpdatePinned, ver("1.0")), eff(2, "nano", IntentRequired, UpdatePinned, ver("1.0"))},
			want: []Resolved{{id(1), "nano", "src1", IntentRequired, ver("1.0")}},
		},
		{
			name: "required latest only",
			in:   []Effective{eff(1, "nano", IntentRequired, UpdateLatest, nil)},
			want: []Resolved{{id(1), "nano", "src1", IntentRequired, nil}},
		},
		{
			name: "sorted by package, one result each",
			in: []Effective{
				eff(3, "vim", IntentRequired, UpdateLatest, nil), eff(1, "emacs", IntentUninstall, UpdateLatest, nil),
				eff(2, "nano", IntentHold, UpdateLatest, nil),
			},
			want: []Resolved{
				{id(1), "emacs", "src1", IntentUninstall, nil}, {id(2), "nano", "src2", IntentHold, nil},
				{id(3), "vim", "src3", IntentRequired, nil},
			},
			holds: []bundle.Hold{{Package: "nano"}},
		},
		{name: "nothing", in: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, holds, conflicts := MergeIntents(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("resolved = %+v, want %+v", got, tc.want)
			}
			if !reflect.DeepEqual(holds, tc.holds) {
				t.Errorf("holds = %+v, want %+v", holds, tc.holds)
			}
			if !reflect.DeepEqual(conflicts, tc.conflicts) {
				t.Errorf("conflicts = %+v, want %+v", conflicts, tc.conflicts)
			}
		})
	}
}

func TestMergeIntentsSupplierIsOrderIndependent(t *testing.T) {
	a, b := eff(2, "nano", IntentRequired, UpdateLatest, nil), eff(1, "nano", IntentRequired, UpdateLatest, nil)
	one, _, _ := MergeIntents([]Effective{a, b})
	two, _, _ := MergeIntents([]Effective{b, a})
	if !reflect.DeepEqual(one, two) || one[0].CatalogEntryID != id(1) {
		t.Fatalf("%+v vs %+v", one, two)
	}
}
