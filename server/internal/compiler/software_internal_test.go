package compiler

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/bundle"
)

// TestSoftwareFailure: a section the agent's contract refuses blocks the device's bundle with a render failure that
// names the device and the rule; a valid or absent section does not.
func TestSoftwareFailure(t *testing.T) {
	d := uuid.New()
	valid := &bundle.SoftwareSpec{Packages: []bundle.SoftwarePackage{{Package: "nano", Intent: bundle.SoftwareRequired,
		CatalogEntryID: "0b6d4c8e-6c55-4a5e-9a2f-1f7f0f5b4a11"}}}
	if f := softwareFailure(d, valid); f != nil {
		t.Fatalf("valid section: %+v", f)
	}
	if f := softwareFailure(d, nil); f != nil {
		t.Fatalf("no section: %+v", f)
	}
	invalid := &bundle.SoftwareSpec{Packages: []bundle.SoftwarePackage{{Package: "nano", Intent: bundle.SoftwareRequired,
		Source: "missing", CatalogEntryID: "0b6d4c8e-6c55-4a5e-9a2f-1f7f0f5b4a11"}}}
	f := softwareFailure(d, invalid)
	if f == nil || f.device != d || !strings.Contains(f.reason, `unknown source "missing"`) {
		t.Fatalf("invalid section: %+v", f)
	}
}

// TestAlignWithHolds: forbid and uninstall drop a hold of the same package and mark it superseded; required and hold
// take the merged hold's version; holds of other packages stay; without a section the holds pass unchanged.
func TestAlignWithHolds(t *testing.T) {
	v := func(s string) *string { return &s }
	spec := &bundle.SoftwareSpec{Packages: []bundle.SoftwarePackage{
		{Package: "a", Intent: bundle.SoftwareForbid}, {Package: "b", Intent: bundle.SoftwareUninstall},
		{Package: "c", Intent: bundle.SoftwareRequired, Version: v("2.0")}, {Package: "d", Intent: bundle.SoftwareHold},
		{Package: "e", Intent: bundle.SoftwareForbid},
	}}
	holds := []bundle.Hold{{Package: "a"}, {Package: "b", Version: v("1")}, {Package: "c", Version: v("1.0")},
		{Package: "d", Version: v("3")}, {Package: "z"}}
	got := alignWithHolds(spec, holds)
	if len(got) != 3 || got[0].Package != "c" || got[1].Package != "d" || got[2].Package != "z" {
		t.Fatalf("holds %+v", got)
	}
	p := spec.Packages
	if !p[0].SupersededHold || !p[1].SupersededHold || p[2].SupersededHold || p[3].SupersededHold || p[4].SupersededHold ||
		*p[2].Version != "1.0" || *p[3].Version != "3" {
		t.Fatalf("packages %+v", p)
	}
	if len(holds) != 5 || holds[0].Package != "a" {
		t.Fatalf("input holds changed: %+v", holds)
	}
	if got := alignWithHolds(nil, holds); len(got) != 5 {
		t.Fatalf("without a section: %+v", got)
	}
}
