package app_test

import (
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
)

// TestUpdatesSectionMergesSoftwareHolds (ADR 0042 decision 3): the holds of the device's software assignments merge
// with the package holds that apply to its groups, one per package, the smallest version winning.
func TestUpdatesSectionMergesSoftwareHolds(t *testing.T) {
	v := func(s string) *string { return &s }
	g, other := uuid.New(), uuid.New()
	holds := []pgstore.PackageHold{
		{Package: "openssl"},
		{Package: "nano", Version: v("2.0"), DeviceGroupID: uuid.NullUUID{UUID: g, Valid: true}},
		{Package: "vim", Version: v("1.0"), DeviceGroupID: uuid.NullUUID{UUID: other, Valid: true}},
	}
	software := []bundle.Hold{{Package: "nano", Version: v("1.5")}, {Package: "curl"}}
	got := app.UpdatesSection(app.UpdateSettings{}, holds, software, []uuid.UUID{g}).Holds
	want := map[string]string{"curl": "", "nano": "1.5", "openssl": ""}
	if len(got) != len(want) {
		t.Fatalf("holds %+v", got)
	}
	for i, h := range got {
		version := ""
		if h.Version != nil {
			version = *h.Version
		}
		if w, ok := want[h.Package]; !ok || w != version || (i > 0 && got[i-1].Package >= h.Package) {
			t.Fatalf("holds %+v", got)
		}
	}
	if s := app.UpdatesSection(app.UpdateSettings{}, holds, nil, []uuid.UUID{other}).Holds; len(s) != 2 || s[0].Package != "openssl" || s[1].Package != "vim" {
		t.Fatalf("holds without software %+v", s)
	}
}
