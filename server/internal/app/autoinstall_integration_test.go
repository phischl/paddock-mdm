package app_test

import (
	"context"
	"encoding/base64"
	"testing"

	"aead.dev/minisign"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// withPackages publishes a release with the given Debian packages (amd64).
func (h releaseHarness) withPackages(t *testing.T, names ...string) string {
	t.Helper()
	ctx := platformAdmin()
	v := uniqueVersion()
	if _, err := h.releases.Create(ctx, v); err != nil {
		t.Fatal(err)
	}
	bin := []byte("paddockd " + v)
	if _, err := h.releases.UploadArtifact(ctx, v, "amd64", bin, h.signBinary(bin, v, "amd64")); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		deb := []byte(name + " " + v)
		if _, err := h.releases.UploadPackage(ctx, v, name, "amd64", deb, base64.StdEncoding.EncodeToString(minisign.Sign(h.priv, deb))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.releases.Publish(ctx, v); err != nil {
		t.Fatal(err)
	}
	return v
}

// TestInstallPackagesSelection checks which release new devices install (plan M4b decision 2): the newest published
// release with both packages for the architecture whose rollout is not halted, read by the api in organization
// scope.
func TestInstallPackagesSelection(t *testing.T) {
	h := newReleaseHarness(t, true)
	h.haltAll(t)
	api, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(api.Close)
	org, _ := h.device(t)
	install := func() []pgstore.InstallPackagesRow {
		t.Helper()
		var rows []pgstore.InstallPackagesRow
		if err := api.InOrg(systemCtx(org), func(ctx context.Context, q *pgstore.Queries) error {
			var err error
			rows, err = q.InstallPackages(ctx, "amd64")
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return rows
	}
	both := h.withPackages(t, "paddock-agent", "paddock-supervisor")
	_ = h.withPackages(t, "paddock-agent") // newer, but incomplete
	if rows := install(); len(rows) != 2 || rows[0].Version != both || rows[0].Name != "paddock-supervisor" || rows[1].Name != "paddock-agent" {
		t.Fatalf("install packages %+v, want both packages of %s", rows, both)
	}
	halted := h.withPackages(t, "paddock-agent", "paddock-supervisor")
	if _, err := h.releases.StartRollout(platformAdmin(), halted, app.RolloutOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.releases.Halt(platformAdmin(), halted); err != nil {
		t.Fatal(err)
	}
	if rows := install(); len(rows) != 2 || rows[0].Version != both {
		t.Fatalf("a halted release is installed: %+v", rows)
	}
	newest := h.withPackages(t, "paddock-agent", "paddock-supervisor")
	if rows := install(); len(rows) != 2 || rows[0].Version != newest || rows[0].ObjectKey != "packages/"+newest+"/paddock-supervisor_"+newest+"_amd64.deb" {
		t.Fatalf("install packages %+v, want %s", rows, newest)
	}
}
