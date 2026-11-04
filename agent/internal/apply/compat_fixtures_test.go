package apply

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/compat"
)

// TestPreviousReleaseBundlesAreAccepted verifies every bundle of the previous releases' fixtures with the agent's own
// accepted schema list (ADR 0047 decision 2): dropping a schema version here refuses the bundles of a device that
// still runs that release.
func TestPreviousReleaseBundlesAreAccepted(t *testing.T) {
	dirs, err := filepath.Glob(filepath.Join("..", "..", "..", "pkg", "compat", "testdata", "*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(dirs) == 0 {
		t.Fatal("no release fixtures in pkg/compat/testdata")
	}
	for _, dir := range dirs {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			var meta compat.Meta
			raw, err := os.ReadFile(filepath.Join(dir, compat.MetaFile))
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(raw, &meta); err != nil {
				t.Fatal(err)
			}
			trust, err := bundle.TrustFromKeys(meta.BundleKeys)
			if err != nil {
				t.Fatal(err)
			}
			if len(meta.SchemaVersions) == 0 {
				t.Fatal("meta.json lists no schema versions")
			}
			for _, schema := range meta.SchemaVersions {
				env, err := os.ReadFile(filepath.Join(dir, compat.BundleFile(schema)))
				if err != nil {
					t.Fatal(err)
				}
				b, err := bundle.VerifyVersions(env, trust, meta.DeviceID, meta.OrganizationID, 0, SchemaVersions)
				if err != nil {
					t.Fatalf("schema %d bundle of %s: %v", schema, meta.Release, err)
				}
				if b.SchemaVersion != schema {
					t.Fatalf("decoded schema %d, want %d", b.SchemaVersion, schema)
				}
			}
		})
	}
}
