package reconcile_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile/fakesys"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// fakeDpkg puts a dpkg-query and a dpkg on PATH that answer like a device with i386 enabled: libc6 is installed for
// amd64 and i386, libfoo only for i386, libgone is unknown.
func fakeDpkg(t *testing.T, native string) {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
case "$1" in
--print-architecture) echo ` + native + `;;
--show) case "$3" in
  libc6) printf 'installed i386 2.39-1\ninstalled amd64 2.39-2\n';;
  libfoo) printf 'installed i386 1.0-1\nnot-installed amd64 1.0-1\n';;
  nano) printf 'installed amd64 7.2-1\n';;
  *) echo "no packages found matching $3" >&2; exit 1;;
  esac;;
esac
`
	for _, name := range []string{"dpkg-query", "dpkg"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil { //nolint:gosec // test stub must be executable
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestOSPackageForTwoArchitectures(t *testing.T) {
	fakeDpkg(t, "amd64")
	sys := reconcile.OS{Root: "/"}
	if !sys.PackageInstalled("libc6") {
		t.Fatal("libc6 installed for two architectures counts as not installed")
	}
	if v := sys.PackageVersion("libc6"); v != "2.39-2" {
		t.Fatalf("version %q, want the native build's", v)
	}
	if a := sys.PackageRemovalNames("libc6"); !slices.Equal(a, []string{"libc6:amd64", "libc6:i386"}) {
		t.Fatalf("removal names %q", a)
	}
	if !sys.PackageInstalled("libfoo") || sys.PackageVersion("libfoo") != "1.0-1" || !slices.Equal(sys.PackageRemovalNames("libfoo"), []string{"libfoo:i386"}) {
		t.Fatal("a package installed only for the foreign architecture")
	}
	if sys.PackageInstalled("nano") != true || sys.PackageVersion("nano") != "7.2-1" || !slices.Equal(sys.PackageRemovalNames("nano"), []string{"nano"}) {
		t.Fatal("single architecture changed")
	}
	if sys.PackageInstalled("libgone") || sys.PackageVersion("libgone") != "" {
		t.Fatal("unknown package")
	}
}

func TestOSPackageVersionFallsBackToTheFirstBuild(t *testing.T) {
	fakeDpkg(t, "arm64")
	if v := (reconcile.OS{Root: "/"}).PackageVersion("libc6"); v != "2.39-1" {
		t.Fatalf("version %q", v)
	}
}

// TestSoftwareForbidRemovesEveryArchitecture: a forbidden package installed for amd64 and i386 is removed for both
// (PDK-711).
func TestSoftwareForbidRemovesEveryArchitecture(t *testing.T) {
	sys, s, events, _ := softwareFixture(t)
	sys.Packages["steam-lib"], sys.Foreign["steam-lib"], sys.Versions["steam-lib"] = true, true, "1.0"
	res := s.Apply(context.Background(), softwareResource(t, nil,
		bundle.SoftwarePackage{Package: "steam-lib", Intent: bundle.SoftwareForbid, CatalogEntryID: otherEntry}))
	if res.Status != reconcile.Changed {
		t.Fatalf("apply %+v", res)
	}
	if !slices.Contains(sys.Calls, "apt-get remove steam-lib:amd64 steam-lib:i386") {
		t.Fatalf("calls %q", sys.Calls)
	}
	if sys.PackageInstalled("steam-lib") {
		t.Fatal("a build is left")
	}
	if it := status(t, s, "steam-lib"); it.State != protocol.SoftwareStateAbsent {
		t.Fatalf("status %+v", it)
	}
	if !slices.Equal(typesOf(*events), []string{protocol.EventSoftwareRemoved}) {
		t.Fatalf("events %+v", *events)
	}
}

// TestSoftwareForbidRemovesAForeignOnlyPackage: a package without a native build is removed with the qualified name,
// a plain one would resolve to the native package apt knows and remove nothing.
func TestSoftwareForbidRemovesAForeignOnlyPackage(t *testing.T) {
	sys, s, _, _ := softwareFixture(t)
	sys.Foreign["steam-lib"], sys.Versions["steam-lib"] = true, "1.0"
	s.Apply(context.Background(), softwareResource(t, nil,
		bundle.SoftwarePackage{Package: "steam-lib", Intent: bundle.SoftwareForbid, CatalogEntryID: otherEntry}))
	if sys.PackageInstalled("steam-lib") || !slices.Contains(sys.Calls, "apt-get remove steam-lib:i386") {
		t.Fatalf("calls %q", sys.Calls)
	}
}

// TestSoftwareRequiredForTwoArchitecturesIsNotReinstalled: the installed package is neither reinstalled nor failed.
func TestSoftwareRequiredForTwoArchitecturesIsNotReinstalled(t *testing.T) {
	sys, s, _, _ := softwareFixture(t)
	sys.Packages["nano"], sys.Foreign["nano"], sys.Versions["nano"] = true, true, "7.2-1"
	s.Apply(context.Background(), softwareResource(t, nil, required("nano", "")))
	if slices.Contains(sys.Calls, "apt-get install nano") {
		t.Fatalf("calls %q", sys.Calls)
	}
	if it := status(t, s, "nano"); it.State != protocol.SoftwareStateInstalled || it.Version != "7.2-1" {
		t.Fatalf("status %+v", it)
	}
}

// TestSoftwareRemovalSimulationCountsEveryArchitecture: two Remv lines of one name for two architectures match the
// summary's two removals, a third removal the lines do not name is still refused.
func TestSoftwareRemovalSimulationCountsEveryArchitecture(t *testing.T) {
	for name, tc := range map[string]struct {
		out  string
		want bool
	}{
		"both architectures": {"Remv nano:amd64 [1]\nRemv nano:i386 [1]\n0 upgraded, 0 newly installed, 2 to remove and 0 not upgraded.\n", true},
		"unnamed removal":    {"Remv nano:amd64 [1]\nRemv nano:i386 [1]\n0 upgraded, 0 newly installed, 3 to remove and 0 not upgraded.\n", false},
	} {
		t.Run(name, func(t *testing.T) {
			sys, s, _, _ := softwareFixture(t)
			sys.Packages["nano"], sys.Foreign["nano"] = true, true
			sys.AptScript = map[string]fakesys.AptReply{"apt-get -s remove nano:amd64 nano:i386": {Output: tc.out}}
			s.Apply(context.Background(), softwareResource(t, nil,
				bundle.SoftwarePackage{Package: "nano", Intent: bundle.SoftwareUninstall, CatalogEntryID: nanoEntry}))
			if removed := slices.Contains(sys.Calls, "apt-get remove nano:amd64 nano:i386"); removed != tc.want {
				t.Fatalf("removed %v: %q", removed, sys.Calls)
			}
		})
	}
}
