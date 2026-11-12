package software_test

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/domain/software"
)

var updateGolden = flag.Bool("update", false, "rewrite the golden files of testdata/")

func indexPackage(pkg, version, arch string, fields map[string]string) software.IndexPackage {
	sum := sha256.Sum256([]byte(pkg + version + arch))
	return software.IndexPackage{Package: pkg, Version: version, Architecture: arch, Fields: fields,
		Filename: software.PoolPath(pkg, version, arch), Size: int64(len(pkg)) * 100, SHA256: hex.EncodeToString(sum[:])}
}

// goldenIndexPackages cover the stanza order, a multi-line description with an empty line, an unknown field, an
// architecture all package and stored fields the index derives itself.
func goldenIndexPackages() []software.IndexPackage {
	return []software.IndexPackage{
		indexPackage("zeta-tool", "2.0-1", "arm64", map[string]string{"Package": "zeta-tool", "Version": "2.0-1",
			"Architecture": "arm64", "Maintainer": "Ops <ops@example.com>", "Description": "zeta\n line one"}),
		indexPackage("acme-tool", "1.0-1", "amd64", map[string]string{"Package": "acme-tool", "Version": "1.0-1",
			"Architecture": "amd64", "Description": "Acme tool\n First paragraph.\n \n Second paragraph.",
			"Depends": "libc6 (>= 2.35)", "X-Custom": "yes", "Section": "utils", "Priority": "optional",
			"Installed-Size": "12", "Maintainer": "Acme <it@acme.example>",
			"SHA256": "forged", "Filename": "pool/forged.deb"}),
		indexPackage("acme-docs", "1:3.1", "all", map[string]string{"Package": "acme-docs", "Version": "1:3.1",
			"Architecture": "all", "Description": "Acme documentation"}),
	}
}

// TestBuildIndexGolden (plan M13c decision 13): the Packages lists and the Release file match testdata/aptindex-*.golden
// (go test -update rewrites them); a package of architecture all appears in both lists; Packages.gz decompresses to
// Packages; Release names every file with its size and SHA-256 and sets Acquire-By-Hash, and each list is also
// published below by-hash/SHA256/ of its directory (§3.7); the same input gives the same bytes.
func TestBuildIndexGolden(t *testing.T) {
	date := time.Date(2026, 11, 9, 20, 0, 0, 0, time.FixedZone("CET", 3600))
	idx, err := software.BuildIndex(goldenIndexPackages(), date)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, f := range idx.Files {
		files[f.Path] = f.Data
	}
	golden(t, "aptindex-amd64-Packages.golden", files["main/binary-amd64/Packages"])
	golden(t, "aptindex-arm64-Packages.golden", files["main/binary-arm64/Packages"])
	golden(t, "aptindex-Release.golden", idx.Release)

	for _, arch := range []string{"amd64", "arm64"} {
		list := string(files["main/binary-"+arch+"/Packages"])
		if !strings.Contains(list, "Package: acme-docs\n") {
			t.Errorf("the all package is missing from the %s list", arch)
		}
		zr, err := gzip.NewReader(bytes.NewReader(files["main/binary-"+arch+"/Packages.gz"]))
		if err != nil {
			t.Fatal(err)
		}
		plain, err := io.ReadAll(zr)
		if err != nil || string(plain) != list {
			t.Errorf("%s Packages.gz does not decompress to Packages (%v)", arch, err)
		}
	}
	if strings.Contains(string(files["main/binary-amd64/Packages"]), "forged") {
		t.Error("a stored Filename or SHA256 reached the index")
	}
	for _, f := range idx.Files {
		sum := sha256.Sum256(f.Data)
		if line := fmt.Sprintf(" %s %d %s\n", hex.EncodeToString(sum[:]), len(f.Data), f.Path); !strings.Contains(string(idx.Release), line) {
			t.Errorf("Release lacks %q", line)
		}
	}
	if !strings.Contains(string(idx.Release), "\nAcquire-By-Hash: yes\n") || strings.Contains(string(idx.Release), "by-hash") {
		t.Error("Release does not announce the lists by hash, or names a by-hash path")
	}
	if len(idx.ByHash) != len(idx.Files) {
		t.Fatalf("%d lists by hash for %d lists", len(idx.ByHash), len(idx.Files))
	}
	for i, f := range idx.Files {
		sum := sha256.Sum256(f.Data)
		want := f.Path[:strings.LastIndex(f.Path, "/")] + "/by-hash/SHA256/" + hex.EncodeToString(sum[:])
		if idx.ByHash[i].Path != want || !bytes.Equal(idx.ByHash[i].Data, f.Data) {
			t.Errorf("by-hash copy of %s at %s, want %s", f.Path, idx.ByHash[i].Path, want)
		}
	}
	again, err := software.BuildIndex(append(goldenIndexPackages()[1:], goldenIndexPackages()[0]), date)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again.Release, idx.Release) {
		t.Error("the index depends on the order of the packages")
	}
}

// TestBuildIndexEmptyAndHostileFields: an empty repository publishes empty lists; a stored value cannot start a field or
// a stanza of its own; an incomplete package is refused.
func TestBuildIndexEmptyAndHostileFields(t *testing.T) {
	idx, err := software.BuildIndex(nil, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.Files) != 4 || len(idx.Files[0].Data) != 0 || !strings.Contains(string(idx.Release), "Architectures: amd64 arm64\n") {
		t.Fatalf("empty index %+v\n%s", idx.Files, idx.Release)
	}
	hostile := indexPackage("evil", "1", "amd64", map[string]string{"Description": "x\nFilename: pool/other.deb\n\nPackage: injected",
		"Bad Name": "v"})
	idx, err = software.BuildIndex([]software.IndexPackage{hostile}, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	list := string(idx.Files[0].Data)
	for _, line := range strings.Split(strings.TrimSuffix(list, "\n"), "\n") {
		if line == "" || strings.HasPrefix(line, "Package: injected") || strings.HasPrefix(line, "Filename: pool/other") ||
			strings.HasPrefix(line, "Bad Name") {
			t.Fatalf("hostile field escaped:\n%s", list)
		}
	}
	incomplete := hostile
	incomplete.SHA256 = ""
	if _, err := software.BuildIndex([]software.IndexPackage{incomplete}, time.Unix(0, 0)); err == nil {
		t.Error("a package without SHA-256 was indexed")
	}
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *updateGolden {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs:\n%s", name, got)
	}
}
