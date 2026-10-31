package auditwriter

import (
	"archive/tar"
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/auditevidence"
)

// TestPackageSizeLongNames: a member name tar cannot store in a plain header adds extension records; packageSize
// counts them as tar.Writer writes them.
func TestPackageSizeLongNames(t *testing.T) {
	mtime := time.Date(2026, 10, 31, 4, 5, 6, 0, time.UTC)
	long := "objects/" + strings.Repeat("x", 180) + ".jsonl.zst"
	c := &collected{eventsSz: 1000, days: []packDay{{
		day: "2026-10-30", raw: []byte(`{"m":1}`),
		objects: []auditevidence.Object{{Path: "objects/2026/10/30/04-a.jsonl.zst"}, {Path: long}},
		sizes:   []int64{511, 513},
	}}}
	readme, exportJSON, sigFile := []byte("readme"), []byte(`{"e":1}`), []byte(`{"s":1}`)

	var pkg bytes.Buffer
	tw := tar.NewWriter(&pkg)
	write := func(name string, size int64) {
		if err := tw.WriteHeader(tarHeader(name, size, mtime)); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(make([]byte, size)); err != nil {
			t.Fatal(err)
		}
	}
	write("README.md", int64(len(readme)))
	write("manifests/2026-10-30.json", int64(len(c.days[0].raw)))
	write(c.days[0].objects[0].Path, 511)
	write(long, 513)
	write("events.jsonl", c.eventsSz)
	write("export.json", int64(len(exportJSON)))
	write("export.sig", int64(len(sigFile)))
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := packageSize(mtime, readme, c, exportJSON, sigFile)
	if err != nil {
		t.Fatal(err)
	}
	if got != int64(pkg.Len()) {
		t.Fatalf("packageSize = %d, tar.Writer wrote %d", got, pkg.Len())
	}
	if pkg.Len() <= 8*512+1024+512*5 {
		t.Fatalf("the long name added no extension records (%d bytes)", pkg.Len())
	}
}
