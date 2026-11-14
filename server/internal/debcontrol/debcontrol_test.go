package debcontrol_test

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/phischl/paddock-mdm/server/internal/debcontrol"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/debtest"
)

func read(deb []byte) (debcontrol.Fields, error) {
	return debcontrol.Read(bytes.NewReader(deb), int64(len(deb)))
}

func zst(t *testing.T, data []byte) []byte {
	t.Helper()
	w, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	return w.EncodeAll(data, nil)
}

func withControl(member string, data []byte) []byte {
	return debtest.Ar(debtest.DebianBinary(), debtest.Member{Name: member, Data: data},
		debtest.Member{Name: "data.tar.gz", Data: debtest.Gzip(debtest.Tar(nil))})
}

func TestReadCompressions(t *testing.T) {
	control := debtest.Control("paddock-agent", "0.1.0~alpha.11", "amd64")
	controlTar := debtest.Tar(map[string]string{"./control": control, "./md5sums": "x  usr/bin/paddockd\n"})
	want := debcontrol.Fields{Package: "paddock-agent", Version: "0.1.0~alpha.11", Architecture: "amd64"}
	for name, deb := range map[string][]byte{
		"gzip":         withControl("control.tar.gz", debtest.Gzip(controlTar)),
		"zstd":         withControl("control.tar.zst", zst(t, controlTar)),
		"uncompressed": withControl("control.tar", controlTar),
		"gnu names":    debtest.Ar(debtest.Member{Name: "debian-binary/", Data: []byte("2.0\n")}, debtest.Member{Name: "control.tar.gz/", Data: debtest.Gzip(controlTar)}),
		"plain name":   withControl("control.tar", debtest.Tar(map[string]string{"control": control})),
	} {
		got, err := read(deb)
		if err != nil || got != want {
			t.Errorf("%s: %+v, %v", name, got, err)
		}
	}
}

func TestReadUnsupportedCompression(t *testing.T) {
	for _, member := range []string{"control.tar.xz", "control.tar.bz2", "control.tar.lzma"} {
		_, err := read(withControl(member, []byte("whatever")))
		if !errors.Is(err, debcontrol.ErrUnsupportedCompression) {
			t.Errorf("%s: err = %v, want ErrUnsupportedCompression", member, err)
		}
	}
}

func TestReadRefusesMalformed(t *testing.T) {
	good := debtest.Deb(debtest.Control("paddock-agent", "1.0.0", "amd64"))
	// A member header whose size claims more than the archive holds.
	forged := debtest.Ar(debtest.DebianBinary(), debtest.Member{Name: "control.tar.gz", Data: []byte("abc")})
	forged = bytes.Replace(forged, []byte("3         `\n"), []byte("999999999 `\n"), 1)
	manyEntries := map[string]string{}
	for i := range 300 {
		manyEntries[fmt.Sprintf("./f%03d", i)] = ""
	}
	manyEntries["./control"] = debtest.Control("paddock-agent", "1.0.0", "amd64")
	var linkTar bytes.Buffer
	tw := tar.NewWriter(&linkTar)
	_ = tw.WriteHeader(&tar.Header{Name: "./control", Linkname: "/etc/shadow", Typeflag: tar.TypeSymlink})
	_ = tw.Close()

	for name, deb := range map[string][]byte{
		"empty":           nil,
		"not ar":          []byte("debian package"),
		"ar magic only":   []byte("!<arch>\n"),
		"truncated":       good[:len("!<arch>\n")+30],
		"forged size":     forged,
		"wrong first":     debtest.Ar(debtest.Member{Name: "control.tar", Data: []byte("x")}),
		"wrong format":    debtest.Ar(debtest.Member{Name: "debian-binary", Data: []byte("3.0\n")}),
		"no control":      debtest.Ar(debtest.DebianBinary()),
		"data second":     withControl("data.tar.gz", debtest.Gzip(debtest.Tar(nil))),
		"broken gzip":     withControl("control.tar.gz", []byte("not gzip")),
		"broken zstd":     withControl("control.tar.zst", []byte("not zstd")),
		"no control file": withControl("control.tar", debtest.Tar(map[string]string{"./md5sums": ""})),
		"traversal only":  withControl("control.tar", debtest.Tar(map[string]string{"../control": debtest.Control("paddock-agent", "1.0.0", "amd64")})),
		"symlink":         withControl("control.tar", linkTar.Bytes()),
		"many entries":    withControl("control.tar", debtest.Tar(manyEntries)),
		"two controls":    withControl("control.tar", debtest.Tar(map[string]string{"./control": debtest.Control("a", "1", "amd64"), "control": debtest.Control("b", "1", "amd64")})),
	} {
		if _, err := read(deb); !errors.Is(err, debcontrol.ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
}

// TestReadBoundsDecompression holds the decompression bomb bound: a small control member that expands beyond 8 MiB is
// refused, whatever its compression.
func TestReadBoundsDecompression(t *testing.T) {
	big := debtest.Tar(map[string]string{"./control": debtest.Control("paddock-agent", "1.0.0", "amd64"),
		"./zzz-padding": strings.Repeat("\x00", 9<<20)})
	for name, deb := range map[string][]byte{
		"gzip": withControl("control.tar.gz", debtest.Gzip(big)),
		"zstd": withControl("control.tar.zst", zst(t, big)),
	} {
		if len(deb) > 1<<20 {
			t.Fatalf("%s: the bomb is %d bytes, not small", name, len(deb))
		}
		if _, err := read(deb); !errors.Is(err, debcontrol.ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	huge := debtest.Tar(map[string]string{"./control": debtest.Control("paddock-agent", "1.0.0", "amd64") +
		"X-Pad: " + strings.Repeat("p", 2<<20) + "\n"})
	if _, err := read(withControl("control.tar.gz", debtest.Gzip(huge))); !errors.Is(err, debcontrol.ErrInvalid) {
		t.Errorf("control file above 1 MiB: err = %v, want ErrInvalid", err)
	}
}

func TestReadControlFields(t *testing.T) {
	deb := func(control string) []byte { return debtest.Deb(control) }
	got, err := read(deb("Package: paddock-agent\r\nVersion: 1.0.0\r\nArchitecture: arm64\r\nDescription: x\n more\n"))
	if err != nil || got != (debcontrol.Fields{Package: "paddock-agent", Version: "1.0.0", Architecture: "arm64"}) {
		t.Errorf("crlf and continuation of another field: %+v, %v", got, err)
	}
	got, err = read(deb("package: paddock-agent\nVERSION: 1.0.0\narchitecture: all\n\nPackage: other\n"))
	if err != nil || got != (debcontrol.Fields{Package: "paddock-agent", Version: "1.0.0", Architecture: "all"}) {
		t.Errorf("case-insensitive names, first paragraph only: %+v, %v", got, err)
	}
	for name, control := range map[string]string{
		"no package":           "Version: 1.0.0\nArchitecture: amd64\n",
		"no version":           "Package: a\nArchitecture: amd64\n",
		"no architecture":      "Package: a\nVersion: 1.0.0\n",
		"empty version":        "Package: a\nVersion:\nArchitecture: amd64\n",
		"duplicate package":    "Package: a\nPackage: b\nVersion: 1.0.0\nArchitecture: amd64\n",
		"multi-line version":   "Package: a\nVersion: 1.0.0\n 2.0.0\nArchitecture: amd64\n",
		"leading continuation": " x\nPackage: a\nVersion: 1.0.0\nArchitecture: amd64\n",
		"not a field":          "Package: a\nVersion 1.0.0\nArchitecture: amd64\n",
	} {
		if _, err := read(deb(control)); !errors.Is(err, debcontrol.ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
}
