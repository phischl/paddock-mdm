package software_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/phischl/paddock-mdm/server/internal/domain/software"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/debtest"
)

// TestParseDebFixtures reads packages dpkg-deb built (testdata/hello-*.deb, Architecture all, an epoch and a
// multi-line description): gzip and zstd control archives are read, xz is refused as an unsupported compression.
func TestParseDebFixtures(t *testing.T) {
	for _, z := range []string{"gzip", "zstd"} {
		t.Run(z, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", "hello-"+z+".deb"))
			if err != nil {
				t.Fatal(err)
			}
			c, err := software.ParseDeb(data)
			if err != nil {
				t.Fatal(err)
			}
			if c.Package != "paddock-hello" || c.Version != "1:1.2.3-1" || c.Architecture != "all" {
				t.Fatalf("control %+v", c)
			}
			if want := "test package\n A test package of the Paddock gates.\n .\n Second paragraph."; c.Fields["Description"] != want {
				t.Fatalf("Description %q, want %q", c.Fields["Description"], want)
			}
		})
	}
	data, err := os.ReadFile(filepath.Join("testdata", "hello-xz.deb"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := software.ParseDeb(data); !errors.Is(err, software.ErrDebCompression) {
		t.Fatalf("xz control archive: %v, want ErrDebCompression", err)
	}
}

// TestParseDebRefuses covers the format violations of an untrusted upload; each must wrap ErrDeb.
func TestParseDebRefuses(t *testing.T) {
	good := debtest.Control("acme-tool", "1.0-1", "amd64")
	control := func(c string) debtest.Member {
		return debtest.Member{Name: "control.tar.gz", Data: debtest.Gzip(debtest.Tar(map[string]string{"./control": c}))}
	}
	data := debtest.Member{Name: "data.tar.gz", Data: debtest.Gzip(debtest.Tar(nil))}
	bomb := func() []byte {
		var b bytes.Buffer
		w, _ := zstd.NewWriter(&b)
		_, _ = w.Write(make([]byte, 64<<20))
		_ = w.Close()
		return b.Bytes()
	}()
	for name, deb := range map[string][]byte{
		"not ar":               []byte("PK\x03\x04 zip"),
		"empty":                nil,
		"debian-binary 3.0":    debtest.Ar(debtest.Member{Name: "debian-binary", Data: []byte("3.0\n")}, control(good), data),
		"missing data":         debtest.Ar(debtest.DebianBinary(), control(good)),
		"extra member":         debtest.Ar(debtest.DebianBinary(), control(good), data, debtest.Member{Name: "_sig", Data: []byte("x")}),
		"wrong order":          debtest.Ar(control(good), debtest.DebianBinary(), data),
		"truncated member":     debtest.Ar(debtest.DebianBinary(), control(good), data)[:120],
		"no control file":      debtest.Ar(debtest.DebianBinary(), debtest.Member{Name: "control.tar.gz", Data: debtest.Gzip(debtest.Tar(map[string]string{"./md5sums": ""}))}, data),
		"traversal name":       debtest.Ar(debtest.DebianBinary(), debtest.Member{Name: "control.tar.gz", Data: debtest.Gzip(debtest.Tar(map[string]string{"../control": good}))}, data),
		"bad member name":      debtest.Ar(debtest.DebianBinary(), debtest.Member{Name: "control.tar.gz/x", Data: nil}, data),
		"zstd bomb":            debtest.Ar(debtest.DebianBinary(), debtest.Member{Name: "control.tar.zst", Data: bomb}, data),
		"gzip bomb":            debtest.Ar(debtest.DebianBinary(), debtest.Member{Name: "control.tar.gz", Data: debtest.Gzip(make([]byte, 64<<20))}, data),
		"two paragraphs":       debtest.Ar(debtest.DebianBinary(), control(good+"\nPackage: other\n"), data),
		"duplicate field":      debtest.Ar(debtest.DebianBinary(), control(good+"package: other\n"), data),
		"filename field":       debtest.Ar(debtest.DebianBinary(), control(good+"Filename: ../../other.deb\n"), data),
		"sha256 field":         debtest.Ar(debtest.DebianBinary(), control(good+"SHA256: 00\n"), data),
		"control character":    debtest.Ar(debtest.DebianBinary(), control(good+"X-Note: a\x1b[31mb\n"), data),
		"leading continuation": debtest.Ar(debtest.DebianBinary(), control(" x\n"+good), data),
		"bad package":          debtest.Ar(debtest.DebianBinary(), control(debtest.Control("Acme_Tool", "1.0", "amd64")), data),
		"package option":       debtest.Ar(debtest.DebianBinary(), control(debtest.Control("-oAPT::x", "1.0", "amd64")), data),
		"bad version":          debtest.Ar(debtest.DebianBinary(), control(debtest.Control("acme", "1.0 rm -rf", "amd64")), data),
		"bad architecture":     debtest.Ar(debtest.DebianBinary(), control(debtest.Control("acme", "1.0", "i386")), data),
		"not utf-8":            debtest.Ar(debtest.DebianBinary(), control(good+"X-Note: \xff\n"), data),
		"field without colon":  debtest.Ar(debtest.DebianBinary(), control(good+"Garbage\n"), data),
		"package continued":    debtest.Ar(debtest.DebianBinary(), control("Package: acme\n other\n"+strings.TrimPrefix(good, "Package: acme-tool\n")), data),
		"version continued":    debtest.Ar(debtest.DebianBinary(), control(strings.Replace(good, "Version: 1.0-1\n", "Version: 1.0-1\n 2\n", 1)), data),
		"arch continued":       debtest.Ar(debtest.DebianBinary(), control(strings.Replace(good, "Architecture: amd64\n", "Architecture: amd64\n\tarm64\n", 1)), data),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := software.ParseDeb(deb)
			if !errors.Is(err, software.ErrDeb) {
				t.Fatalf("ParseDeb: %v, want ErrDeb", err)
			}
		})
	}
	if _, err := software.ParseDeb(debtest.Ar(debtest.DebianBinary(), debtest.Member{Name: "control.tar.bz2", Data: []byte("x")}, data)); !errors.Is(err, software.ErrDebCompression) {
		t.Fatalf("bz2 control archive: %v, want ErrDebCompression", err)
	}
	if _, err := software.ParseDeb(make([]byte, software.MaxPackageBytes+1)); !errors.Is(err, software.ErrDeb) {
		t.Fatalf("oversized: %v", err)
	}
}

// TestParseDebAccepts covers the variants dpkg-deb writes besides the fixtures: an uncompressed control archive, a
// control file without "./" and with CRLF line ends, and a member name with the GNU "/" terminator.
func TestParseDebAccepts(t *testing.T) {
	data := debtest.Member{Name: "data.tar.xz", Data: []byte("not opened")}
	for name, deb := range map[string][]byte{
		"plain tar":  debtest.Ar(debtest.DebianBinary(), debtest.Member{Name: "control.tar", Data: debtest.Tar(map[string]string{"./control": debtest.Control("acme", "2.0", "arm64")})}, data),
		"bare name":  debtest.Ar(debtest.DebianBinary(), debtest.Member{Name: "control.tar.gz", Data: debtest.Gzip(debtest.Tar(map[string]string{"control": debtest.Control("acme", "2.0", "arm64")}))}, data),
		"crlf":       debtest.Ar(debtest.DebianBinary(), debtest.Member{Name: "control.tar.gz", Data: debtest.Gzip(debtest.Tar(map[string]string{"./control": strings.ReplaceAll(debtest.Control("acme", "2.0", "arm64"), "\n", "\r\n")}))}, data),
		"gnu suffix": debtest.Ar(debtest.Member{Name: "debian-binary/", Data: []byte("2.0\n")}, debtest.Member{Name: "control.tar/", Data: debtest.Tar(map[string]string{"./control": debtest.Control("acme", "2.0", "arm64")})}, data),
	} {
		t.Run(name, func(t *testing.T) {
			c, err := software.ParseDeb(deb)
			if err != nil {
				t.Fatal(err)
			}
			if c.Package != "acme" || c.Version != "2.0" || c.Architecture != "arm64" {
				t.Fatalf("control %+v", c)
			}
		})
	}
}

func TestPoolPath(t *testing.T) {
	for _, c := range []struct{ pkg, version, arch, want string }{
		{"acme", "1.0-1", "amd64", "pool/main/a/acme/acme_1.0-1_amd64.deb"},
		{"libacme1", "2:1.0", "arm64", "pool/main/liba/libacme1/libacme1_1.0_arm64.deb"},
		{"lib", "1", "all", "pool/main/l/lib/lib_1_all.deb"},
	} {
		if got := software.PoolPath(c.pkg, c.version, c.arch); got != c.want {
			t.Errorf("PoolPath(%s, %s, %s) = %s, want %s", c.pkg, c.version, c.arch, got, c.want)
		}
	}
}
