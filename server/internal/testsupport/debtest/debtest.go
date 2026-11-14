// Package debtest builds binary Debian packages in memory for the tests of the package upload (plan M13c decision
// 12): the ar framing, the control archive and its compression, so a test states only what differs.
package debtest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"slices"
)

// Member is one member of an ar archive.
type Member struct {
	Name string
	Data []byte
}

// Control returns the control file of a package with the given name, version and architecture.
func Control(pkg, version, arch string) string {
	return fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: %s\nMaintainer: Paddock Test <test@example.invalid>\n"+
		"Description: test package\n A package of the Paddock tests.\n", pkg, version, arch)
}

// Deb returns a package with the given control file in a gzip control archive and an empty data archive.
func Deb(control string) []byte {
	return Ar(DebianBinary(), Member{Name: "control.tar.gz", Data: Gzip(Tar(map[string]string{"./control": control}))},
		Member{Name: "data.tar.gz", Data: Gzip(Tar(nil))})
}

// DebianBinary is the first member of every package.
func DebianBinary() Member { return Member{Name: "debian-binary", Data: []byte("2.0\n")} }

// Ar frames members as a common ar archive.
func Ar(members ...Member) []byte {
	var b bytes.Buffer
	b.WriteString("!<arch>\n")
	for _, m := range members {
		fmt.Fprintf(&b, "%-16s%-12s%-6s%-6s%-8s%-10d`\n", m.Name, "0", "0", "0", "100644", len(m.Data))
		b.Write(m.Data)
		if len(m.Data)%2 == 1 {
			b.WriteByte('\n')
		}
	}
	return b.Bytes()
}

// Tar returns a tar archive of regular files, in name order.
func Tar(files map[string]string) []byte {
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		_ = w.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(files[n])), Typeflag: tar.TypeReg})
		_, _ = w.Write([]byte(files[n]))
	}
	_ = w.Close()
	return b.Bytes()
}

// Gzip compresses data.
func Gzip(data []byte) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = w.Write(data)
	_ = w.Close()
	return b.Bytes()
}
