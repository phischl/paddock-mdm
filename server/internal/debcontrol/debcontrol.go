// Package debcontrol reads the identity of a binary Debian package — the Package, Version and Architecture fields of
// its control file — without unpacking it, so that a release package can be checked against the name, release and
// architecture it is stored under (plan M19 D6, ADR 0043 amendment 2026-11-11 b). The package is untrusted input: every
// size is bounded, nothing is written to disk and the data archive is never opened.
package debcontrol

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// Errors of Read. ErrUnsupportedCompression wraps a control archive in xz or another compression than gzip or zstd;
// every other violation wraps ErrInvalid.
var (
	ErrInvalid                = errors.New("debcontrol: invalid Debian package")
	ErrUnsupportedCompression = errors.New("debcontrol: unsupported control compression")
)

// Bounds of the control part of a package. Real control archives are a few KiB; the bounds stop a decompression bomb
// or a forged member size before it costs more than a few MiB.
const (
	maxControlMemberBytes = 8 << 20
	maxControlTarBytes    = 8 << 20
	maxControlFileBytes   = 1 << 20
	maxControlEntries     = 256
	// zstdMaxWindow bounds the zstd window and so the decoder's memory; dpkg-deb writes the control archive with a
	// small window.
	zstdMaxWindow = 8 << 20
)

const (
	arMagic       = "!<arch>\n"
	arHeaderBytes = 60
)

// Fields are the identity fields of a package's control file.
type Fields struct {
	Package, Version, Architecture string
}

// Read returns the control fields of the binary Debian package of size bytes in r: an ar archive whose first member is
// debian-binary ("2.0\n") and whose second member is control.tar, control.tar.gz or control.tar.zst with a single
// regular file ./control. Package, Version and Architecture must each appear exactly once, on one line.
func Read(r io.ReaderAt, size int64) (Fields, error) {
	magic := make([]byte, len(arMagic))
	if _, err := r.ReadAt(magic, 0); err != nil || string(magic) != arMagic {
		return Fields{}, fmt.Errorf("%w: not an ar archive", ErrInvalid)
	}
	off := int64(len(arMagic))
	name, dataOff, dataSize, err := arMember(r, size, off)
	if err != nil {
		return Fields{}, err
	}
	if name != "debian-binary" || dataSize != 4 {
		return Fields{}, fmt.Errorf("%w: the first member is not debian-binary 2.0", ErrInvalid)
	}
	version := make([]byte, 4)
	if _, err := r.ReadAt(version, dataOff); err != nil || string(version) != "2.0\n" {
		return Fields{}, fmt.Errorf("%w: the first member is not debian-binary 2.0", ErrInvalid)
	}
	name, dataOff, dataSize, err = arMember(r, size, dataOff+dataSize+dataSize%2)
	if err != nil {
		return Fields{}, err
	}
	if dataSize > maxControlMemberBytes {
		return Fields{}, fmt.Errorf("%w: the control member is larger than %d bytes", ErrInvalid, maxControlMemberBytes)
	}
	tarReader, closeFn, err := controlArchive(name, io.NewSectionReader(r, dataOff, dataSize))
	if err != nil {
		return Fields{}, err
	}
	defer closeFn()
	control, err := controlFile(io.LimitReader(tarReader, maxControlTarBytes))
	if err != nil {
		return Fields{}, err
	}
	return parse(control)
}

// arMember reads the ar member header at off and returns the member's name and the offset and size of its data, which
// must lie inside the archive.
func arMember(r io.ReaderAt, size, off int64) (name string, dataOff, dataSize int64, err error) {
	header := make([]byte, arHeaderBytes)
	if off+arHeaderBytes > size {
		return "", 0, 0, fmt.Errorf("%w: truncated ar archive", ErrInvalid)
	}
	if _, err := r.ReadAt(header, off); err != nil || string(header[58:60]) != "`\n" {
		return "", 0, 0, fmt.Errorf("%w: malformed ar header", ErrInvalid)
	}
	name = strings.TrimSuffix(strings.TrimRight(string(header[:16]), " "), "/")
	dataSize, err = strconv.ParseInt(strings.TrimRight(string(header[48:58]), " "), 10, 64)
	dataOff = off + arHeaderBytes
	if err != nil || dataSize < 0 || dataSize > size-dataOff {
		return "", 0, 0, fmt.Errorf("%w: malformed ar member size", ErrInvalid)
	}
	return name, dataOff, dataSize, nil
}

// controlArchive returns the decompressed stream of the control member name and the function that releases its
// decoder.
func controlArchive(name string, member io.Reader) (io.Reader, func(), error) {
	switch name {
	case "control.tar":
		return member, func() {}, nil
	case "control.tar.gz":
		gz, err := gzip.NewReader(member)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: control.tar.gz: %v", ErrInvalid, err)
		}
		gz.Multistream(false)
		return gz, func() { _ = gz.Close() }, nil
	case "control.tar.zst":
		zr, err := zstd.NewReader(member, zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderMaxMemory(maxControlTarBytes), zstd.WithDecoderMaxWindow(zstdMaxWindow))
		if err != nil {
			return nil, nil, fmt.Errorf("%w: control.tar.zst: %v", ErrInvalid, err)
		}
		return zr, zr.Close, nil
	}
	if strings.HasPrefix(name, "control.tar.") {
		return nil, nil, fmt.Errorf("%w: %s; build the package with gzip or zstd", ErrUnsupportedCompression, name)
	}
	return nil, nil, fmt.Errorf("%w: the second member is not control.tar", ErrInvalid)
}

// controlFile returns the regular file ./control (or control) of the control archive. Other entries are skipped
// unread; nothing is written to disk, so no entry name can reach a path.
func controlFile(archive io.Reader) ([]byte, error) {
	tr := tar.NewReader(archive)
	var control []byte
	for n := 0; ; n++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: control archive: %v", ErrInvalid, err)
		}
		if n == maxControlEntries {
			return nil, fmt.Errorf("%w: the control archive has more than %d entries", ErrInvalid, maxControlEntries)
		}
		if h.Name != "./control" && h.Name != "control" {
			continue
		}
		if h.Typeflag != tar.TypeReg || control != nil {
			return nil, fmt.Errorf("%w: control is not one regular file", ErrInvalid)
		}
		if h.Size > maxControlFileBytes {
			return nil, fmt.Errorf("%w: the control file is larger than %d bytes", ErrInvalid, maxControlFileBytes)
		}
		if control, err = io.ReadAll(tr); err != nil {
			return nil, fmt.Errorf("%w: control archive: %v", ErrInvalid, err)
		}
	}
	if control == nil {
		return nil, fmt.Errorf("%w: the control archive has no control file", ErrInvalid)
	}
	return control, nil
}

// parse reads Package, Version and Architecture from the first paragraph of a control file; other fields are skipped.
func parse(control []byte) (Fields, error) {
	var f Fields
	seen := map[string]bool{}
	last := ""
	for i, line := range strings.Split(strings.ReplaceAll(string(control), "\r\n", "\n"), "\n") {
		if line == "" {
			break
		}
		if line[0] == ' ' || line[0] == '\t' {
			if last == "" {
				return Fields{}, fmt.Errorf("%w: control line %d continues no field", ErrInvalid, i+1)
			}
			if seen[last] && identity(last) {
				return Fields{}, fmt.Errorf("%w: the control field %s must be a single line", ErrInvalid, last)
			}
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return Fields{}, fmt.Errorf("%w: control line %d is not a field", ErrInvalid, i+1)
		}
		last = strings.ToLower(name)
		if !identity(last) {
			continue
		}
		if seen[last] {
			return Fields{}, fmt.Errorf("%w: the control field %s appears twice", ErrInvalid, name)
		}
		seen[last] = true
		value = strings.TrimSpace(value)
		switch last {
		case "package":
			f.Package = value
		case "version":
			f.Version = value
		case "architecture":
			f.Architecture = value
		}
	}
	if f.Package == "" || f.Version == "" || f.Architecture == "" {
		return Fields{}, fmt.Errorf("%w: the control file lacks Package, Version or Architecture", ErrInvalid)
	}
	return f, nil
}

func identity(field string) bool {
	return field == "package" || field == "version" || field == "architecture"
}
