package software

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/klauspost/compress/zstd"

	"github.com/phischl/paddock-mdm/pkg/bundle"
)

// Errors of ParseDeb. ErrDeb is answered with 400 invalid_request, ErrDebCompression with 415 unsupported_compression.
var (
	ErrDeb            = errors.New("invalid package")
	ErrDebCompression = errors.New("unsupported compression")
)

// Limits of an uploaded package (plan M13c decision 12, ADR 0050 decision 2). The control archive and the control file
// are small in every real package; the bounds stop a decompression bomb before it costs more than a few MiB.
const (
	// MaxPackageBytes is the largest .deb the api accepts, the size bound of software_package.size.
	MaxPackageBytes = 256 << 20
	// maxControlTarBytes bounds the decompressed control archive.
	maxControlTarBytes = 8 << 20
	// maxControlFileBytes bounds the control file inside it.
	maxControlFileBytes = 1 << 20
	// maxControlEntries bounds the entries of the control archive (control, md5sums, maintainer scripts, …).
	maxControlEntries = 256
	// maxControlFields bounds the fields of the control file.
	maxControlFields = 100
	// zstdMaxWindow bounds the zstd window and so the decoder's memory: dpkg-deb writes the control archive with a
	// small window, a larger one is no package Paddock needs to read.
	zstdMaxWindow = 8 << 20
)

// Architectures a stored package may have (plan M13c decision 11).
const (
	ArchAMD64 = "amd64"
	ArchARM64 = "arm64"
	ArchAll   = "all"
)

var (
	controlFieldName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)
	// indexFields are the fields the repository index derives from the stored file (PDK-813); a control file that
	// brings its own would let the uploader point Filename at another object or forge the hashes.
	indexFields = []string{"filename", "size", "md5sum", "sha1", "sha256", "sha512", "description-md5"}
)

// DebControl is the checked control paragraph of a package.
type DebControl struct {
	Package, Version, Architecture string
	// Fields are every field of the control file by its name as written, the value without the separating space;
	// a multi-line value keeps its continuation lines with their leading white space, joined by "\n".
	Fields map[string]string
}

// ParseDeb checks that data is a binary Debian package in the format dpkg-deb writes — an ar archive of exactly
// debian-binary ("2.0\n"), control.tar[.gz|.zst] and data.tar[.*] — and returns its control paragraph. Nothing of the
// package is executed and the data archive is never opened. A control archive in xz or any other compression wraps
// ErrDebCompression; every other violation wraps ErrDeb.
func ParseDeb(data []byte) (DebControl, error) {
	if len(data) > MaxPackageBytes {
		return DebControl{}, fmt.Errorf("%w: larger than %d bytes", ErrDeb, MaxPackageBytes)
	}
	members, err := arMembers(data)
	if err != nil {
		return DebControl{}, err
	}
	if len(members) != 3 || members[0].name != "debian-binary" {
		return DebControl{}, fmt.Errorf("%w: expected the members debian-binary, control.tar.* and data.tar.*", ErrDeb)
	}
	if string(members[0].data) != "2.0\n" {
		return DebControl{}, fmt.Errorf("%w: debian-binary is not 2.0", ErrDeb)
	}
	if !strings.HasPrefix(members[2].name, "data.tar") {
		return DebControl{}, fmt.Errorf("%w: the third member is not data.tar", ErrDeb)
	}
	tarData, err := controlArchive(members[1].name, members[1].data)
	if err != nil {
		return DebControl{}, err
	}
	control, err := controlFile(tarData)
	if err != nil {
		return DebControl{}, err
	}
	return parseControl(control)
}

type arMember struct {
	name string
	data []byte
}

// arMembers splits a common ar archive; a member name longer than 16 bytes, a GNU name table or a malformed header
// is refused.
func arMembers(data []byte) ([]arMember, error) {
	const magic, header = "!<arch>\n", 60
	if !bytes.HasPrefix(data, []byte(magic)) {
		return nil, fmt.Errorf("%w: not an ar archive", ErrDeb)
	}
	var out []arMember
	for rest := data[len(magic):]; len(rest) > 0; {
		if len(rest) < header || string(rest[58:60]) != "`\n" {
			return nil, fmt.Errorf("%w: malformed ar header", ErrDeb)
		}
		name := strings.TrimSuffix(strings.TrimRight(string(rest[:16]), " "), "/")
		size, err := strconv.ParseInt(strings.TrimRight(string(rest[48:58]), " "), 10, 64)
		if err != nil || size < 0 || size > int64(len(rest)-header) {
			return nil, fmt.Errorf("%w: malformed ar member size", ErrDeb)
		}
		if name == "" || strings.ContainsAny(name, "/\x00") {
			return nil, fmt.Errorf("%w: malformed ar member name", ErrDeb)
		}
		if len(out) == 3 {
			return nil, fmt.Errorf("%w: more than three ar members", ErrDeb)
		}
		out = append(out, arMember{name: name, data: rest[header : header+size]})
		next := header + size
		if size%2 == 1 && next < int64(len(rest)) {
			next++ // ar pads every member to an even offset
		}
		rest = rest[next:]
	}
	return out, nil
}

// controlArchive returns the decompressed control archive, at most maxControlTarBytes.
func controlArchive(name string, data []byte) ([]byte, error) {
	var r io.Reader
	switch name {
	case "control.tar":
		r = bytes.NewReader(data)
	case "control.tar.gz":
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("%w: control.tar.gz: %v", ErrDeb, err)
		}
		defer gz.Close()
		gz.Multistream(false)
		r = gz
	case "control.tar.zst":
		zr, err := zstd.NewReader(bytes.NewReader(data), zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderMaxMemory(maxControlTarBytes), zstd.WithDecoderMaxWindow(zstdMaxWindow))
		if err != nil {
			return nil, fmt.Errorf("%w: control.tar.zst: %v", ErrDeb, err)
		}
		defer zr.Close()
		r = zr
	default:
		if strings.HasPrefix(name, "control.tar.") {
			return nil, fmt.Errorf("%w: %s; build the package with dpkg-deb -Zgzip or -Zzstd", ErrDebCompression, name)
		}
		return nil, fmt.Errorf("%w: the second member is not control.tar", ErrDeb)
	}
	out, err := io.ReadAll(io.LimitReader(r, maxControlTarBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrDeb, name, err)
	}
	if len(out) > maxControlTarBytes {
		return nil, fmt.Errorf("%w: the control archive is larger than %d bytes decompressed", ErrDeb, maxControlTarBytes)
	}
	return out, nil
}

// controlFile returns the control file of the control archive: the regular file ./control (or control). Other entries
// are skipped unread; nothing is written to disk, so their names cannot reach any path.
func controlFile(tarData []byte) ([]byte, error) {
	tr := tar.NewReader(bytes.NewReader(tarData))
	var control []byte
	for n := 0; ; n++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: control archive: %v", ErrDeb, err)
		}
		if n == maxControlEntries {
			return nil, fmt.Errorf("%w: the control archive has more than %d entries", ErrDeb, maxControlEntries)
		}
		if h.Name != "./control" && h.Name != "control" {
			continue
		}
		if h.Typeflag != tar.TypeReg || control != nil {
			return nil, fmt.Errorf("%w: control is not one regular file", ErrDeb)
		}
		if h.Size > maxControlFileBytes {
			return nil, fmt.Errorf("%w: the control file is larger than %d bytes", ErrDeb, maxControlFileBytes)
		}
		if control, err = io.ReadAll(tr); err != nil {
			return nil, fmt.Errorf("%w: control archive: %v", ErrDeb, err)
		}
	}
	if control == nil {
		return nil, fmt.Errorf("%w: the control archive has no control file", ErrDeb)
	}
	return control, nil
}

// parseControl parses the single paragraph of a control file (deb822) and checks Package, Version and Architecture.
func parseControl(data []byte) (DebControl, error) {
	if !utf8.Valid(data) {
		return DebControl{}, fmt.Errorf("%w: the control file is not UTF-8", ErrDeb)
	}
	text := strings.TrimRight(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	c := DebControl{Fields: map[string]string{}}
	seen := map[string]bool{}
	var last string
	for i, line := range strings.Split(text, "\n") {
		if strings.IndexFunc(line, func(r rune) bool { return r != '\t' && unicode.IsControl(r) }) >= 0 {
			return DebControl{}, fmt.Errorf("%w: control line %d has a control character", ErrDeb, i+1)
		}
		switch {
		case line == "":
			return DebControl{}, fmt.Errorf("%w: the control file has more than one paragraph", ErrDeb)
		case line[0] == ' ' || line[0] == '\t':
			if last == "" {
				return DebControl{}, fmt.Errorf("%w: control line %d continues no field", ErrDeb, i+1)
			}
			// The index and the pool path use the parsed single-line value; a continuation would make the published
			// field differ from it.
			if k := strings.ToLower(last); k == "package" || k == "version" || k == "architecture" {
				return DebControl{}, fmt.Errorf("%w: the control field %s must be a single line", ErrDeb, last)
			}
			c.Fields[last] += "\n" + line
		default:
			name, value, ok := strings.Cut(line, ":")
			if !ok || !controlFieldName.MatchString(name) {
				return DebControl{}, fmt.Errorf("%w: control line %d is not a field", ErrDeb, i+1)
			}
			key := strings.ToLower(name)
			if seen[key] {
				return DebControl{}, fmt.Errorf("%w: the control field %s appears twice", ErrDeb, name)
			}
			if slices.Contains(indexFields, key) {
				return DebControl{}, fmt.Errorf("%w: the control file must not set %s", ErrDeb, name)
			}
			if len(seen) == maxControlFields {
				return DebControl{}, fmt.Errorf("%w: more than %d control fields", ErrDeb, maxControlFields)
			}
			seen[key], last = true, name
			c.Fields[name] = strings.TrimLeft(value, " \t")
			switch key {
			case "package":
				c.Package = strings.TrimSpace(value)
			case "version":
				c.Version = strings.TrimSpace(value)
			case "architecture":
				c.Architecture = strings.TrimSpace(value)
			}
		}
	}
	switch {
	case !bundle.ValidPackage(c.Package):
		return DebControl{}, fmt.Errorf("%w: Package %q is not a Debian package name", ErrDeb, DisplayParam(c.Package, 64))
	case !bundle.ValidPackageVersion(c.Version):
		return DebControl{}, fmt.Errorf("%w: Version %q is not a Debian version", ErrDeb, DisplayParam(c.Version, 64))
	case !slices.Contains([]string{ArchAMD64, ArchARM64, ArchAll}, c.Architecture):
		return DebControl{}, fmt.Errorf("%w: Architecture must be amd64, arm64 or all", ErrDeb)
	}
	return c, nil
}

// PoolPath is the path of a stored package inside its repository (ADR 0050 decision 1):
// pool/main/<p>/<package>/<package>_<version>_<arch>.deb, where <p> is the package's first letter, or "lib" and the
// next letter for a library, and the version is written without its epoch, as Debian names its files.
func PoolPath(pkg, version, arch string) string {
	prefix := pkg[:1]
	if strings.HasPrefix(pkg, "lib") && len(pkg) > 3 {
		prefix = pkg[:4]
	}
	if _, v, ok := strings.Cut(version, ":"); ok {
		version = v
	}
	return "pool/main/" + prefix + "/" + pkg + "/" + pkg + "_" + version + "_" + arch + ".deb"
}
