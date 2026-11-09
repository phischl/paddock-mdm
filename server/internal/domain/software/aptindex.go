package software

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Layout of an organization's Paddock repository (ADR 0050 decision 1, plan M13c decision 13).
const (
	// RepositorySuite is the suite and codename of every Paddock repository.
	RepositorySuite = "paddock"
	// RepositoryComponent is its only component.
	RepositoryComponent = "main"
)

// RepositoryArchitectures are the architectures every Paddock repository publishes an index for; a package of
// architecture all appears in each of them.
var RepositoryArchitectures = []string{ArchAMD64, ArchARM64}

// IndexPackage is a stored package as the repository index lists it: its control fields as uploaded and what the
// repository derives from the stored file.
type IndexPackage struct {
	Package, Version, Architecture string
	// Fields are the control fields by their name as written (DebControl.Fields).
	Fields   map[string]string
	Filename string
	Size     int64
	SHA256   string
}

// IndexFile is a file of the index below dists/<suite>/.
type IndexFile struct {
	Path string
	Data []byte
}

// RepositoryIndex is the unsigned index of a repository: the Packages lists, plain and gzip-compressed, per
// architecture, and the Release file that names them with their SHA-256. The same packages and date give the same
// bytes.
type RepositoryIndex struct {
	Files []IndexFile
	// ByHash are the lists again below by-hash/SHA256/<sha256> of their directory. The Release file sets
	// Acquire-By-Hash, so apt fetches the lists of the InRelease it holds by their hash: a build that fails after
	// overwriting the lists but before InRelease leaves the previous generation readable (plan M13c §3.7).
	ByHash  []IndexFile
	Release []byte
}

// releaseDate is the date format of a Release file (RFC 2822 in UTC, as apt-ftparchive writes it).
const releaseDate = "Mon, 02 Jan 2006 15:04:05 UTC"

// stanzaHead and stanzaTail order the control fields of a stanza as dpkg writes them; any other field follows the
// head in alphabetical order, and the fields derived from the stored file come before the tail.
var (
	stanzaHead = []string{"package", "source", "version", "architecture", "maintainer", "installed-size", "pre-depends",
		"depends", "recommends", "suggests", "enhances", "conflicts", "breaks", "replaces", "provides", "multi-arch",
		"section", "priority", "homepage"}
	stanzaTail = []string{"description"}
	// derived are written from the row, never from the control fields, whatever an older upload stored.
	derived = append([]string{"package", "version", "architecture"}, indexFields...)
)

// BuildIndex returns the index of pkgs dated date (plan M13c decision 13): one stanza per package in every list of its
// architecture, a package of architecture all in every list.
func BuildIndex(pkgs []IndexPackage, date time.Time) (RepositoryIndex, error) {
	sorted := slices.Clone(pkgs)
	slices.SortFunc(sorted, func(a, b IndexPackage) int {
		return strings.Compare(a.Package+"\x00"+a.Version+"\x00"+a.Architecture+"\x00"+a.Filename,
			b.Package+"\x00"+b.Version+"\x00"+b.Architecture+"\x00"+b.Filename)
	})
	var idx RepositoryIndex
	for _, arch := range RepositoryArchitectures {
		var list bytes.Buffer
		for _, p := range sorted {
			if p.Architecture != arch && p.Architecture != ArchAll {
				continue
			}
			if list.Len() > 0 {
				list.WriteByte('\n')
			}
			if err := writeStanza(&list, p); err != nil {
				return RepositoryIndex{}, err
			}
		}
		gz, err := gzipped(list.Bytes())
		if err != nil {
			return RepositoryIndex{}, err
		}
		dir := RepositoryComponent + "/binary-" + arch + "/"
		idx.Files = append(idx.Files, IndexFile{Path: dir + "Packages", Data: list.Bytes()},
			IndexFile{Path: dir + "Packages.gz", Data: gz})
	}
	for _, f := range idx.Files {
		sum := sha256.Sum256(f.Data)
		dir := f.Path[:strings.LastIndex(f.Path, "/")+1]
		idx.ByHash = append(idx.ByHash, IndexFile{Path: dir + "by-hash/SHA256/" + hex.EncodeToString(sum[:]), Data: f.Data})
	}
	idx.Release = release(idx.Files, date)
	return idx, nil
}

// writeStanza writes the stanza of p.
func writeStanza(w *bytes.Buffer, p IndexPackage) error {
	if p.Package == "" || p.Version == "" || p.Architecture == "" || p.Filename == "" || p.Size <= 0 ||
		len(p.SHA256) != sha256.Size*2 {
		return fmt.Errorf("index: package %q %q %q is incomplete", p.Package, p.Version, p.Architecture)
	}
	byKey := map[string]string{}
	for name := range p.Fields {
		key := strings.ToLower(name)
		if controlFieldName.MatchString(name) && !slices.Contains(derived, key) {
			byKey[key] = name
		}
	}
	field := func(key string) {
		if name, ok := byKey[key]; ok {
			writeField(w, name, p.Fields[name])
			delete(byKey, key)
		}
	}
	writeField(w, "Package", p.Package)
	for _, key := range stanzaHead {
		switch key {
		case "version":
			writeField(w, "Version", p.Version)
		case "architecture":
			writeField(w, "Architecture", p.Architecture)
		default:
			field(key)
		}
	}
	rest := make([]string, 0, len(byKey))
	for key := range byKey {
		if !slices.Contains(stanzaTail, key) {
			rest = append(rest, key)
		}
	}
	slices.Sort(rest)
	for _, key := range rest {
		field(key)
	}
	writeField(w, "Filename", p.Filename)
	writeField(w, "Size", fmt.Sprint(p.Size))
	writeField(w, "SHA256", p.SHA256)
	for _, key := range stanzaTail {
		field(key)
	}
	return nil
}

// writeField writes one field. A value read from the stored control fields cannot end the stanza or start a field of
// its own: every continuation line starts with a space, and an empty one is written as " ." as Debian writes an empty
// line of a description.
func writeField(w *bytes.Buffer, name, value string) {
	lines := strings.Split(value, "\n")
	w.WriteString(name + ":")
	if first := strings.TrimSpace(lines[0]); first != "" {
		w.WriteString(" " + first)
	}
	w.WriteByte('\n')
	for _, line := range lines[1:] {
		switch {
		case strings.TrimSpace(line) == "":
			line = " ."
		case line[0] != ' ' && line[0] != '\t':
			line = " " + line
		}
		w.WriteString(strings.TrimRight(line, " \t") + "\n")
	}
}

// gzipped compresses data without a name or time in the header, so the same list gives the same bytes.
func gzipped(data []byte) ([]byte, error) {
	var out bytes.Buffer
	zw, err := gzip.NewWriterLevel(&out, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(data); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// release returns the Release file naming files with their size and SHA-256. It has no Valid-Until: a device that
// cannot reach the server keeps working with the index it has (fail safe).
func release(files []IndexFile, date time.Time) []byte {
	var b strings.Builder
	b.WriteString("Origin: Paddock\nLabel: Paddock\n")
	b.WriteString("Suite: " + RepositorySuite + "\nCodename: " + RepositorySuite + "\n")
	b.WriteString("Date: " + date.UTC().Format(releaseDate) + "\n")
	b.WriteString("Acquire-By-Hash: yes\n")
	b.WriteString("Architectures: " + strings.Join(RepositoryArchitectures, " ") + "\n")
	b.WriteString("Components: " + RepositoryComponent + "\n")
	b.WriteString("Description: Packages stored in Paddock\nSHA256:\n")
	for _, f := range files {
		sum := sha256.Sum256(f.Data)
		fmt.Fprintf(&b, " %s %d %s\n", hex.EncodeToString(sum[:]), len(f.Data), f.Path)
	}
	return []byte(b.String())
}
