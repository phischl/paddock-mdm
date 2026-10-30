// Package evidence verifies an audit evidence package offline (plan M10 decisions 38-39): it reads the tar twice, never
// extracts it and needs no configuration, token or network.
package evidence

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/klauspost/compress/zstd"

	"github.com/phischl/paddock-mdm/pkg/auditevidence"
	"github.com/phischl/paddock-mdm/pkg/canonicaljson"
)

// Limits. The package is untrusted input; none of these is reachable by an honest builder.
const (
	// maxDecodedObject matches the builder's bound (auditwriter exportMaxDecodedObject): an object the builder did not
	// decode must not be decoded here either.
	maxDecodedObject = 256 << 20
	// maxDecodedTotal bounds the decompression work of one run.
	maxDecodedTotal = 64 << 30
	maxExportJSON   = 64 << 20
	maxManifest     = 16 << 20
	maxSignature    = 64 << 10
	maxEventLine    = 16 << 20
	maxMembers      = 2_000_000
	maxDays         = 36_600
	maxProblems     = 1000
	maxProblemRunes = 500
)

// ErrNotTar is returned for a file that does not start with a tar header.
var ErrNotTar = errors.New("not a tar archive")

// ErrLimit is returned when the package exceeds a bound of the verifier; nothing can be said about it.
var ErrLimit = errors.New("package exceeds a limit of the verifier")

// Options are the verifier's inputs besides the package.
type Options struct {
	// Fingerprint is the hex SHA-256 of the audit-chain public key the auditor obtained out of band; empty means the
	// signing key is taken from the package itself and is not authenticated.
	Fingerprint string
}

// Server is what the package says about the server-side verification; a problem here is not a verifier problem.
type Server struct {
	OK               bool     `json:"ok"`
	Problems         []string `json:"problems"`
	Runs             int      `json:"runs"`
	RunsWithProblems int      `json:"runs_with_problems"`
}

// Result is the outcome of one verification.
type Result struct {
	OK                 bool     `json:"ok"`
	OrganizationID     string   `json:"organization_id"`
	FromDay            string   `json:"from_day"`
	ToDay              string   `json:"to_day"`
	Days               int      `json:"days"`
	Objects            int      `json:"objects"`
	Events             int      `json:"events"`
	KeyVersion         int      `json:"key_version"`
	Fingerprint        string   `json:"fingerprint"`
	FingerprintChecked bool     `json:"fingerprint_checked"`
	ChainAnchor        *string  `json:"chain_anchor"`
	Server             Server   `json:"server_verification"`
	Problems           []string `json:"problems"`
}

type member struct {
	off, size int64
}

var (
	manifestName = regexp.MustCompile(`^manifests/\d{4}-\d{2}-\d{2}\.json$`)
	uuidPattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

type verifier struct {
	ra       io.ReaderAt
	res      *Result
	members  map[string]member
	order    []string
	total    int
	decoded  int64
	maxTotal int64
	dec      *zstd.Decoder
	exportBy []byte
	sigBy    []byte

	expectedHash   string
	expectedEvents int
}

// Verify checks the package in ra (size bytes). Problems of the package are in Result.Problems; the error is only
// for a file that is no tar archive or that exceeds a limit of the verifier.
func Verify(ra io.ReaderAt, size int64, opts Options) (*Result, error) {
	return verify(ra, size, opts, maxDecodedTotal)
}

// verify takes the total decoding bound as a parameter so a test can reach it without decoding 64 GiB.
func verify(ra io.ReaderAt, size int64, opts Options, maxTotal int64) (*Result, error) {
	v := &verifier{maxTotal: maxTotal, ra: ra, res: &Result{Problems: []string{}, Server: Server{Problems: []string{}}}, members: map[string]member{}}
	// A streaming decoder bounded in memory: the window of an untrusted frame must not size an allocation.
	dec, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(maxDecodedObject),
		zstd.WithDecoderMaxWindow(maxDecodedObject))
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	v.dec = dec
	if err := v.index(size); err != nil {
		return nil, err
	}
	if err := v.check(opts); err != nil {
		return nil, err
	}
	v.res.OK = len(v.res.Problems) == 0
	return v.res, nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// add records a problem. Names and texts come from the package, so everything printable is cleaned: a member name
// must not be able to rewrite a terminal line.
func (v *verifier) add(format string, args ...any) {
	switch n := len(v.res.Problems); {
	case n > maxProblems:
		return
	case n == maxProblems:
		v.res.Problems = append(v.res.Problems, "further problems are not listed")
		return
	}
	v.res.Problems = append(v.res.Problems, clean(fmt.Sprintf(format, args...)))
}

func clean(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == maxProblemRunes {
			b.WriteString("...")
			break
		}
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			r = ' '
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// unsafeName reports why a tar member name could not be extracted safely, or "".
func unsafeName(name string) string {
	switch {
	case name == "":
		return "is empty"
	case strings.HasPrefix(name, "/"):
		return "is an absolute path"
	case strings.Contains(name, "\\"):
		return "contains a backslash"
	case strings.ContainsFunc(name, func(r rune) bool { return r == utf8.RuneError || !unicode.IsPrint(r) }):
		return "contains a control or non-printable character"
	}
	for _, seg := range strings.Split(name, "/") {
		switch seg {
		case "":
			return "has an empty path segment"
		case ".", "..":
			return "has a . or .. path segment"
		}
	}
	return ""
}

// index is pass 1: it walks the headers, validates every member name, records where each member's data lies and
// reads export.json and export.sig.
func (v *verifier) index(size int64) error {
	cr := &countingReader{r: io.NewSectionReader(v.ra, 0, size)}
	tr := tar.NewReader(cr)
	for first := true; ; first = false {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) && !first {
			return nil
		}
		if err != nil {
			if first {
				return fmt.Errorf("%w: %v", ErrNotTar, err)
			}
			v.add("tar archive is damaged after %d members: %v", v.total, err)
			return nil
		}
		if v.total++; v.total > maxMembers {
			return fmt.Errorf("%w: more than %d members", ErrLimit, maxMembers)
		}
		if why := unsafeName(h.Name); why != "" {
			v.add("member %q %s", h.Name, why)
			continue
		}
		if h.Typeflag != tar.TypeReg {
			v.add("member %q is not a regular file", h.Name)
			continue
		}
		if _, dup := v.members[h.Name]; dup {
			v.add("member %q appears more than once", h.Name)
			continue
		}
		if !knownName(h.Name) {
			v.add("member %q is not part of an evidence package", h.Name)
			continue
		}
		v.members[h.Name] = member{off: cr.n, size: h.Size}
		v.order = append(v.order, h.Name)
		switch h.Name {
		case "export.json":
			v.exportBy = v.readSmall(tr, h.Name, maxExportJSON)
		case "export.sig":
			v.sigBy = v.readSmall(tr, h.Name, maxSignature)
		}
	}
}

func knownName(name string) bool {
	return name == "README.md" || name == "events.jsonl" || name == "export.json" || name == "export.sig" ||
		manifestName.MatchString(name) || strings.HasPrefix(name, "objects/")
}

func (v *verifier) readSmall(r io.Reader, name string, limit int64) []byte {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	switch {
	case err != nil:
		v.add("member %q cannot be read: %v", name, err)
		return nil
	case int64(len(b)) > limit:
		v.add("member %q is larger than %d bytes", name, limit)
		return nil
	}
	return b
}

func (v *verifier) section(name string) io.Reader {
	m := v.members[name]
	return io.NewSectionReader(v.ra, m.off, m.size)
}

func (v *verifier) hashMember(name string) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, v.section(name)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// check is pass 2: the five check groups of decision 39, in order, collecting problems.
func (v *verifier) check(opts Options) error {
	doc, keys, ok := v.checkSignature(opts)
	if !ok {
		return nil
	}
	expected, err := v.checkDays(doc, keys)
	if err != nil {
		return err
	}
	v.checkEvents(doc, expected)
	v.checkServer(doc)
	return nil
}

// checkSignature is group 1. It returns false when export.json is unusable and nothing else can be checked.
func (v *verifier) checkSignature(opts Options) (*auditevidence.Export, map[int][]byte, bool) {
	if _, ok := v.members["export.json"]; !ok {
		v.add("export.json is missing")
		return nil, nil, false
	}
	if v.exportBy == nil {
		return nil, nil, false
	}
	var doc auditevidence.Export
	if err := json.Unmarshal(v.exportBy, &doc); err != nil {
		v.add("export.json is not valid: %v", err)
		return nil, nil, false
	}
	canonical, err := canonicaljson.Transform(v.exportBy)
	if err != nil {
		v.add("export.json cannot be canonicalized: %v", err)
		return nil, nil, false
	}
	res := v.res
	res.OrganizationID, res.FromDay, res.ToDay = doc.OrganizationID, doc.FromDay, doc.ToDay
	if doc.Schema != auditevidence.ExportSchema {
		v.add("export.json has schema %q, want %q", doc.Schema, auditevidence.ExportSchema)
	}
	keys := map[int][]byte{}
	for _, k := range doc.Keys {
		if _, dup := keys[k.KeyVersion]; dup {
			v.add("export.json embeds key v%d twice", k.KeyVersion)
		}
		keys[k.KeyVersion] = k.PublicKey
		if auditevidence.Fingerprint(k.PublicKey) != k.Fingerprint {
			v.add("embedded key v%d does not match its fingerprint", k.KeyVersion)
		}
	}

	var sig auditevidence.Signature
	switch _, present := v.members["export.sig"]; {
	case !present:
		v.add("export.sig is missing")
	case v.sigBy == nil:
	case json.Unmarshal(v.sigBy, &sig) != nil:
		v.add("export.sig is not valid JSON")
	default:
		res.KeyVersion = sig.KeyVersion
		digest := auditevidence.ExportDigest(canonical)
		if !auditevidence.VerifySignature(keys, sig.KeyVersion, sig.Signature, digest[:]) {
			v.add("package signature does not verify with audit-chain v%d", sig.KeyVersion)
		}
	}
	if pub, ok := keys[sig.KeyVersion]; ok {
		res.Fingerprint = auditevidence.Fingerprint(pub)
	}
	if want := strings.ToLower(strings.TrimSpace(opts.Fingerprint)); want != "" {
		res.FingerprintChecked = true
		if res.Fingerprint != want {
			v.add("signing key fingerprint differs from --fingerprint")
		}
	}
	if !uuidPattern.MatchString(doc.OrganizationID) {
		v.add("organization_id %q is not a UUID", doc.OrganizationID)
	}
	return &doc, keys, true
}

type day struct {
	name   string
	digest [32]byte
	have   bool
}

// checkDays is groups 2 and 3 in one walk, because the objects are visited in manifest order. It returns the object
// list export.json must hold, with the event counts actually found.
func (v *verifier) checkDays(doc *auditevidence.Export, keys map[int][]byte) ([]auditevidence.Object, error) {
	from, errFrom := time.Parse(time.DateOnly, doc.FromDay)
	to, errTo := time.Parse(time.DateOnly, doc.ToDay)
	if errFrom != nil || errTo != nil || to.Before(from) || to.Sub(from) > maxDays*24*time.Hour {
		v.add("recording range %q..%q is not a valid range of at most %d days", doc.FromDay, doc.ToDay, maxDays)
		return nil, nil
	}
	listed := map[string]auditevidence.Day{}
	for _, d := range doc.Days {
		if _, dup := listed[d.Day]; dup {
			v.add("days[] of export.json lists %s twice", d.Day)
		}
		listed[d.Day] = d
	}
	eventsH := sha256.New()
	var expected []auditevidence.Object
	var objectSeq []string
	used := map[string]bool{}
	var prev day
	events := 0
	for d := from; !d.After(to); d = d.AddDate(0, 0, 1) {
		name := d.Format(time.DateOnly)
		cur := day{name: name}
		entry, inDoc := listed[name]
		delete(listed, name)
		if !inDoc {
			v.add("%s: day is missing from days[] of export.json", name)
		}
		raw, present := v.manifestBytes(name)
		if !present {
			v.add("%s: no manifest (chain broken)", name)
			v.res.Days++
			prev = cur
			continue
		}
		v.res.Days++
		manifest, digest, ok := v.checkManifest(name, raw, keys)
		if ok {
			cur.digest, cur.have = digest, true
			if inDoc {
				v.checkDayEntry(doc, entry, manifest, digest)
			}
			if name == doc.FromDay {
				anchor := manifest.PrevManifestSHA256
				v.res.ChainAnchor = anchor
				if deref(anchor) != deref(doc.ChainAnchor) {
					v.add("chain_anchor of export.json differs from the first manifest")
				}
			} else if prevHex := hex.EncodeToString(prev.digest[:]); !prev.have || deref(manifest.PrevManifestSHA256) != prevHex {
				v.add("%s: prev_manifest_sha256 does not link to the previous day", name)
			}
		}
		prev = cur
		if !ok {
			continue
		}
		dayEvents := 0
		listedObjects := slices.Clone(manifest.Objects)
		sort.Slice(listedObjects, func(i, j int) bool { return listedObjects[i].Key < listedObjects[j].Key })
		for _, o := range listedObjects {
			obj, err := v.checkObject(doc.OrganizationID, name, o, used, eventsH)
			if err != nil {
				return nil, err
			}
			if obj.Path != "" {
				if _, there := v.members[obj.Path]; there {
					objectSeq = append(objectSeq, obj.Path)
				}
			}
			dayEvents += obj.EventCount
			expected = append(expected, obj)
		}
		events += dayEvents
		if inDoc && entry.EventCount != dayEvents {
			v.add("%s: days[] of export.json counts %d events, the objects hold %d", name, entry.EventCount, dayEvents)
		}
	}
	for name := range listed {
		v.add("days[] of export.json lists %s, which is outside the recording range", name)
	}
	v.res.Objects = len(expected)
	v.expectedHash = hex.EncodeToString(eventsH.Sum(nil))
	v.expectedEvents = events
	v.checkUnlisted(used)
	v.checkObjectsList(doc, expected)
	v.checkOrder(objectSeq, used)
	if doc.EventCount != events {
		v.add("event_count of export.json (%d) differs from the %d events of the objects", doc.EventCount, events)
	}
	return expected, nil
}
