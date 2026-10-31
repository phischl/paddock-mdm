package evidence

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"slices"
	"strings"

	"github.com/phischl/paddock-mdm/pkg/auditevidence"
)

func (v *verifier) manifestBytes(name string) ([]byte, bool) {
	key := "manifests/" + name + ".json"
	m, ok := v.members[key]
	if !ok {
		return nil, false
	}
	if m.size > maxManifest {
		v.add("%s: manifest is larger than %d bytes", name, maxManifest)
		return []byte{}, true
	}
	b, err := io.ReadAll(v.section(key))
	if err != nil {
		v.add("%s: manifest cannot be read: %v", name, err)
		return []byte{}, true
	}
	return b, true
}

// checkManifest verifies one manifest file; ok is false when it cannot serve as the link of the chain.
func (v *verifier) checkManifest(name string, raw []byte, keys map[int][]byte) (auditevidence.Manifest, [32]byte, bool) {
	var file auditevidence.ManifestFile
	if err := json.Unmarshal(raw, &file); err != nil {
		v.add("%s: manifest object is not valid JSON", name)
		return auditevidence.Manifest{}, [32]byte{}, false
	}
	canonical, digest, err := auditevidence.ManifestDigest(file)
	if err != nil {
		v.add("%s: manifest cannot be canonicalized", name)
		return auditevidence.Manifest{}, [32]byte{}, false
	}
	if !auditevidence.VerifySignature(keys, file.KeyVersion, file.Signature, digest[:]) {
		v.add("%s: signature does not verify with audit-chain v%d", name, file.KeyVersion)
	}
	var m auditevidence.Manifest
	if err := json.Unmarshal(canonical, &m); err != nil {
		v.add("%s: manifest does not parse", name)
		return m, digest, false
	}
	if m.OrganizationID != v.res.OrganizationID || m.Day != name || m.Schema != auditevidence.ManifestSchema {
		v.add("%s: manifest belongs to %s/%s with schema %s", name, m.OrganizationID, m.Day, m.Schema)
	}
	return m, digest, true
}

func (v *verifier) checkDayEntry(doc *auditevidence.Export, e auditevidence.Day, m auditevidence.Manifest, digest [32]byte) {
	if e.ManifestSHA256 != hex.EncodeToString(digest[:]) {
		v.add("%s: manifest does not match manifest_sha256 of export.json", e.Day)
	}
	if want := "org/" + doc.OrganizationID + "/manifests/" + e.Day + ".json"; e.ManifestKey != want {
		v.add("%s: manifest_key of export.json is %s, want %s", e.Day, e.ManifestKey, want)
	}
	if e.ObjectCount != len(m.Objects) {
		v.add("%s: days[] of export.json counts %d objects, the manifest lists %d", e.Day, e.ObjectCount, len(m.Objects))
	}
}

type lineCounter struct{ n int }

func (c *lineCounter) Write(p []byte) (int, error) {
	c.n += bytes.Count(p, []byte("\n"))
	return len(p), nil
}

// decodeInto appends the decoded object to h. On any failure h is restored, so an object the builder did not decode
// contributes nothing to the expected events.jsonl (plan M10 amendment 2026-10-30, item 5).
func (v *verifier) decodeInto(name string, h hash.Hash) (int, error) {
	state, err := h.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		return 0, err
	}
	if err := v.dec.Reset(v.section(name)); err != nil {
		return 0, err
	}
	lc := &lineCounter{}
	n, err := io.Copy(io.MultiWriter(h, lc), &io.LimitedReader{R: v.dec, N: maxDecodedObject + 1})
	// Counted on the error path too, or objects that fail after a lot of output would escape the total bound.
	v.decoded += n
	if err == nil && n > maxDecodedObject {
		err = fmt.Errorf("decoded size exceeds %d bytes", int64(maxDecodedObject))
	}
	if err != nil {
		if rerr := h.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); rerr != nil {
			return 0, rerr
		}
		return 0, err
	}
	return lc.n, nil
}

// checkObject is group 3 for one manifest entry and feeds the expected events hash. The returned object is the entry
// export.json must hold: the hash of the packed bytes and 0 events when the object is not decoded.
func (v *verifier) checkObject(org, dayName string, o auditevidence.ManifestObject, used map[string]bool, eventsH hash.Hash) (auditevidence.Object, error) {
	path, err := auditevidence.ObjectPath(org, o.Key)
	if err != nil {
		v.add("%s: object %s is outside the organization prefix or not a plain path", dayName, o.Key)
		return auditevidence.Object{Key: o.Key, SHA256: o.SHA256}, nil
	}
	obj := auditevidence.Object{Key: o.Key, Path: path, SHA256: o.SHA256}
	if used[path] {
		v.add("%s: object %s is listed more than once", dayName, o.Key)
		return obj, nil
	}
	used[path] = true
	if _, ok := v.members[path]; !ok {
		v.add("%s: object %s is missing from the package", dayName, o.Key)
		return obj, nil
	}
	sum, err := v.hashMember(path)
	if err != nil {
		v.add("%s: object %s cannot be read: %v", dayName, o.Key, err)
		return obj, nil
	}
	obj.SHA256 = sum
	if sum != o.SHA256 {
		v.add("%s: object %s was modified (SHA-256 mismatch)", dayName, o.Key)
		return obj, nil
	}
	lines, err := v.decodeInto(path, eventsH)
	if v.decoded > v.maxTotal {
		return obj, fmt.Errorf("%w: more than %d decoded bytes", ErrLimit, v.maxTotal)
	}
	if err != nil {
		v.add("%s: object %s cannot be decoded", dayName, o.Key)
		return obj, nil
	}
	obj.EventCount = lines
	if lines != o.EventCount {
		v.add("%s: object %s holds %d events, the manifest says %d", dayName, o.Key, lines, o.EventCount)
	}
	return obj, nil
}

func (v *verifier) checkUnlisted(used map[string]bool) {
	for _, name := range v.order {
		if strings.HasPrefix(name, "objects/") && !used[name] {
			v.add("member %s is not listed in any manifest", name)
		}
	}
}

func (v *verifier) checkObjectsList(doc *auditevidence.Export, expected []auditevidence.Object) {
	got := map[string]auditevidence.Object{}
	for _, o := range doc.Objects {
		if _, dup := got[o.Key]; dup {
			v.add("objects[] of export.json lists %s twice", o.Key)
		}
		got[o.Key] = o
	}
	for _, want := range expected {
		o, ok := got[want.Key]
		delete(got, want.Key)
		if !ok {
			v.add("objects[] of export.json does not list %s", want.Key)
		} else if want.Path != "" && o != want {
			v.add("objects[] of export.json describes %s differently than the package (path, SHA-256 or event count)", want.Key)
		}
	}
	for key := range got {
		v.add("objects[] of export.json lists %s, which no manifest lists", key)
	}
}

const (
	rankReadme = iota
	rankManifest
	rankObject
	rankEvents
	rankExport
	rankSig
)

func rank(name string) int {
	switch {
	case name == "README.md":
		return rankReadme
	case name == "events.jsonl":
		return rankEvents
	case name == "export.json":
		return rankExport
	case name == "export.sig":
		return rankSig
	case strings.HasPrefix(name, "objects/"):
		return rankObject
	}
	return rankManifest
}

// checkOrder reports a package whose members are not in the documented order. The signature does not cover the tar,
// and the checks above do not depend on the order, so this only flags a package no builder would write.
func (v *verifier) checkOrder(objectSeq []string, used map[string]bool) {
	var actualObjects, manifests []string
	last, ordered := 0, true
	for _, name := range v.order {
		r := rank(name)
		if r < last {
			ordered = false
		}
		last = r
		switch r {
		case rankObject:
			if used[name] {
				actualObjects = append(actualObjects, name)
			}
		case rankManifest:
			manifests = append(manifests, name)
		}
	}
	if !ordered || !slices.IsSorted(manifests) || !slices.Equal(actualObjects, objectSeq) {
		v.add("members are not in the documented order")
	}
}

// checkEvents is group 4.
func (v *verifier) checkEvents(doc *auditevidence.Export, _ []auditevidence.Object) {
	if _, ok := v.members["events.jsonl"]; !ok {
		v.add("events.jsonl is missing")
		return
	}
	h := sha256.New()
	tee := io.TeeReader(v.section("events.jsonl"), h)
	sc := bufio.NewScanner(tee)
	sc.Buffer(make([]byte, 0, 64<<10), maxEventLine)
	lines, bad, other, schema, firstBad, firstOther, firstSchema := 0, 0, 0, 0, 0, 0, 0
	for sc.Scan() {
		lines++
		var ev struct {
			OrganizationID string `json:"organization_id"`
			Schema         string `json:"schema"`
		}
		switch err := json.Unmarshal(sc.Bytes(), &ev); {
		case err != nil:
			if bad++; bad == 1 {
				firstBad = lines
			}
		default:
			if ev.OrganizationID != doc.OrganizationID {
				if other++; other == 1 {
					firstOther = lines
				}
			}
			if ev.Schema != auditevidence.EventSchema {
				if schema++; schema == 1 {
					firstSchema = lines
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		v.add("events.jsonl line %d cannot be read: %v", lines+1, err)
	}
	// The hash must cover the whole member, also after a line that stopped the scanner.
	if _, err := io.Copy(io.Discard, tee); err != nil {
		v.add("events.jsonl cannot be read: %v", err)
	}
	sum := hex.EncodeToString(h.Sum(nil))
	v.res.Events = lines
	if sum != doc.EventsSHA256 {
		v.add("events.jsonl does not match events_sha256 of export.json")
	}
	if sum != v.expectedHash {
		v.add("events.jsonl differs from the decoded objects")
	}
	if lines != doc.EventCount {
		v.add("events.jsonl has %d lines, export.json says %d", lines, doc.EventCount)
	}
	if bad > 0 {
		v.add("events.jsonl: %d line(s) are not JSON (first at line %d)", bad, firstBad)
	}
	if other > 0 {
		v.add("events.jsonl: %d event(s) belong to another organization (first at line %d)", other, firstOther)
	}
	if schema > 0 {
		v.add("events.jsonl: %d event(s) have a schema other than %s (first at line %d)", schema, auditevidence.EventSchema, firstSchema)
	}
}

// checkReadme is part of group 4: the README an auditor reads first is covered by the signature through export.json.
func (v *verifier) checkReadme(doc *auditevidence.Export) {
	if _, ok := v.members["README.md"]; !ok {
		v.add("README.md is missing")
		return
	}
	if doc.ReadmeSHA256 == "" {
		v.add("export.json has no readme_sha256")
		return
	}
	sum, err := v.hashMember("README.md")
	if err != nil {
		v.add("README.md cannot be read: %v", err)
		return
	}
	if sum != doc.ReadmeSHA256 {
		v.add("README.md does not match readme_sha256 of export.json")
	}
}

// checkServer is group 5: reported, never a problem of the verifier.
func (v *verifier) checkServer(doc *auditevidence.Export) {
	s := &v.res.Server
	s.OK = doc.Verification.OK
	for _, p := range doc.Verification.Problems {
		s.Problems = append(s.Problems, clean(p))
	}
	s.Runs = len(doc.Verification.Runs)
	for _, r := range doc.Verification.Runs {
		if !r.OK || len(r.Problems) > 0 {
			s.RunsWithProblems++
		}
	}
}
