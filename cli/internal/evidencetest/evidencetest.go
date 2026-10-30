// Package evidencetest builds evidence packages the way the audit writer's exporter does, for the verifier's tests.
package evidencetest

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/phischl/paddock-mdm/pkg/auditevidence"
	"github.com/phischl/paddock-mdm/pkg/canonicaljson"
)

const Org = "11111111-2222-4333-8444-555555555555"

// ObjSpec is one audit object of a fixture day. Raw replaces the packed bytes (the manifest hash is then taken over
// Raw, like a stored object the builder cannot decode); Tamper packs other bytes than the manifest lists.
type ObjSpec struct {
	Lines  []string
	Raw    []byte
	Tamper bool
}

type TarMember struct {
	Name string
	Body []byte
	Typ  byte
}

type Pkg struct {
	t       *testing.T
	Priv    ed25519.PrivateKey
	Pub     ed25519.PublicKey
	Members []TarMember
	Export  auditevidence.Export
}

func EventLine(org, schema string, n int) string {
	return fmt.Sprintf(`{"organization_id":%q,"schema":%q,"n":%d}`, org, schema, n)
}

func GoodLines(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = EventLine(Org, auditevidence.EventSchema, i)
	}
	return out
}

func sign(priv ed25519.PrivateKey, version int, msg []byte) string {
	return fmt.Sprintf("vault:v%d:%s", version, base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg)))
}

// Assemble builds a package like the audit writer's exporter does (plan M10 §6.5 and amendment 2026-10-30): objects
// the builder cannot decode are packed, contribute no events and set verify_ok to false. breakLink makes the manifest
// of that day link to a wrong predecessor.
func Assemble(t *testing.T, days [][]ObjSpec, breakLink int) *Pkg {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	p := &Pkg{t: t, Priv: priv, Pub: pub}
	p.Members = append(p.Members, TarMember{Name: "README.md", Body: []byte("informational\n")})
	start := time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)
	anchor := hex.EncodeToString(bytes.Repeat([]byte{0xaa}, 32))
	prev := &anchor
	var manifests, objects []TarMember
	var events bytes.Buffer
	doc := auditevidence.Export{
		Schema: auditevidence.ExportSchema, ExportID: "e1", OrganizationID: Org,
		FromDay: start.Format(time.DateOnly), ToDay: start.AddDate(0, 0, len(days)-1).Format(time.DateOnly),
		RequestedBy: auditevidence.Actor{Type: "admin"}, RequestedAt: start, CreatedAt: start, Purpose: "test", Generator: "test",
		Days: []auditevidence.Day{}, Objects: []auditevidence.Object{}, ChainAnchor: &anchor,
		Verification: auditevidence.Verification{OK: true, Problems: []string{}, VerifiedAt: start, Verifier: "test", Runs: []auditevidence.Run{}},
		Keys:         []auditevidence.Key{{KeyVersion: 2, PublicKey: pub, Fingerprint: auditevidence.Fingerprint(pub)}},
	}
	for i, specs := range days {
		name := start.AddDate(0, 0, i).Format(time.DateOnly)
		var listed []auditevidence.ManifestObject
		var packed []auditevidence.Object
		dayEvents := 0
		for j, s := range specs {
			plain := []byte{}
			for _, l := range s.Lines {
				plain = append(plain, l+"\n"...)
			}
			Body := enc.EncodeAll(plain, nil)
			if s.Raw != nil {
				Body = s.Raw
			}
			sum := sha256.Sum256(Body)
			key := fmt.Sprintf("org/%s/%s/%02d-ev%d.jsonl.zst", Org, start.AddDate(0, 0, i).Format("2006/01/02"), j, j)
			path, err := auditevidence.ObjectPath(Org, key)
			if err != nil {
				t.Fatal(err)
			}
			listed = append(listed, auditevidence.ManifestObject{Key: key, SHA256: hex.EncodeToString(sum[:]), EventCount: len(s.Lines)})
			count := len(s.Lines)
			if s.Raw != nil {
				count = 0
				doc.Verification.OK = false
				doc.Verification.Problems = append(doc.Verification.Problems, fmt.Sprintf("%s: object %s cannot be decoded", name, key))
			} else {
				events.Write(plain)
			}
			if s.Tamper {
				Body = append(append([]byte{}, Body...), 0)
				Body[len(Body)-1] ^= 1
				sum = sha256.Sum256(Body)
				count = 0
				doc.Verification.OK = false
				doc.Verification.Problems = append(doc.Verification.Problems,
					fmt.Sprintf("%s: object %s was modified (SHA-256 mismatch)", name, key))
				events.Truncate(events.Len() - len(plain))
			}
			packed = append(packed, auditevidence.Object{Key: key, Path: path, SHA256: hex.EncodeToString(sum[:]), EventCount: count})
			objects = append(objects, TarMember{Name: path, Body: Body})
			dayEvents += count
		}
		wantPrev := prev
		if i == breakLink {
			bad := hex.EncodeToString(bytes.Repeat([]byte{0xbb}, 32))
			wantPrev = &bad
		}
		Raw, err := json.Marshal(auditevidence.Manifest{Schema: auditevidence.ManifestSchema, OrganizationID: Org, Day: name,
			Objects: append([]auditevidence.ManifestObject{}, listed...), PrevManifestSHA256: wantPrev})
		if err != nil {
			t.Fatal(err)
		}
		canonical, err := canonicaljson.Transform(Raw)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(canonical)
		file, err := json.Marshal(auditevidence.ManifestFile{Manifest: canonical, Signature: sign(priv, 2, sum[:]), KeyVersion: 2})
		if err != nil {
			t.Fatal(err)
		}
		manifests = append(manifests, TarMember{Name: "manifests/" + name + ".json", Body: file})
		next := hex.EncodeToString(sum[:])
		prev = &next
		doc.Days = append(doc.Days, auditevidence.Day{Day: name, ManifestKey: "org/" + Org + "/manifests/" + name + ".json",
			ManifestSHA256: next, ObjectCount: len(specs), EventCount: dayEvents})
		doc.Objects = append(doc.Objects, packed...)
		doc.EventCount += dayEvents
	}
	esum := sha256.Sum256(events.Bytes())
	doc.EventsSHA256 = hex.EncodeToString(esum[:])
	p.Export = doc
	p.Members = append(p.Members, manifests...)
	p.Members = append(p.Members, objects...)
	p.Members = append(p.Members, TarMember{Name: "events.jsonl", Body: events.Bytes()}, TarMember{Name: "export.json"}, TarMember{Name: "export.sig"})
	p.Resign()
	return p
}

// Resign rewrites Export.json and Export.sig from p.Export.
func (p *Pkg) Resign() {
	p.t.Helper()
	canonical, err := canonicaljson.Marshal(p.Export)
	if err != nil {
		p.t.Fatal(err)
	}
	digest := auditevidence.ExportDigest(canonical)
	sig, err := json.Marshal(auditevidence.Signature{Signature: sign(p.Priv, 2, digest[:]), KeyVersion: 2})
	if err != nil {
		p.t.Fatal(err)
	}
	p.Set("export.json", canonical)
	p.Set("export.sig", sig)
}

func (p *Pkg) Idx(name string) int {
	for i, m := range p.Members {
		if m.Name == name {
			return i
		}
	}
	p.t.Fatalf("no member %s", name)
	return -1
}

func (p *Pkg) Set(name string, body []byte) { p.Members[p.Idx(name)].Body = body }

func (p *Pkg) Remove(name string) {
	i := p.Idx(name)
	p.Members = append(p.Members[:i], p.Members[i+1:]...)
}

func (p *Pkg) Fingerprint() string { return auditevidence.Fingerprint(p.Pub) }

// file writes the tar to a temp file and returns its path.
func (p *Pkg) File() string {
	p.t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, m := range p.Members {
		Typ := m.Typ
		if Typ == 0 {
			Typ = tar.TypeReg
		}
		h := &tar.Header{Name: m.Name, Typeflag: Typ, Mode: 0o644, Size: int64(len(m.Body))}
		if Typ != tar.TypeReg {
			h.Size, h.Linkname = 0, "/etc/passwd"
		}
		if err := tw.WriteHeader(h); err != nil {
			p.t.Fatal(err)
		}
		if _, err := tw.Write(m.Body); err != nil && Typ == tar.TypeReg {
			p.t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		p.t.Fatal(err)
	}
	path := filepath.Join(p.t.TempDir(), "package.tar")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		p.t.Fatal(err)
	}
	return path
}
