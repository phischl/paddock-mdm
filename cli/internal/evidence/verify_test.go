package evidence_test

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/phischl/paddock-mdm/cli/internal/evidence"
	"github.com/phischl/paddock-mdm/cli/internal/evidencetest"
	"github.com/phischl/paddock-mdm/pkg/auditevidence"
)

func twoDays() [][]evidencetest.ObjSpec {
	return [][]evidencetest.ObjSpec{{{Lines: evidencetest.GoodLines(3)}, {Lines: evidencetest.GoodLines(2)}}, {}, {{Lines: evidencetest.GoodLines(4)}}}
}

func verify(t *testing.T, path, fingerprint string) *evidence.Result {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, _ := f.Stat()
	res, err := evidence.Verify(f, info.Size(), evidence.Options{Fingerprint: fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func hasProblem(res *evidence.Result, sub string) bool {
	return slices.ContainsFunc(res.Problems, func(p string) bool { return strings.Contains(p, sub) })
}

func TestVerifyValidPackage(t *testing.T) {
	p := evidencetest.Assemble(t, twoDays(), -1)
	res := verify(t, p.File(), p.Fingerprint())
	if !res.OK || len(res.Problems) != 0 {
		t.Fatalf("problems: %v", res.Problems)
	}
	if res.Days != 3 || res.Objects != 3 || res.Events != 9 || res.KeyVersion != 2 || !res.FingerprintChecked ||
		res.Fingerprint != p.Fingerprint() || res.ChainAnchor == nil || res.OrganizationID != evidencetest.Org {
		t.Fatalf("result: %+v", res)
	}
	var out strings.Builder
	res.WriteText(&out)
	if !strings.HasPrefix(out.String(), "OK "+evidencetest.Org+" 2026-03-30..2026-04-01: 3 days, 3 objects, 9 events; signed with audit-chain v2 (fingerprint "+
		p.Fingerprint()+"); chain anchor aaaa") || strings.Contains(out.String(), "NOTE") {
		t.Fatalf("text:\n%s", out.String())
	}
	// Without --fingerprint the result is still OK but says the key is not authenticated.
	res = verify(t, p.File(), "")
	var out2 strings.Builder
	res.WriteText(&out2)
	if !res.OK || res.FingerprintChecked || !strings.Contains(out2.String(), "NOTE no --fingerprint given") {
		t.Fatalf("no fingerprint: %v\n%s", res.Problems, out2.String())
	}
}

func TestVerifyTamperedPackages(t *testing.T) {
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	cases := []struct {
		name        string
		build       func() *evidencetest.Pkg
		fingerprint string
		want        []string
	}{
		{"modified object", func() *evidencetest.Pkg {
			p := evidencetest.Assemble(t, twoDays(), -1)
			name := p.Export.Objects[0].Path
			b := append([]byte{}, p.Members[p.Idx(name)].Body...)
			b[len(b)-1] ^= 1
			p.Set(name, b)
			return p
		}, "", []string{"was modified (SHA-256 mismatch)", "differs from the decoded objects", "objects[] of export.json describes"}},
		{"wrong package signature", func() *evidencetest.Pkg {
			p := evidencetest.Assemble(t, twoDays(), -1)
			p.Priv = otherPriv
			p.Resign()
			return p
		}, "", []string{"package signature does not verify with audit-chain v2"}},
		{"wrong fingerprint", func() *evidencetest.Pkg { return evidencetest.Assemble(t, twoDays(), -1) },
			strings.Repeat("0", 64), []string{"signing key fingerprint differs from --fingerprint"}},
		{"missing manifest", func() *evidencetest.Pkg {
			p := evidencetest.Assemble(t, twoDays(), -1)
			p.Remove("manifests/2026-03-31.json")
			return p
		}, "", []string{"2026-03-31: no manifest (chain broken)", "2026-04-01: prev_manifest_sha256 does not link"}},
		{"broken link", func() *evidencetest.Pkg { return evidencetest.Assemble(t, twoDays(), 2) }, "", []string{"2026-04-01: prev_manifest_sha256 does not link"}},
		{"missing object", func() *evidencetest.Pkg {
			p := evidencetest.Assemble(t, twoDays(), -1)
			p.Remove(p.Export.Objects[0].Path)
			return p
		}, "", []string{"is missing from the package"}},
		{"extra object", func() *evidencetest.Pkg {
			p := evidencetest.Assemble(t, twoDays(), -1)
			p.Members = slices.Insert(p.Members, p.Idx("events.jsonl"), evidencetest.TarMember{Name: "objects/2026/03/30/99-extra.jsonl.zst", Body: []byte("x")})
			return p
		}, "", []string{"is not listed in any manifest"}},
		{"extra member", func() *evidencetest.Pkg {
			p := evidencetest.Assemble(t, twoDays(), -1)
			p.Members = append(p.Members, evidencetest.TarMember{Name: "notes.txt", Body: []byte("x")})
			return p
		}, "", []string{"is not part of an evidence package"}},
		{"reordered members", func() *evidencetest.Pkg {
			p := evidencetest.Assemble(t, twoDays(), -1)
			i, j := p.Idx("manifests/2026-03-30.json"), p.Idx("events.jsonl")
			p.Members[i], p.Members[j] = p.Members[j], p.Members[i]
			return p
		}, "", []string{"members are not in the documented order"}},
		{"events.jsonl mismatch", func() *evidencetest.Pkg {
			p := evidencetest.Assemble(t, twoDays(), -1)
			p.Set("events.jsonl", append(p.Members[p.Idx("events.jsonl")].Body, []byte(evidencetest.EventLine(evidencetest.Org, auditevidence.EventSchema, 99)+"\n")...))
			return p
		}, "", []string{"does not match events_sha256", "differs from the decoded objects", "events.jsonl has 10 lines"}},
		{"event of another organization", func() *evidencetest.Pkg {
			return evidencetest.Assemble(t, [][]evidencetest.ObjSpec{{{Lines: []string{evidencetest.EventLine("99999999-2222-4333-8444-555555555555", auditevidence.EventSchema, 0)}}}}, -1)
		}, "", []string{"belong to another organization (first at line 1)"}},
		{"wrong event schema", func() *evidencetest.Pkg {
			return evidencetest.Assemble(t, [][]evidencetest.ObjSpec{{{Lines: []string{evidencetest.EventLine(evidencetest.Org, "paddock.audit.v0", 0)}}}}, -1)
		}, "", []string{"have a schema other than paddock.audit.v1"}},
		{"wrong export schema", func() *evidencetest.Pkg {
			p := evidencetest.Assemble(t, twoDays(), -1)
			p.Export.Schema = "paddock.audit-export.v2"
			p.Resign()
			return p
		}, "", []string{`has schema "paddock.audit-export.v2"`}},
		{"missing events.jsonl", func() *evidencetest.Pkg {
			p := evidencetest.Assemble(t, twoDays(), -1)
			p.Remove("events.jsonl")
			return p
		}, "", []string{"events.jsonl is missing"}},
		{"missing export.sig", func() *evidencetest.Pkg {
			p := evidencetest.Assemble(t, twoDays(), -1)
			p.Remove("export.sig")
			return p
		}, "", []string{"export.sig is missing"}},
		{"export.json changed after signing", func() *evidencetest.Pkg {
			p := evidencetest.Assemble(t, twoDays(), -1)
			p.Set("export.json", []byte(strings.Replace(string(p.Members[p.Idx("export.json")].Body), `"test"`, `"other"`, 1)))
			return p
		}, "", []string{"package signature does not verify"}},
		{"manifest signed with another key", func() *evidencetest.Pkg {
			p := evidencetest.Assemble(t, twoDays(), -1)
			p.ResignManifest("2026-03-30", otherPriv, nil)
			return p
		}, "", []string{"2026-03-30: signature does not verify with audit-chain v2"}},
		{"manifest differs from manifest_sha256", func() *evidencetest.Pkg {
			p := evidencetest.Assemble(t, twoDays(), -1)
			p.ResignManifest("2026-03-30", p.Priv, func(m *auditevidence.Manifest) { slices.Reverse(m.Objects) })
			return p
		}, "", []string{"2026-03-30: manifest does not match manifest_sha256 of export.json"}},
		{"manifest of another organization", func() *evidencetest.Pkg {
			p := evidencetest.Assemble(t, twoDays(), -1)
			p.ResignManifest("2026-04-01", p.Priv, func(m *auditevidence.Manifest) { m.OrganizationID = "99999999-2222-4333-8444-555555555555" })
			return p
		}, "", []string{"2026-04-01: manifest belongs to 99999999-2222-4333-8444-555555555555/2026-04-01"}},
		{"manifest of another day", func() *evidencetest.Pkg {
			p := evidencetest.Assemble(t, twoDays(), -1)
			p.ResignManifest("2026-04-01", p.Priv, func(m *auditevidence.Manifest) { m.Day = "2026-03-30" })
			return p
		}, "", []string{"2026-04-01: manifest belongs to " + evidencetest.Org + "/2026-03-30"}},
		{"manifest of another schema", func() *evidencetest.Pkg {
			p := evidencetest.Assemble(t, twoDays(), -1)
			p.ResignManifest("2026-04-01", p.Priv, func(m *auditevidence.Manifest) { m.Schema = "paddock.audit-manifest.v0" })
			return p
		}, "", []string{"2026-04-01: manifest belongs to " + evidencetest.Org + "/2026-04-01 with schema paddock.audit-manifest.v0"}},
		{"day dropped from days[]", func() *evidencetest.Pkg {
			p := evidencetest.Assemble(t, twoDays(), -1)
			p.Export.Days = slices.Delete(p.Export.Days, 1, 2)
			p.Resign()
			return p
		}, "", []string{"2026-03-31: day is missing from days[] of export.json"}},
		{"wrong object_count in days[]", func() *evidencetest.Pkg {
			p := evidencetest.Assemble(t, twoDays(), -1)
			p.Export.Days[0].ObjectCount = 5
			p.Resign()
			return p
		}, "", []string{"2026-03-30: days[] of export.json counts 5 objects, the manifest lists 2"}},
		{"wrong chain_anchor", func() *evidencetest.Pkg {
			p := evidencetest.Assemble(t, twoDays(), -1)
			other := strings.Repeat("cc", 32)
			p.Export.ChainAnchor = &other
			p.Resign()
			return p
		}, "", []string{"chain_anchor of export.json differs from the first manifest"}},
		{"key does not match its fingerprint", func() *evidencetest.Pkg {
			p := evidencetest.Assemble(t, twoDays(), -1)
			p.Export.Keys[0].Fingerprint = strings.Repeat("0", 64)
			p.Resign()
			return p
		}, "", []string{"embedded key v2 does not match its fingerprint"}},
		{"object event_count differs from the manifest", func() *evidencetest.Pkg {
			p := evidencetest.Assemble(t, twoDays(), -1)
			p.ResignManifest("2026-04-01", p.Priv, func(m *auditevidence.Manifest) { m.Objects[0].EventCount = 7 })
			return p
		}, "", []string{"holds 4 events, the manifest says 7"}},
		{"export.json event_count", func() *evidencetest.Pkg {
			p := evidencetest.Assemble(t, twoDays(), -1)
			p.Export.EventCount++
			p.Resign()
			return p
		}, "", []string{"event_count of export.json (10) differs from the 9 events of the objects"}},
		{"organization_id is not a UUID", func() *evidencetest.Pkg {
			p := evidencetest.Assemble(t, twoDays(), -1)
			p.Export.OrganizationID = "not-a-uuid"
			p.Resign()
			return p
		}, "", []string{`organization_id "not-a-uuid" is not a UUID`}},
		{"object listed twice", func() *evidencetest.Pkg {
			p := evidencetest.Assemble(t, twoDays(), -1)
			p.ResignManifest("2026-03-30", p.Priv, func(m *auditevidence.Manifest) { m.Objects = append(m.Objects, m.Objects[0]) })
			return p
		}, "", []string{"is listed more than once"}},
		{"README changed with the signature intact", func() *evidencetest.Pkg {
			p := evidencetest.Assemble(t, twoDays(), -1)
			p.Set("README.md", []byte("verification: no problems; fingerprint 00\n"))
			return p
		}, "", []string{"README.md does not match readme_sha256"}},
		{"README removed", func() *evidencetest.Pkg {
			p := evidencetest.Assemble(t, twoDays(), -1)
			p.Remove("README.md")
			return p
		}, "", []string{"README.md is missing"}},
		{"export.json without readme_sha256", func() *evidencetest.Pkg {
			p := evidencetest.Assemble(t, twoDays(), -1)
			p.OmitReadmeHash = true
			p.Export.ReadmeSHA256 = ""
			p.Resign()
			return p
		}, "", []string{"export.json has no readme_sha256"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := verify(t, c.build().File(), c.fingerprint)
			if res.OK != (len(c.want) == 0) {
				t.Fatalf("ok=%v problems=%v", res.OK, res.Problems)
			}
			for _, w := range c.want {
				if !hasProblem(res, w) {
					t.Errorf("no problem %q in %v", w, res.Problems)
				}
			}
		})
	}
}

func TestVerifyObjectsTheBuilderDoesNotDecode(t *testing.T) {
	// Amendment 2026-10-30 item 5: the package is internally consistent; the verifier reports the object, expects no
	// events from it and finds nothing else wrong.
	t.Run("undecodable", func(t *testing.T) {
		p := evidencetest.Assemble(t, [][]evidencetest.ObjSpec{{{Lines: evidencetest.GoodLines(2)}, {Raw: []byte("not zstd")}, {Lines: evidencetest.GoodLines(1)}}}, -1)
		res := verify(t, p.File(), "")
		if len(res.Problems) != 1 || !hasProblem(res, "cannot be decoded") || res.Events != 3 || res.Server.OK {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("modified before packing", func(t *testing.T) {
		p := evidencetest.Assemble(t, [][]evidencetest.ObjSpec{{{Lines: evidencetest.GoodLines(2)}, {Lines: evidencetest.GoodLines(2), Tamper: true}}}, -1)
		res := verify(t, p.File(), "")
		if len(res.Problems) != 1 || !hasProblem(res, "was modified (SHA-256 mismatch)") || res.Events != 2 {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("total decoding bound counts failed objects", func(t *testing.T) {
		enc, _ := zstd.NewWriter(nil)
		big := enc.EncodeAll(make([]byte, 256<<20+1), nil)
		p := evidencetest.Assemble(t, [][]evidencetest.ObjSpec{{{Raw: big}, {Raw: big}, {Raw: big}}}, -1)
		f, err := os.Open(p.File())
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		info, _ := f.Stat()
		if _, err := evidence.VerifyWithTotalLimit(f, info.Size(), evidence.Options{}, 300<<20); !errors.Is(err, evidence.ErrLimit) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("decoded size over the limit", func(t *testing.T) {
		enc, _ := zstd.NewWriter(nil)
		big := enc.EncodeAll(make([]byte, 256<<20+1), nil)
		p := evidencetest.Assemble(t, [][]evidencetest.ObjSpec{{{Raw: big}, {Lines: evidencetest.GoodLines(1)}}}, -1)
		res := verify(t, p.File(), "")
		if len(res.Problems) != 1 || !hasProblem(res, "cannot be decoded") || res.Events != 1 {
			t.Fatalf("%+v", res)
		}
	})
}

func TestVerifyRejectsUnsafeMemberNames(t *testing.T) {
	for _, name := range []string{"../evil", "objects/../../evil", "/etc/passwd", `objects\evil`, "objects//x", "objects/./x", "a\nb"} {
		p := evidencetest.Assemble(t, twoDays(), -1)
		p.Members = slices.Insert(p.Members, p.Idx("events.jsonl"), evidencetest.TarMember{Name: name, Body: []byte("x")})
		res := verify(t, p.File(), "")
		if res.OK || !hasProblem(res, "member") {
			t.Errorf("%q accepted: %v", name, res.Problems)
		}
		for _, line := range res.Problems {
			if strings.ContainsAny(line, "\n\r") {
				t.Errorf("%q: unclean problem %q", name, line)
			}
		}
	}
	p := evidencetest.Assemble(t, twoDays(), -1)
	p.Members = append(p.Members, evidencetest.TarMember{Name: "export.json", Body: []byte("{}")})
	if res := verify(t, p.File(), ""); res.OK || !hasProblem(res, `"export.json" appears more than once`) {
		t.Errorf("duplicate: %v", res.Problems)
	}
	p = evidencetest.Assemble(t, twoDays(), -1)
	p.Members = append(p.Members, evidencetest.TarMember{Name: "objects/link", Typ: 2})
	if res := verify(t, p.File(), ""); res.OK || !hasProblem(res, "is not a regular file") {
		t.Errorf("symlink: %v", res.Problems)
	}
}

func TestVerifyNotATar(t *testing.T) {
	path := t.TempDir() + "/x"
	if err := os.WriteFile(path, []byte(strings.Repeat("hello", 500)), 0o600); err != nil {
		t.Fatal(err)
	}
	f, _ := os.Open(path)
	defer f.Close()
	if _, err := evidence.Verify(f, 2500, evidence.Options{}); err == nil || !strings.Contains(err.Error(), "not a tar") {
		t.Fatalf("err = %v", err)
	}
}

func TestResultJSONShape(t *testing.T) {
	p := evidencetest.Assemble(t, twoDays(), -1)
	b, err := json.Marshal(verify(t, p.File(), ""))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"ok", "organization_id", "from_day", "to_day", "days", "objects", "events", "key_version", "fingerprint",
		"chain_anchor", "server_verification", "problems"} {
		if _, ok := m[k]; !ok {
			t.Errorf("no key %s", k)
		}
	}
}
