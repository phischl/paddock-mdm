package auditevidence_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/pkg/auditevidence"
)

func TestVerifySignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("digest")
	sig := "vault:v2:" + base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
	keys := map[int][]byte{2: pub}
	if !auditevidence.VerifySignature(keys, 2, sig, msg) {
		t.Fatal("valid signature refused")
	}
	other, _, _ := ed25519.GenerateKey(nil)
	cases := map[string]struct {
		keys    map[int][]byte
		version int
		sig     string
		msg     []byte
	}{
		"other message":       {keys, 2, sig, []byte("other")},
		"wrong version":       {map[int][]byte{1: pub, 2: pub}, 1, sig, msg},
		"unknown version":     {map[int][]byte{1: pub}, 2, sig, msg},
		"other key":           {map[int][]byte{2: other}, 2, sig, msg},
		"not vault":           {keys, 2, strings.Replace(sig, "vault:", "bao:", 1), msg},
		"bad base64":          {keys, 2, "vault:v2:%%%", msg},
		"missing parts":       {keys, 2, "vault:v2", msg},
		"short public key":    {map[int][]byte{2: pub[:16]}, 2, sig, msg},
		"empty signature":     {keys, 2, "", msg},
		"version mismatch v3": {keys, 3, sig, msg},
	}
	for name, c := range cases {
		if auditevidence.VerifySignature(c.keys, c.version, c.sig, c.msg) {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestFingerprintAndExportDigest(t *testing.T) {
	pub := []byte(strings.Repeat("k", 32))
	sum := sha256.Sum256(pub)
	if got := auditevidence.Fingerprint(pub); got != hex.EncodeToString(sum[:]) {
		t.Fatalf("Fingerprint = %s", got)
	}
	if auditevidence.ExportDigest([]byte("{}")) != sha256.Sum256([]byte("{}")) {
		t.Fatal("ExportDigest is not the SHA-256 of the canonical bytes")
	}
}

func TestManifestDigestCanonicalizes(t *testing.T) {
	file := auditevidence.ManifestFile{Manifest: json.RawMessage(`{ "objects": [], "day": "2026-01-01" }`)}
	canonical, sum, err := auditevidence.ManifestDigest(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(canonical) != `{"day":"2026-01-01","objects":[]}` {
		t.Fatalf("canonical = %s", canonical)
	}
	if sum != sha256.Sum256(canonical) {
		t.Fatal("digest is not the SHA-256 of the canonical bytes")
	}
	if _, _, err := auditevidence.ManifestDigest(auditevidence.ManifestFile{Manifest: json.RawMessage(`{`)}); err == nil {
		t.Fatal("invalid manifest accepted")
	}
}

func TestObjectPath(t *testing.T) {
	const org = "0190a0a0-0000-7000-8000-000000000001"
	got, err := auditevidence.ObjectPath(org, "org/"+org+"/2026/01/01/08-x.jsonl.zst")
	if err != nil || got != "objects/2026/01/01/08-x.jsonl.zst" {
		t.Fatalf("ObjectPath = %q, %v", got, err)
	}
	for _, key := range []string{
		"org/0190a0a0-0000-7000-8000-000000000002/2026/01/01/08-x.jsonl.zst",
		"2026/01/01/08-x.jsonl.zst",
		"org/" + org + "/",
		"org/" + org,
		"org/" + org + "/../" + "0190a0a0-0000-7000-8000-000000000002/x.jsonl.zst",
		"org/" + org + "/2026/../../x.jsonl.zst",
		"org/" + org + "/2026/01/..",
		"org/" + org + "//etc/x.jsonl.zst",
		"org/" + org + "/2026\\01\\x.jsonl.zst",
		"org/" + org + "/2026/./01/x.jsonl.zst",
		"org/" + org + "/./x.jsonl.zst",
		"org/" + org + "/2026//01/x.jsonl.zst",
		"org/" + org + "/2026/01/",
		"org/" + org + "/.",
	} {
		if _, err := auditevidence.ObjectPath(org, key); err == nil {
			t.Errorf("foreign key %q accepted", key)
		}
	}
	if _, err := auditevidence.ObjectPath("", "org//x"); err == nil {
		t.Error("empty organization accepted")
	}
}
