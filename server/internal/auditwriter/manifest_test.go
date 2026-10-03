package auditwriter

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCanonicalManifestIsStableForPermutedObjects(t *testing.T) {
	org := uuid.MustParse("0192f0c4-0000-7000-8000-000000000001")
	day := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	objects := []ManifestObject{
		{Key: "org/x/2026/10/02/09-b.jsonl.zst", SHA256: "bb", EventCount: 2},
		{Key: "org/x/2026/10/02/08-a.jsonl.zst", SHA256: "aa", EventCount: 1},
		{Key: "org/x/2026/10/02/23-c.jsonl.zst", SHA256: "cc", EventCount: 3},
	}
	permuted := []ManifestObject{objects[2], objects[0], objects[1]}
	prev := bytes.Repeat([]byte{0xab}, 32)

	a, sumA, err := CanonicalManifest(org, day, objects, prev)
	if err != nil {
		t.Fatal(err)
	}
	b, sumB, err := CanonicalManifest(org, day, permuted, prev)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) || sumA != sumB {
		t.Fatalf("canonical bytes differ for permuted input:\n%s\n%s", a, b)
	}
	want := `{"day":"2026-10-02","objects":[{"event_count":1,"key":"org/x/2026/10/02/08-a.jsonl.zst","sha256":"aa"},` +
		`{"event_count":2,"key":"org/x/2026/10/02/09-b.jsonl.zst","sha256":"bb"},` +
		`{"event_count":3,"key":"org/x/2026/10/02/23-c.jsonl.zst","sha256":"cc"}],` +
		`"organization_id":"0192f0c4-0000-7000-8000-000000000001",` +
		`"prev_manifest_sha256":"abababababababababababababababababababababababababababababababab",` +
		`"schema":"paddock.audit-manifest.v1"}`
	if string(a) != want {
		t.Fatalf("canonical manifest\n got %s\nwant %s", a, want)
	}
}

func TestCanonicalManifestEmptyDayAndFirstManifest(t *testing.T) {
	c, _, err := CanonicalManifest(uuid.Nil, time.Date(2026, 1, 1, 13, 0, 0, 0, time.UTC), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"day":"2026-01-01","objects":[],"organization_id":"00000000-0000-0000-0000-000000000000","prev_manifest_sha256":null,"schema":"paddock.audit-manifest.v1"}`
	if string(c) != want {
		t.Fatalf("got %s", c)
	}
}

func TestObjectKey(t *testing.T) {
	org := uuid.MustParse("0192f0c4-0000-7000-8000-000000000001")
	ev := uuid.MustParse("0192f0c4-0000-7000-8000-0000000000ff")
	got := ObjectKey(org, time.Date(2026, 3, 4, 5, 0, 0, 0, time.UTC), ev)
	if got != "org/0192f0c4-0000-7000-8000-000000000001/2026/03/04/05-0192f0c4-0000-7000-8000-0000000000ff.jsonl.zst" {
		t.Fatal(got)
	}
}
