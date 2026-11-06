package backuprole

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
)

// TestEscrowOrganizations: the organizations of the set's escrowed headers, once each and sorted; other objects of the
// escrow directory do not count.
func TestEscrowOrganizations(t *testing.T) {
	const a, b = "22222222-2222-2222-2222-222222222222", "11111111-1111-1111-1111-111111111111"
	const d1, d2, d3 = "33333333-3333-3333-3333-333333333331", "33333333-3333-3333-3333-333333333332",
		"33333333-3333-3333-3333-333333333333"
	dir := writeSet(t, map[string]string{
		"escrow/org/" + a + "/devices/" + d1 + "/luks-header/h1": "x",
		"escrow/org/" + a + "/devices/" + d2 + "/luks-header/h1": "x",
		"escrow/org/" + b + "/devices/" + d3 + "/luks-header/h1": "x",
		"escrow/org/not-a-uuid/devices/d4/diagnostics/x":         "x",
		"openbao/20261102T000000Z.snap.enc":                      "x",
	})
	got, err := EscrowOrganizations(openRoot(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	if want := []uuid.UUID{uuid.MustParse(b), uuid.MustParse(a)}; !slices.Equal(got, want) {
		t.Errorf("organizations %v, want %v", got, want)
	}
}

// TestEscrowOrganizationsRefusesNonUUID: a header whose organization the audit index cannot be asked about, or whose
// segments are not the canonical UUID strings the evidence is keyed by, fails the step instead of going back unchecked
// (fail closed).
func TestEscrowOrganizationsRefusesNonUUID(t *testing.T) {
	const org, dev = "11111111-1111-1111-1111-111111111111", "33333333-3333-3333-3333-33333333333a"
	for name, tc := range map[string]struct{ org, dev, want string }{
		"organization not a UUID": {"not-a-uuid", dev, "organization is not a UUID"},
		"organization upper case": {"AAAAAAAA-1111-1111-1111-111111111111", dev, "organization is not a UUID"},
		"organization braced":     {"{" + org + "}", dev, "organization is not a UUID"},
		"device not a UUID":       {org, "d1", "device is not a UUID"},
		"device upper case":       {org, strings.ToUpper(dev), "device is not a UUID"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeSet(t, map[string]string{"escrow/org/" + tc.org + "/devices/" + tc.dev + "/luks-header/h1": "x"})
			if _, err := EscrowOrganizations(openRoot(t, dir)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err %v, want %q", err, tc.want)
			}
		})
	}
}

// TestRestoreEscrowAuditEvidenceAfterPointInTime: the restored database (a point in time before the Destroy) holds no
// evidence, the audit index does; the audit evidence keeps the header out, and without it the header would go back
// (PDK-831).
func TestRestoreEscrowAuditEvidenceAfterPointInTime(t *testing.T) {
	const org = "11111111-1111-1111-1111-111111111111"
	k := "org/" + org + "/devices/d1/luks-header/h1"
	destroyedAt := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	m := backupset.Manifest{Schema: backupset.ManifestSchema, InstallationID: restoreInstallation, ServerVersion: "t",
		GeneratedAt: destroyedAt, KeyID: testKeyID, KeyFingerprint: backupset.Fingerprint(testKey)}
	m.Contents.PgBackRest.Path = backupset.RepoPath(testKeyID)
	m.Contents.Escrow = []backupset.File{{Path: "escrow/" + k, Bytes: 4, At: destroyedAt.Add(-time.Hour)}}
	dir := writeSet(t, map[string]string{"escrow/" + k: "aaaa"})
	audit := map[string]time.Time{org + "/d1": destroyedAt}

	bucket := &fakeS3{objects: map[string]string{}}
	res, err := RestoreEscrow(context.Background(), openRoot(t, dir), m, bucket, bucket, audit)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := bucket.objects[k]; ok || res.Destroyed != 1 || len(res.Skipped) != 1 || res.Skipped[0].Key != k {
		t.Errorf("audit evidence: result %+v, bucket %v", res, bucket.objects)
	}

	bucket = &fakeS3{objects: map[string]string{}}
	if res, err = RestoreEscrow(context.Background(), openRoot(t, dir), m, bucket, bucket, map[string]time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := bucket.objects[k]; !ok || res.Put != 1 {
		t.Errorf("no evidence: result %+v (the regression this guards against)", res)
	}
}
