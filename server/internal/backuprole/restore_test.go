package backuprole

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
)

const restoreInstallation = "6f1c2b0a-4d1e-5a7b-9c3d-2e4f6a8b0c1d"

// writeSet writes files (path → content) into a fresh directory and returns it.
func writeSet(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for p, c := range files {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func openRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

// TestInspectSetPicksAtOrBefore: the newest snapshot and dump at or before the point are chosen; without a point the
// newest of all; files whose name is not exactly the role's format, and symlinks, never count. A stanza counts only
// with a backup label, and its oldest backup's start is reported.
func TestInspectSetPicksAtOrBefore(t *testing.T) {
	repo := backupset.RepoPath(testKeyID)
	dir := writeSet(t, map[string]string{
		"manifest.json":                                                              string(testManifest(t, restoreInstallation, nil)),
		repo + "/backup/paddock/backup.info":                                         "i",
		repo + "/backup/paddock/20261101-010000F/backup.manifest":                    "m",
		repo + "/backup/paddock/20261101-010000F_20261102-010000I/backup.manifest":   "m",
		repo + "/backup/paddock/20261031-010000F.partial/backup.manifest":            "m",
		repo + "/backup/authentik/backup.info":                                       "i",
		repo + "/backup/authentik/20261101-010000F_20261101-020000D/backup.manifest": "m",
		repo + "/backup/authentik/20261101-010000F/backup.manifest":                  "m",
		repo + "/backup/empty/backup.info":                                           "i",
		"openbao/20261101T000000Z.snap.enc":                                          "a",
		"openbao/20261102T120000Z.snap.enc":                                          "b",
		"openbao/20261103T000000Z.snap.enc":                                          "c",
		"openbao/20261102T130000Z.snap.enc.part":                                     "x",
		"openbao/20261102T130000Z.snap.encx":                                         "x",
		"fleet/20261101T060000Z.sql.gz.enc":                                          "d",
		"fleet/20261102T060000Z.sql.gz.enc":                                          "e",
	})
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "fleet", "20261102T070000Z.sql.gz.enc")); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 2, 12, 30, 0, 0, time.UTC)
	info, err := InspectSet(openRoot(t, dir), at)
	if err != nil {
		t.Fatal(err)
	}
	if info.OpenBao != "openbao/20261102T120000Z.snap.enc" || info.Fleet != "fleet/20261102T060000Z.sql.gz.enc" {
		t.Errorf("at %v: openbao %q fleet %q", at, info.OpenBao, info.Fleet)
	}
	if strings.Join(info.Stanzas, ",") != "authentik,paddock" || info.Manifest.KeyID != testKeyID {
		t.Errorf("stanzas %v, key %q", info.Stanzas, info.Manifest.KeyID)
	}
	if want := time.Date(2026, 11, 1, 1, 0, 0, 0, time.UTC); !info.Oldest["paddock"].Equal(want) ||
		!info.Oldest["authentik"].Equal(want) {
		t.Errorf("oldest backups %v, want %v for both", info.Oldest, want)
	}
	if info, _ := InspectSet(openRoot(t, dir), time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)); info.OpenBao !=
		"openbao/20261102T120000Z.snap.enc" {
		t.Errorf("a snapshot taken exactly at the point: %q", info.OpenBao)
	}
	if info, _ := InspectSet(openRoot(t, dir), time.Time{}); info.OpenBao != "openbao/20261103T000000Z.snap.enc" {
		t.Errorf("latest: %q", info.OpenBao)
	}
	if info, _ := InspectSet(openRoot(t, dir), time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)); info.OpenBao != "" ||
		info.Fleet != "" {
		t.Errorf("before every file: %q %q", info.OpenBao, info.Fleet)
	}
}

// TestInspectSetRefusesBadManifest: a missing or invalid manifest fails; a manifest planted as a symlink is not read.
func TestInspectSetRefusesBadManifest(t *testing.T) {
	if _, err := InspectSet(openRoot(t, writeSet(t, nil)), time.Time{}); err == nil {
		t.Error("a set without manifest.json was accepted")
	}
	if _, err := InspectSet(openRoot(t, writeSet(t, map[string]string{"manifest.json": `{"schema":"x"}`})),
		time.Time{}); err == nil {
		t.Error("an invalid manifest was accepted")
	}
	good := writeSet(t, map[string]string{"real.json": string(testManifest(t, restoreInstallation, nil))})
	link := writeSet(t, nil)
	if err := os.Symlink(filepath.Join(good, "real.json"), filepath.Join(link, "manifest.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectSet(openRoot(t, link), time.Time{}); err == nil {
		t.Error("a manifest.json symlink was followed")
	}
}

// TestCopySet: the prefix limits the copy, a file with another size is replaced, NoClobber keeps it, and every
// copied file arrives with its content.
func TestCopySet(t *testing.T) {
	repo := backupset.RepoPath(testKeyID)
	src := writeSet(t, map[string]string{
		"manifest.json":                      "m",
		repo + "/backup/paddock/backup.info": "new-info",
		repo + "/archive/paddock/seg":        "wal",
		"openbao/20261101T000000Z.snap.enc":  "s",
	})
	ctx := context.Background()
	dst := writeSet(t, map[string]string{repo + "/backup/paddock/backup.info": "old"})
	files, bytes, err := CopySet(ctx, NewSetDir(src), openRoot(t, dst), CopyOptions{Prefix: repo + "/", NoClobber: true})
	if err != nil || files != 1 || bytes != 3 {
		t.Fatalf("no-clobber copy: %d files %d bytes, %v", files, bytes, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, repo, "backup/paddock/backup.info")); string(b) != "old" {
		t.Errorf("no-clobber replaced backup.info: %q", b)
	}
	if _, err := os.Stat(filepath.Join(dst, "manifest.json")); err == nil {
		t.Error("a file outside the prefix was copied")
	}
	files, _, err = CopySet(ctx, NewSetDir(src), openRoot(t, dst), CopyOptions{})
	if err != nil || files != 3 {
		t.Fatalf("full copy: %d files, %v", files, err)
	}
	for p, want := range map[string]string{repo + "/backup/paddock/backup.info": "new-info", "manifest.json": "m",
		"openbao/20261101T000000Z.snap.enc": "s"} {
		if b, _ := os.ReadFile(filepath.Join(dst, p)); string(b) != want {
			t.Errorf("%s: %q, want %q", p, b, want)
		}
	}
	if files, _, _ := CopySet(ctx, NewSetDir(src), openRoot(t, dst), CopyOptions{}); files != 0 {
		t.Errorf("a second copy copied %d files", files)
	}
}

// TestCopySetFromS3Target: a target's copy is read through the target (the restore from a connected target).
func TestCopySetFromS3Target(t *testing.T) {
	s3 := &fakeS3{objects: map[string]string{"site/paddock-backup/manifest.json": "m",
		"site/paddock-backup/fleet/20261101T000000Z.sql.gz.enc": "dump"}}
	set, err := AsSetReader(NewS3Target(s3, "site"))
	if err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	if files, _, err := CopySet(context.Background(), set, openRoot(t, dst), CopyOptions{}); err != nil || files != 2 {
		t.Fatalf("%d files, %v", files, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "fleet/20261101T000000Z.sql.gz.enc")); string(b) != "dump" {
		t.Errorf("dump %q", b)
	}
}

// TestEmptyDir: everything below the root goes, the root stays.
func TestEmptyDir(t *testing.T) {
	dir := writeSet(t, map[string]string{"a/b/c": "x", "manifest.json": "m"})
	if err := EmptyDir(openRoot(t, dir)); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Errorf("left %v, %v", entries, err)
	}
}

// TestRestoreEscrow: missing headers are put, present ones skipped, and no copy that a Destroy covers (or that has no
// recorded time while its device was destroyed) goes back into the bucket; a copy newer than the Destroy does.
func TestRestoreEscrow(t *testing.T) {
	const org = "11111111-1111-1111-1111-111111111111"
	key := func(dev, name string) string { return "org/" + org + "/devices/" + dev + "/luks-header/" + name }
	destroyedAt := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	files := map[string]string{
		"escrow/" + key("d1", "h1"):                       "aaaa", // missing: put
		"escrow/" + key("d2", "h1"):                       "bbbb", // present with the same size: skipped
		"escrow/" + key("d3", "h1"):                       "cccc", // destroyed after the copy: skipped
		"escrow/" + key("d3", "h2"):                       "dddd", // escrowed after the Destroy: put
		"escrow/" + key("d4", "h1"):                       "eeee", // destroyed, no recorded time: skipped
		"escrow/org/" + org + "/devices/d1/diagnostics/x": "z",
	}
	m := backupset.Manifest{Schema: backupset.ManifestSchema, InstallationID: restoreInstallation, ServerVersion: "t",
		GeneratedAt: destroyedAt, KeyID: testKeyID, KeyFingerprint: backupset.Fingerprint(testKey)}
	m.Contents.PgBackRest.Path = backupset.RepoPath(testKeyID)
	m.Contents.Escrow = []backupset.File{
		{Path: "escrow/" + key("d3", "h1"), Bytes: 4, At: destroyedAt.Add(-time.Hour)},
		{Path: "escrow/" + key("d3", "h2"), Bytes: 4, At: destroyedAt.Add(time.Hour)},
	}
	dir := writeSet(t, files)
	bucket := &fakeS3{objects: map[string]string{key("d2", "h1"): "BBBB"}}
	destroyed := map[string]time.Time{org + "/d3": destroyedAt, org + "/d4": destroyedAt}
	res, err := RestoreEscrow(context.Background(), openRoot(t, dir), m, bucket, bucket, destroyed)
	if err != nil {
		t.Fatal(err)
	}
	if res.Put != 2 || res.Present != 1 || res.Destroyed != 2 {
		t.Errorf("result %+v", res)
	}
	wantSkipped := []EscrowSkip{{Key: key("d3", "h1"), Device: org + "/d3", DestroyedAt: destroyedAt},
		{Key: key("d4", "h1"), Device: org + "/d4", DestroyedAt: destroyedAt}}
	if !slices.Equal(res.Skipped, wantSkipped) {
		t.Errorf("skipped %+v, want %+v", res.Skipped, wantSkipped)
	}
	for k, want := range map[string]string{key("d1", "h1"): "aaaa", key("d3", "h2"): "dddd"} {
		if bucket.objects[k] != want {
			t.Errorf("%s: %q", k, bucket.objects[k])
		}
	}
	for _, k := range []string{key("d3", "h1"), key("d4", "h1"), "org/" + org + "/devices/d1/diagnostics/x"} {
		if _, ok := bucket.objects[k]; ok {
			t.Errorf("%s was put", k)
		}
	}
}

// TestParseTargetFile: only an S3 target with endpoint, bucket and both keys is accepted.
func TestParseTargetFile(t *testing.T) {
	good := `{"schema":"paddock.backup-target.v1","name":"offsite","type":"s3","settings":{"endpoint":"https://s3.example",` +
		`"bucket":"b"},"credentials":{"access_key":"a","secret_key":"s"}}`
	if f, err := ParseTargetFile([]byte(good)); err != nil || f.Name != "offsite" {
		t.Errorf("good file: %+v, %v", f.Name, err)
	}
	for name, raw := range map[string]string{
		"not json":    "{",
		"schema":      strings.Replace(good, "v1", "v2", 1),
		"smb":         strings.Replace(good, `"type":"s3"`, `"type":"smb"`, 1),
		"no bucket":   strings.Replace(good, `"bucket":"b"`, `"bucket":""`, 1),
		"no secret":   strings.Replace(good, `"secret_key":"s"`, `"secret_key":""`, 1),
		"no access":   strings.Replace(good, `"access_key":"a"`, `"access_key":""`, 1),
		"no endpoint": strings.Replace(good, `"endpoint":"https://s3.example",`, ``, 1),
	} {
		if _, err := ParseTargetFile([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestExportTargetRefusesMountedTypes: a share target cannot be exported (it is mounted on the new host instead).
func TestExportTargetRefusesMountedTypes(t *testing.T) {
	if _, err := ExportTarget(context.Background(), nil, TargetRecord{Name: "nas", Type: backupset.TypeSMB}); err == nil {
		t.Error("an SMB target was exported")
	}
}
