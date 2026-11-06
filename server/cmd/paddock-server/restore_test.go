package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
)

// TestPrintSchemaVersions: migrate --version names both databases with the newest embedded migration.
func TestPrintSchemaVersions(t *testing.T) {
	var out bytes.Buffer
	if err := printSchemaVersions(&out); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^paddock [1-9][0-9]*\naudit [1-9][0-9]*\n$`).MatchString(out.String()) {
		t.Errorf("output %q", out.String())
	}
	if code := run([]string{"migrate", "--version", "x"}); code != 2 {
		t.Errorf("migrate --version x: exit %d, want 2", code)
	}
}

// TestBackupManifestLines: backup manifest prints the key, the schema versions, the stanzas and the chosen files as
// name=value lines.
func TestBackupManifestLines(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	m := backupset.Manifest{Schema: backupset.ManifestSchema, InstallationID: "6f1c2b0a-4d1e-5a7b-9c3d-2e4f6a8b0c1d",
		ServerVersion: "0.1.0-test", GeneratedAt: time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC),
		KeyID: "bk-20261104-7f3a9c1e", KeyFingerprint: backupset.Fingerprint(key),
		SchemaVersions: map[string]int{"paddock": 100, "audit": 10}}
	m.Contents.PgBackRest.Path = backupset.RepoPath(m.KeyID)
	raw, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for p, c := range map[string][]byte{"manifest.json": raw, m.Contents.PgBackRest.Path + "/backup/paddock/backup.info": nil,
		m.Contents.PgBackRest.Path + "/backup/paddock/20261103-020000F/backup.manifest": nil,
		m.Contents.PgBackRest.Path + "/backup/authentik/backup.info":                    nil,
		"openbao/20261104T090000Z.snap.enc":                                             nil, "openbao/20261104T110000Z.snap.enc": nil} {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, c, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	if err := backupManifest([]string{"--at", "2026-11-04T10:00:00Z", dir}, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"key_id=bk-20261104-7f3a9c1e", "key_fingerprint=" + backupset.Fingerprint(key),
		"repo_path=pgbackrest/bk-20261104-7f3a9c1e", "stanzas=paddock", "oldest.paddock=2026-11-03T02:00:00Z", "openbao=openbao/20261104T090000Z.snap.enc",
		"fleet=", "escrow=0", "schema.audit=10", "schema.paddock=100"} {
		if !strings.Contains("\n"+out.String(), "\n"+want+"\n") {
			t.Errorf("missing line %q in\n%s", want, out.String())
		}
	}
	if err := backupManifest([]string{"--at", "yesterday", dir}, &out); err == nil {
		t.Error("an --at that is not RFC 3339 was accepted")
	}
	if err := backupManifest(nil, &out); !errors.Is(err, errUsage) {
		t.Errorf("no directory: %v", err)
	}
}

// TestSetSourceNeedsExactlyOne: a restore reads from exactly one source, and a target file only from stdin.
func TestSetSourceNeedsExactlyOne(t *testing.T) {
	for _, c := range []struct {
		src  setSource
		want bool
	}{
		{setSource{dir: "/d"}, true},
		{setSource{target: "offsite"}, true},
		{setSource{targetFile: "-"}, true},
		{setSource{targetFile: "/etc/target.json"}, false},
		{setSource{}, false},
		{setSource{dir: "/d", target: "offsite"}, false},
	} {
		if got := c.src.valid(); got != c.want {
			t.Errorf("%+v: valid %v, want %v", c.src, got, c.want)
		}
	}
}

// TestRestoreRepoArguments: restore-repo takes one source or --check alone; both are refused before the database is
// opened.
func TestRestoreRepoArguments(t *testing.T) {
	for _, args := range [][]string{nil, {"--check", "extra"}, {"--dir", "/d", "--target", "offsite"}} {
		if err := backupRestoreRepo(context.Background(), nil, args, nil, &bytes.Buffer{}); !errors.Is(err, errUsage) {
			t.Errorf("%q: %v, want the usage error", args, err)
		}
	}
}
