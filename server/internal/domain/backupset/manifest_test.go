package backupset_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
)

const testKeyID = "bk-20261104-7f3a9c1e"

const testFingerprint = "0123456789abcdef"

var testSHA = strings.Repeat("ab", 32)

func validManifest() backupset.Manifest {
	at := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	return backupset.Manifest{
		Schema: backupset.ManifestSchema, InstallationID: "0193f1a2-7b4c-7d5e-8f60-123456789abc",
		ServerVersion: "0.1.0-alpha.9", GeneratedAt: at, KeyID: testKeyID, KeyFingerprint: testFingerprint,
		SchemaVersions: map[string]int{"paddock": 100, "audit": 10},
		Contents: backupset.Contents{
			PgBackRest: backupset.PgBackRest{Path: backupset.RepoPath(testKeyID), Stanzas: []backupset.Stanza{
				{Name: "paddock", LastFull: "20261104-020000F", LastFullAt: at, WALMax: "000000010000000000000042"},
				{Name: "authentik"},
			}},
			OpenBao: []backupset.File{{Path: backupset.OpenBaoKey(at), Bytes: 1234, SHA256: testSHA, At: at}},
			Fleet:   []backupset.File{{Path: backupset.FleetKey(at), Bytes: 99, SHA256: testSHA, At: at}},
			Escrow:  []backupset.File{{Path: backupset.EscrowKey("org/a/devices/b/luks-header/1"), Bytes: 4096}},
		},
	}
}

func TestManifestRoundTrip(t *testing.T) {
	m := validManifest()
	b, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := backupset.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, m) {
		t.Fatalf("round trip changed the manifest:\n got %+v\nwant %+v", got, m)
	}
	for _, want := range []string{`"schema": "paddock.backup-set.v1"`, `"key_id": "` + testKeyID + `"`,
		`"path": "pgbackrest/` + testKeyID + `"`, `"last_full_at": "2026-11-04T10:00:00Z"`,
		`"path": "openbao/20261104T100000Z.snap.enc"`, `"path": "fleet/20261104T100000Z.sql.gz.enc"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("manifest.json lacks %s:\n%s", want, b)
		}
	}
	if strings.Contains(string(b), `"name": "authentik",`) {
		t.Errorf("an unknown last full was written:\n%s", b)
	}
}

func TestManifestEmptyListsAreArrays(t *testing.T) {
	m := validManifest()
	m.Contents = backupset.Contents{PgBackRest: backupset.PgBackRest{Path: backupset.RepoPath(testKeyID)}}
	m.SchemaVersions = nil
	b, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "null") {
		t.Fatalf("manifest.json holds null:\n%s", b)
	}
}

func TestManifestValidate(t *testing.T) {
	for name, mut := range map[string]func(*backupset.Manifest){
		"schema":            func(m *backupset.Manifest) { m.Schema = "paddock.backup-set.v2" },
		"installation":      func(m *backupset.Manifest) { m.InstallationID = "lab" },
		"server version":    func(m *backupset.Manifest) { m.ServerVersion = " " },
		"generated at":      func(m *backupset.Manifest) { m.GeneratedAt = time.Time{} },
		"key id":            func(m *backupset.Manifest) { m.KeyID = "bk-1" },
		"fingerprint":       func(m *backupset.Manifest) { m.KeyFingerprint = strings.ToUpper(testFingerprint) },
		"schema versions":   func(m *backupset.Manifest) { m.SchemaVersions["../x"] = 1 },
		"repo of other key": func(m *backupset.Manifest) { m.Contents.PgBackRest.Path = "pgbackrest/legacy" },
		"stanza name":       func(m *backupset.Manifest) { m.Contents.PgBackRest.Stanzas[0].Name = "../x" },
		"stanza repeated":   func(m *backupset.Manifest) { m.Contents.PgBackRest.Stanzas[1].Name = "paddock" },
		"openbao traversal": func(m *backupset.Manifest) { m.Contents.OpenBao[0].Path = "openbao/../../etc/passwd" },
		"openbao other dir": func(m *backupset.Manifest) { m.Contents.OpenBao[0].Path = "fleet/x.snap.enc" },
		"openbao dir only":  func(m *backupset.Manifest) { m.Contents.OpenBao[0].Path = "openbao/" },
		"openbao no sha":    func(m *backupset.Manifest) { m.Contents.OpenBao[0].SHA256 = "" },
		"fleet absolute":    func(m *backupset.Manifest) { m.Contents.Fleet[0].Path = "/fleet/x" },
		"fleet bytes":       func(m *backupset.Manifest) { m.Contents.Fleet[0].Bytes = -1 },
		"escrow traversal":  func(m *backupset.Manifest) { m.Contents.Escrow[0].Path = "escrow/org/../../x" },
		"escrow empty elem": func(m *backupset.Manifest) { m.Contents.Escrow[0].Path = "escrow//x" },
		"escrow backslash":  func(m *backupset.Manifest) { m.Contents.Escrow[0].Path = `escrow/a\..\x` },
		"escrow bad sha":    func(m *backupset.Manifest) { m.Contents.Escrow[0].SHA256 = "xyz" },
	} {
		t.Run(name, func(t *testing.T) {
			m := validManifest()
			mut(&m)
			if err := m.Validate(); !errors.Is(err, backupset.ErrInvalidManifest) {
				t.Fatalf("Validate = %v, want ErrInvalidManifest", err)
			}
			if _, err := m.Marshal(); !errors.Is(err, backupset.ErrInvalidManifest) {
				t.Fatalf("Marshal = %v, want ErrInvalidManifest", err)
			}
		})
	}
	if err := validManifest().Validate(); err != nil {
		t.Fatalf("valid manifest refused: %v", err)
	}
	m := validManifest()
	m.KeyID, m.Contents.PgBackRest.Path = backupset.LegacyKeyID, "pgbackrest/legacy"
	if err := m.Validate(); err != nil {
		t.Fatalf("legacy key manifest refused: %v", err)
	}
}

func TestParseRefusesInvalidJSON(t *testing.T) {
	for _, b := range []string{"", "{", `{"schema":"paddock.backup-set.v1"}`, `[]`} {
		if _, err := backupset.Parse([]byte(b)); !errors.Is(err, backupset.ErrInvalidManifest) {
			t.Errorf("Parse(%q) = %v, want ErrInvalidManifest", b, err)
		}
	}
}

func TestLayout(t *testing.T) {
	at := time.Date(2026, 11, 4, 11, 2, 3, 0, time.FixedZone("CET", 3600))
	for got, want := range map[string]string{
		backupset.RepoPath(testKeyID):          "pgbackrest/" + testKeyID,
		backupset.OpenBaoKey(at):               "openbao/20261104T100203Z.snap.enc",
		backupset.FleetKey(at):                 "fleet/20261104T100203Z.sql.gz.enc",
		backupset.EscrowKey("org/a/devices/b"): "escrow/org/a/devices/b",
	} {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}
