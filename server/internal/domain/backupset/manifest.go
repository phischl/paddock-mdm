package backupset

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ErrInvalidManifest is the cause of every manifest Validate refuses.
var ErrInvalidManifest = errors.New("backupset: invalid manifest")

var (
	sha256Pattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	stanzaPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	schemaKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
)

// Manifest describes a backup set (plan M15 §6.5); manifest.json is its JSON form.
type Manifest struct {
	Schema         string         `json:"schema"`
	InstallationID string         `json:"installation_id"`
	ServerVersion  string         `json:"server_version"`
	GeneratedAt    time.Time      `json:"generated_at"`
	KeyID          string         `json:"key_id"`
	KeyFingerprint string         `json:"key_fingerprint"`
	SchemaVersions map[string]int `json:"schema_versions"`
	Contents       Contents       `json:"contents"`
}

// Contents lists what a set holds per kind.
type Contents struct {
	PgBackRest PgBackRest `json:"pgbackrest"`
	OpenBao    []File     `json:"openbao"`
	Fleet      []File     `json:"fleet"`
	Escrow     []File     `json:"escrow"`
}

// PgBackRest is the set's pgBackRest repository and the state of its stanzas.
type PgBackRest struct {
	Path    string   `json:"path"`
	Stanzas []Stanza `json:"stanzas"`
}

// Stanza is one pgBackRest stanza: its newest full backup and the newest archived WAL segment.
type Stanza struct {
	Name       string    `json:"name"`
	LastFull   string    `json:"last_full,omitempty"`
	LastFullAt time.Time `json:"last_full_at,omitzero"`
	WALMax     string    `json:"wal_max,omitempty"`
}

// File is one file of the set. Escrow objects carry no hash: they are copied unchanged. Their time is the escrow
// object's own time (LastModified at copy time), absent when unknown; the backup role's escrow rule needs it to tell
// whether a Destroy covers a copy (plan M15, A2 note 2026-11-05 c).
type File struct {
	Path   string    `json:"path"`
	Bytes  int64     `json:"bytes"`
	SHA256 string    `json:"sha256,omitempty"`
	At     time.Time `json:"at,omitzero"`
}

// Marshal validates m and returns manifest.json. Empty lists are written as [], never null.
func (m Manifest) Marshal() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	m.Contents.PgBackRest.Stanzas = nonNil(m.Contents.PgBackRest.Stanzas)
	m.Contents.OpenBao = nonNil(m.Contents.OpenBao)
	m.Contents.Fleet = nonNil(m.Contents.Fleet)
	m.Contents.Escrow = nonNil(m.Contents.Escrow)
	if m.SchemaVersions == nil {
		m.SchemaVersions = map[string]int{}
	}
	return json.MarshalIndent(m, "", "  ")
}

// Parse reads manifest.json and validates it.
func Parse(b []byte) (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return Manifest{}, fmt.Errorf("%w: %w", ErrInvalidManifest, err)
	}
	if err := m.Validate(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// Validate checks the schema, the identifiers and every path: a restore reads the paths of a set that may come from
// anywhere, so each must stay inside its kind's directory.
func (m Manifest) Validate() error {
	switch {
	case m.Schema != ManifestSchema:
		return invalidManifest("schema must be " + ManifestSchema)
	case uuid.Validate(m.InstallationID) != nil:
		return invalidManifest("installation_id must be a UUID")
	case strings.TrimSpace(m.ServerVersion) == "":
		return invalidManifest("server_version is missing")
	case m.GeneratedAt.IsZero():
		return invalidManifest("generated_at is missing")
	case !ValidKeyID(m.KeyID):
		return invalidManifest("key_id is not a backup key ID")
	case !fingerprintPattern.MatchString(m.KeyFingerprint):
		return invalidManifest("key_fingerprint must be 16 lowercase hex characters")
	}
	for name, v := range m.SchemaVersions {
		if !schemaKeyPattern.MatchString(name) || v < 0 {
			return invalidManifest("schema_versions holds an invalid entry")
		}
	}
	if m.Contents.PgBackRest.Path != RepoPath(m.KeyID) {
		return invalidManifest("contents.pgbackrest.path must be " + RepoPath(m.KeyID))
	}
	seen := map[string]bool{}
	for _, s := range m.Contents.PgBackRest.Stanzas {
		if !stanzaPattern.MatchString(s.Name) || seen[s.Name] {
			return invalidManifest("contents.pgbackrest.stanzas holds an invalid or repeated name")
		}
		seen[s.Name] = true
	}
	for _, g := range []struct {
		field, dir string
		files      []File
		hashed     bool
	}{
		{"contents.openbao", dirOpenBao, m.Contents.OpenBao, true},
		{"contents.fleet", dirFleet, m.Contents.Fleet, true},
		{"contents.escrow", dirEscrow, m.Contents.Escrow, false},
	} {
		for _, f := range g.files {
			if err := validateFile(g.field, g.dir, f, g.hashed); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateFile(field, dir string, f File, hashed bool) error {
	if !strings.HasPrefix(f.Path, dir) || len(f.Path) == len(dir) || !cleanRelative(f.Path) {
		return invalidManifest(field + ": a path is not a file under " + dir)
	}
	if f.Bytes < 0 {
		return invalidManifest(field + ": bytes must not be negative")
	}
	if (hashed || f.SHA256 != "") && !sha256Pattern.MatchString(f.SHA256) {
		return invalidManifest(field + ": sha256 must be 64 lowercase hex characters")
	}
	return nil
}

// cleanRelative reports whether p is a relative slash path without empty, "." or ".." elements.
func cleanRelative(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\\\x00") {
		return false
	}
	for el := range strings.SplitSeq(p, "/") {
		if el == "" || el == "." || el == ".." {
			return false
		}
	}
	return true
}

func invalidManifest(reason string) error { return fmt.Errorf("%w: %s", ErrInvalidManifest, reason) }

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
