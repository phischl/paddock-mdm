package backupset

import "time"

// Layout of a backup set (plan M15 §6.5): every path is relative to the set's root directory paddock-backup/.
const (
	// SetRoot is the directory name of a backup set and the root of its tarball form.
	SetRoot = "paddock-backup"
	// ManifestPath is the manifest's path in the set; a mirror writes it last.
	ManifestPath = "manifest.json"
	// ManifestSchema is the schema of the manifest this package reads and writes.
	ManifestSchema = "paddock.backup-set.v1"

	dirPgBackRest = "pgbackrest/"
	dirOpenBao    = "openbao/"
	dirFleet      = "fleet/"
	dirEscrow     = "escrow/"

	fileTime = "20060102T150405Z"
)

// RepoPath is the pgBackRest repository (repo1-path) of the key keyID: a new key starts a new repository.
func RepoPath(keyID string) string { return dirPgBackRest + keyID }

// OpenBaoKey is the path of the sealed OpenBao snapshot taken at t.
func OpenBaoKey(t time.Time) string { return dirOpenBao + t.UTC().Format(fileTime) + ".snap.enc" }

// FleetKey is the path of the sealed Fleet database dump taken at t.
func FleetKey(t time.Time) string { return dirFleet + t.UTC().Format(fileTime) + ".sql.gz.enc" }

// EscrowKey is the path of the escrow bucket's object objectKey in the set; the object is copied unchanged.
func EscrowKey(objectKey string) string { return dirEscrow + objectKey }
