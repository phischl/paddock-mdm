package backupset

import (
	"strings"
	"time"
)

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

// EscrowHeader reports whether objectKey of the escrow bucket is an escrowed LUKS header
// (org/<org>/devices/<device>/luks-header/<name>): the only objects of the bucket a backup set holds. Diagnostics
// bundles share the bucket but are short-lived personal data, and the backup role's credential cannot read them.
func EscrowHeader(objectKey string) bool {
	el := strings.Split(objectKey, "/")
	if len(el) < 6 || el[0] != "org" || el[2] != "devices" || el[4] != "luks-header" {
		return false
	}
	for _, e := range el {
		if e == "" || e == "." || e == ".." {
			return false
		}
	}
	return true
}
