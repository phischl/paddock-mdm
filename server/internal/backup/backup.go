// Package backup encrypts the OpenBao snapshots of the control plane's backup (plan M6a decision 5) and names the
// objects of the backup bucket whose age the monitoring watches (decision 9).
package backup

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// magic starts every sealed file, so that a wrong file is recognized before decryption.
var magic = []byte("PADDOCK-BACKUP-1")

// KeySize is the size of the backup encryption key (AES-256).
const KeySize = 32

// ParseKey decodes the backup encryption key file: 32 random bytes in standard base64.
func ParseKey(s string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("backup key: not base64: %w", err)
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("backup key: %d bytes, want %d", len(key), KeySize)
	}
	return key, nil
}

// Seal encrypts plaintext with AES-256-GCM: magic, 12-byte random nonce, ciphertext with tag. The magic is the
// additional data, so it cannot be swapped.
func Seal(key, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append(append(bytes.Clone(magic), nonce...), gcm.Seal(nil, nonce, plaintext, magic)...)
	return out, nil
}

// ErrNotSealed means the input is not a sealed backup file.
var ErrNotSealed = errors.New("backup: not a Paddock backup file")

// Open decrypts a file written by Seal.
func Open(key, sealed []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < len(magic)+gcm.NonceSize()+gcm.Overhead() || !bytes.Equal(sealed[:len(magic)], magic) {
		return nil, ErrNotSealed
	}
	nonce := sealed[len(magic) : len(magic)+gcm.NonceSize()]
	plain, err := gcm.Open(nil, nonce, sealed[len(magic)+gcm.NonceSize():], magic)
	if err != nil {
		return nil, fmt.Errorf("backup: decrypt (wrong key or damaged file): %w", err)
	}
	return plain, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("backup key: %d bytes, want %d", len(key), KeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Kind is one kind of backup in the bucket.
type Kind struct {
	Name string
	// Prefix is the object key prefix whose newest object marks the last successful backup.
	Prefix string
}

// Kinds are the backups of the control plane (compose.backup.yaml). pgBackRest rewrites a stanza's backup.info at the
// end of every backup.
var Kinds = []Kind{
	{Name: "postgres", Prefix: "pgbackrest/backup/paddock/backup.info"},
	{Name: "authentik", Prefix: "pgbackrest/backup/authentik/backup.info"},
	{Name: "openbao", Prefix: OpenBaoPrefix},
	{Name: "fleet", Prefix: "fleet/"},
}

// WALStanzas are the pgBackRest stanzas whose WAL is archived continuously (compose.backup.yaml).
var WALStanzas = []string{"paddock", "authentik"}

// WALArchivePrefix is the key prefix of a stanza's WAL archive: below it pgBackRest keeps one directory per archive ID
// (<PostgreSQL version>-<n>), in it one directory per timeline and log (16 hex digits) holding the segments.
func WALArchivePrefix(stanza string) string { return "pgbackrest/archive/" + stanza + "/" }

// OpenBaoPrefix is the key prefix of the OpenBao snapshots.
const OpenBaoPrefix = "openbao/"

// OpenBaoKey is the object key of a snapshot taken at t.
func OpenBaoKey(t time.Time) string {
	return OpenBaoPrefix + t.UTC().Format("20060102T150405Z") + ".snap.enc"
}
