// Package backupset holds the pure rules of platform backups (plan M15 decision 6, ADR 0046): the backup set's
// manifest and layout, the backup key's ID, fingerprint and confirmation challenge, and the validation of targets and
// the schedule. It performs no I/O.
package backupset

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"time"
)

// ChallengeLength is the number of key characters an administrator types back to confirm a key (plan M15 decision 5
// of 2026-11-04).
const ChallengeLength = 6

// LegacyKeyID is the ID of the key imported from the host file of an installation older than M15 (plan M15 decision 9).
const LegacyKeyID = "legacy"

var keyIDPattern = regexp.MustCompile(`^(bk-[0-9]{8}-[0-9a-f]{8}|legacy)$`)

var fingerprintPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)

// ErrInvalidKeyText is returned by Challenge for a key text that cannot carry a challenge.
var ErrInvalidKeyText = errors.New("backupset: key text must hold at least six printable ASCII characters")

// KeyID returns the ID of a key generated at now: bk-<YYYYMMDD of now in UTC>-<8 hex of the first four bytes of rnd>.
// Callers pass four random bytes; fewer are padded with zeros, which the primary key of backup_key would reveal as a
// collision rather than hide.
func KeyID(now time.Time, rnd []byte) string {
	var b [4]byte
	copy(b[:], rnd)
	return "bk-" + now.UTC().Format("20060102") + "-" + hex.EncodeToString(b[:])
}

// ValidKeyID reports whether id has the form of KeyID or is LegacyKeyID (the CHECK of backup_key.key_id).
func ValidKeyID(id string) bool { return keyIDPattern.MatchString(id) }

// Fingerprint returns the first 16 hex characters of the SHA-256 of the raw key bytes. It identifies a key in the
// portal, the manifest and audit params without revealing it.
func Fingerprint(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:8])
}

// Challenge picks ChallengeLength distinct positions of keyText, uniformly at random from rnd, and returns them
// 1-based in ascending order with the answer: the characters at those positions, in that order.
func Challenge(keyText string, rnd io.Reader) ([ChallengeLength]int, string, error) {
	var positions [ChallengeLength]int
	n := len(keyText)
	if n < ChallengeLength {
		return positions, "", ErrInvalidKeyText
	}
	for i := range n {
		if keyText[i] < '!' || keyText[i] > '~' {
			return positions, "", ErrInvalidKeyText
		}
	}
	idx := make([]int, n)
	for i := range idx {
		idx[i] = i
	}
	// A partial Fisher–Yates shuffle: the first ChallengeLength entries are a uniform sample without repetition.
	for i := range ChallengeLength {
		j, err := uniform(rnd, n-i)
		if err != nil {
			return positions, "", fmt.Errorf("backupset: challenge: %w", err)
		}
		idx[i], idx[i+j] = idx[i+j], idx[i]
	}
	chosen := slices.Clone(idx[:ChallengeLength])
	slices.Sort(chosen)
	answer := make([]byte, ChallengeLength)
	for k, p := range chosen {
		positions[k] = p + 1
		answer[k] = keyText[p]
	}
	return positions, string(answer), nil
}

// uniform returns a uniform integer in [0, n) from rnd.
func uniform(rnd io.Reader, n int) (int, error) {
	// Rejecting values at or above the largest multiple of n removes the modulo bias.
	const space = uint64(1) << 32
	limit := space - space%uint64(n) //nolint:gosec // n is in [1, len(keyText)], far below 2^32
	var b [4]byte
	for {
		if _, err := io.ReadFull(rnd, b[:]); err != nil {
			return 0, err
		}
		if v := uint64(binary.BigEndian.Uint32(b[:])); v < limit {
			return int(v % uint64(n)), nil //nolint:gosec // n is in [1, len(keyText)], far below 2^32
		}
	}
}

// ChallengeHash is the stored form of a challenge's answer: SHA-256 of keyID + ":" + answer. Binding the key ID keeps
// an answer of one key from confirming another.
func ChallengeHash(keyID, answer string) [32]byte {
	return sha256.Sum256([]byte(keyID + ":" + answer))
}
