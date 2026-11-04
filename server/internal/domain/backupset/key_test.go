package backupset_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
)

func TestKeyID(t *testing.T) {
	now := time.Date(2026, 11, 4, 23, 30, 0, 0, time.FixedZone("CET", 3600))
	id := backupset.KeyID(now, []byte{0x7f, 0x3a, 0x9c, 0x1e, 0xff})
	if id != "bk-20261104-7f3a9c1e" {
		t.Fatalf("KeyID = %q", id)
	}
	if !backupset.ValidKeyID(id) || !backupset.ValidKeyID(backupset.LegacyKeyID) {
		t.Fatal("a generated or the legacy key ID is not valid")
	}
	for _, bad := range []string{"", "bk-2026110-7f3a9c1e", "bk-20261104-7F3A9C1E", "bk-20261104-7f3a9c1e0", "Legacy"} {
		if backupset.ValidKeyID(bad) {
			t.Errorf("ValidKeyID(%q) = true", bad)
		}
	}
}

func TestFingerprint(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	sum := sha256.Sum256(key)
	got := backupset.Fingerprint(key)
	if got != hex.EncodeToString(sum[:])[:16] {
		t.Fatalf("Fingerprint = %q", got)
	}
	if backupset.Fingerprint(bytes.Repeat([]byte{2}, 32)) == got {
		t.Fatal("two keys share a fingerprint")
	}
}

// TestChallenge: six distinct, sorted, 1-based positions inside the key text; the answer is the characters there.
func TestChallenge(t *testing.T) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	text := base64.StdEncoding.EncodeToString(raw)
	if len(text) != 44 {
		t.Fatalf("key text has %d characters", len(text))
	}
	hits := make([]int, len(text)+1)
	for range 2000 {
		pos, answer, err := backupset.Challenge(text, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if len(answer) != backupset.ChallengeLength {
			t.Fatalf("answer %q", answer)
		}
		for i, p := range pos {
			if p < 1 || p > len(text) {
				t.Fatalf("position %d outside [1, %d]", p, len(text))
			}
			if i > 0 && p <= pos[i-1] {
				t.Fatalf("positions %v not distinct and ascending", pos)
			}
			if answer[i] != text[p-1] {
				t.Fatalf("answer %q does not match positions %v", answer, pos)
			}
			hits[p]++
		}
	}
	for p := 1; p <= len(text); p++ {
		if hits[p] == 0 {
			t.Errorf("position %d never chosen in 2000 challenges", p)
		}
	}
}

func TestChallengeMinimalText(t *testing.T) {
	pos, answer, err := backupset.Challenge("abcdef", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if pos != [6]int{1, 2, 3, 4, 5, 6} || answer != "abcdef" {
		t.Fatalf("Challenge = %v %q", pos, answer)
	}
}

func TestChallengeRefuses(t *testing.T) {
	for _, text := range []string{"", "abcde", "abc def", "abcdef\n", "abcdéf"} {
		if _, _, err := backupset.Challenge(text, rand.Reader); !errors.Is(err, backupset.ErrInvalidKeyText) {
			t.Errorf("Challenge(%q) = %v, want ErrInvalidKeyText", text, err)
		}
	}
	if _, _, err := backupset.Challenge("abcdefghij", bytes.NewReader([]byte{1, 2})); err == nil {
		t.Error("Challenge with an exhausted random source succeeded")
	}
}

func TestChallengeHash(t *testing.T) {
	a := backupset.ChallengeHash("bk-20261104-7f3a9c1e", "Ab3+/Z")
	if a != backupset.ChallengeHash("bk-20261104-7f3a9c1e", "Ab3+/Z") {
		t.Fatal("ChallengeHash is not stable")
	}
	if a != sha256.Sum256([]byte("bk-20261104-7f3a9c1e:Ab3+/Z")) {
		t.Fatal("ChallengeHash is not sha256(keyID:answer)")
	}
	if a == backupset.ChallengeHash("bk-20261105-7f3a9c1e", "Ab3+/Z") ||
		a == backupset.ChallengeHash("bk-20261104-7f3a9c1e", "Ab3+/z") {
		t.Fatal("ChallengeHash ignores the key ID or the answer")
	}
}
