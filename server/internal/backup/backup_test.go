package backup_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/backup"
)

func key(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, backup.KeySize)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSealOpenRoundTrip(t *testing.T) {
	k := key(t)
	plain := []byte("raft snapshot bytes")
	sealed, err := backup.Seal(k, plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, plain) {
		t.Fatal("sealed file contains the plaintext")
	}
	got, err := backup.Open(k, sealed)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("open: %q, %v", got, err)
	}
	again, _ := backup.Seal(k, plain)
	if bytes.Equal(again, sealed) {
		t.Fatal("two seals must use different nonces")
	}
}

func TestOpenRejects(t *testing.T) {
	k := key(t)
	sealed, err := backup.Seal(k, []byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backup.Open(key(t), sealed); err == nil {
		t.Fatal("wrong key must fail")
	}
	tampered := bytes.Clone(sealed)
	tampered[len(tampered)-1] ^= 1
	if _, err := backup.Open(k, tampered); err == nil {
		t.Fatal("tampered file must fail")
	}
	if _, err := backup.Open(k, []byte("plain text, not sealed at all......")); !errors.Is(err, backup.ErrNotSealed) {
		t.Fatalf("plain file: %v", err)
	}
	if _, err := backup.Seal(k[:16], []byte("x")); err == nil {
		t.Fatal("short key must fail")
	}
}

func TestParseKey(t *testing.T) {
	k := key(t)
	got, err := backup.ParseKey(base64.StdEncoding.EncodeToString(k) + "\n")
	if err != nil || !bytes.Equal(got, k) {
		t.Fatalf("parse: %v", err)
	}
	for _, bad := range []string{"", "not base64!", base64.StdEncoding.EncodeToString(k[:31])} {
		if _, err := backup.ParseKey(bad); err == nil {
			t.Fatalf("%q must fail", bad)
		}
	}
}

func TestOpenBaoKey(t *testing.T) {
	at := time.Date(2026, 10, 8, 14, 5, 9, 0, time.FixedZone("CEST", 2*3600))
	if got := backup.OpenBaoKey(at); got != "openbao/20261008T120509Z.snap.enc" {
		t.Fatal(got)
	}
}
