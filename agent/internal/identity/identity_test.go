package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity", "sign.key")
	k1, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v, %v; want 0600", fi.Mode().Perm(), err)
	}
	if di, _ := os.Stat(filepath.Dir(path)); di.Mode().Perm() != 0o700 {
		t.Fatalf("key directory mode %v; want 0700", di.Mode().Perm())
	}
	k2, err := LoadOrCreate(path)
	if err != nil || k2.KeyID != k1.KeyID || len(k1.KeyID) != 64 {
		t.Fatalf("reload: %v, key IDs %s / %s", err, k1.KeyID, k2.KeyID)
	}
}

func TestLoadRejects(t *testing.T) {
	dir := t.TempDir()
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(p384)
	for name, data := range map[string][]byte{
		"garbage":  []byte("not a key"),
		"p384":     pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		"bad type": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}),
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOrCreate(path); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
