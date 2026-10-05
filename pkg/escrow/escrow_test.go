package escrow

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
)

func pemOf(t *testing.T, pub any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func TestEncryptRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(pemOf(t, &key.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	ct, err := Encrypt(pub, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(ct)
	if pt, err := rsa.DecryptOAEP(sha256.New(), nil, key, raw, nil); err != nil || string(pt) != "secret" {
		t.Fatalf("decrypt: %q %v", pt, err)
	}
	small, _ := rsa.GenerateKey(rand.Reader, 2048)
	for name, p := range map[string]string{"not pem": "x", "2048 bit": pemOf(t, &small.PublicKey)} {
		if _, err := ParsePublicKey(p); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestKeyVersion(t *testing.T) {
	if v, err := KeyVersion(KeyID(3)); err != nil || v != 3 {
		t.Fatalf("%d %v", v, err)
	}
	for _, id := range []string{"escrow-wrap:v0", "escrow-wrap:x", "bundle-signing:v1", ""} {
		if _, err := KeyVersion(id); err == nil {
			t.Fatalf("%q accepted", id)
		}
	}
}
