package escrow

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
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

func TestSealHeaderRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	// A LUKS2 header is mostly zeros with random keyslot areas.
	header := make([]byte, 16<<20)
	if _, err := rand.Read(header[32768 : 32768+258048]); err != nil {
		t.Fatal(err)
	}
	sealed, err := SealHeader(&key.PublicKey, header, "esc-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed.Object) >= len(header)/4 {
		t.Fatalf("sealed header has %d bytes, want it compressed", len(sealed.Object))
	}
	sum := sha256.Sum256(sealed.Object)
	if sealed.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("SHA256 does not match the object")
	}
	wrapped, _ := base64.StdEncoding.DecodeString(sealed.WrappedDEK)
	dek, err := rsa.DecryptOAEP(sha256.New(), nil, key, wrapped, nil)
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := base64.StdEncoding.DecodeString(sealed.Nonce)
	got, err := OpenHeader(dek, nonce, "esc-1", sealed.Object)
	if err != nil || !bytes.Equal(got, header) {
		t.Fatalf("open: %v", err)
	}
	// Another escrow ID, a changed object or a wrong key do not open.
	if _, err := OpenHeader(dek, nonce, "esc-2", sealed.Object); err == nil {
		t.Fatal("opened with another escrow ID")
	}
	tampered := bytes.Clone(sealed.Object)
	tampered[10] ^= 1
	if _, err := OpenHeader(dek, nonce, "esc-1", tampered); err == nil {
		t.Fatal("opened a changed object")
	}
	if _, err := OpenHeader(make([]byte, 32), nonce, "esc-1", sealed.Object); err == nil {
		t.Fatal("opened with a wrong key")
	}
	if _, err := OpenHeader(dek[:16], nonce, "esc-1", sealed.Object); err == nil {
		t.Fatal("opened with a short key")
	}
	other, err := SealHeader(&key.PublicKey, header, "esc-1")
	if err != nil || other.Nonce == sealed.Nonce || other.WrappedDEK == sealed.WrappedDEK {
		t.Fatal("two seals share nonce or key")
	}
}

func TestHeaderObjectKey(t *testing.T) {
	if k := HeaderObjectKey("o", "d", "v", 3); k != "org/o/devices/d/luks-header/v/3.bin" {
		t.Fatalf("key %q", k)
	}
	if k := HeaderObjectKey("o", "d", "", 3); k != "org/o/devices/d/luks-header/3.bin" {
		t.Fatal(k)
	}
}
