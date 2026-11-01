package outbound_test

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/domain/outbound"
)

// TestSignature: a fixed vector computed independently (openssl dgst -sha256 -hmac).
func TestSignature(t *testing.T) {
	got := outbound.Signature([]byte("whsec-test"), 1700000000, []byte(`{"kind":"test"}`))
	want := "v1=454143f1532cdf4875295398c04b1ff35f08766b374f6de114b2f6d26914931d"
	if got != want {
		t.Fatalf("Signature = %s, want %s", got, want)
	}
	if outbound.Signature([]byte("whsec-test"), 1700000001, []byte(`{"kind":"test"}`)) == want {
		t.Fatal("the timestamp is not signed")
	}
}

// TestNewSecret: 43 base64url characters of 32 random bytes, different each time.
func TestNewSecret(t *testing.T) {
	a, err := outbound.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := outbound.NewSecret()
	raw, err := base64.RawURLEncoding.DecodeString(a)
	if len(a) != 43 || err != nil || len(raw) != 32 {
		t.Fatalf("secret %q: length %d, decode %v", a, len(a), err)
	}
	if a == b {
		t.Fatal("two secrets are equal")
	}
}

// TestDocumentedSignatureVector: the test vector of docs/operations/notifications.md, which receivers check their
// verification code against, is what Signature produces.
func TestDocumentedSignatureVector(t *testing.T) {
	doc, err := os.ReadFile("../../../../docs/operations/notifications.md")
	if err != nil {
		t.Fatal(err)
	}
	want := outbound.Signature([]byte("whsec-test"), 1700000000, []byte(`{"kind":"test"}`))
	if !strings.Contains(string(doc), "X-Paddock-Signature: "+want+"\n") {
		t.Fatalf("docs/operations/notifications.md does not carry the test vector %s", want)
	}
	for _, s := range []string{"the secret `whsec-test`", "the timestamp `1700000000`", "the body `{\"kind\":\"test\"}`"} {
		if !strings.Contains(string(doc), s) {
			t.Errorf("the documented vector does not state %s", s)
		}
	}
}
