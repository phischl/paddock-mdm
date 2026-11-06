package authflow

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

// verifyAssertion checks an assertion the way a relying party does (WebAuthn §7.2 steps 11–21 that concern the
// authenticator's output): client data, RP ID hash, flags and the ES256 signature with the COSE public key.
func verifyAssertion(t *testing.T, w *WebAuthn, cred map[string]any, challenge, origin, rpID string) {
	t.Helper()
	resp := cred["response"].(map[string]any)
	dec := func(k string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(resp[k].(string))
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		return b
	}
	clientData, authData, sig := dec("clientDataJSON"), dec("authenticatorData"), dec("signature")
	var cd struct{ Type, Challenge, Origin string }
	if err := json.Unmarshal(clientData, &cd); err != nil || cd.Type != "webauthn.get" || cd.Challenge != challenge || cd.Origin != origin {
		t.Fatalf("client data %s (%v)", clientData, err)
	}
	rpHash := sha256.Sum256([]byte(rpID))
	if len(authData) != 37 || !bytes.Equal(authData[:32], rpHash[:]) || authData[32] != 0x05 {
		t.Fatalf("authenticator data %x", authData)
	}
	cose := w.COSEPublicKey()
	if len(cose) != 77 || !bytes.Equal(cose[:10], []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20}) ||
		!bytes.Equal(cose[42:45], []byte{0x22, 0x58, 0x20}) {
		t.Fatalf("COSE key %x", cose)
	}
	point := append(append([]byte{0x04}, cose[10:42]...), cose[45:77]...)
	pub, err := ecdh.P256().NewPublicKey(point)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(pub)
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	clientHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, authData...), clientHash[:]...))
	if !ecdsa.VerifyASN1(parsed.(*ecdsa.PublicKey), digest[:], sig) {
		t.Fatal("the signature does not verify with the COSE public key")
	}
	if cred["id"] != w.CredentialIDBase64URL() || cred["rawId"] != w.CredentialIDBase64URL() || cred["type"] != "public-key" {
		t.Fatalf("credential %v", cred)
	}
}

func TestWebAuthnAssert(t *testing.T) {
	w, err := NewWebAuthn()
	if err != nil {
		t.Fatal(err)
	}
	opts := `{"challenge":"c2VjcmV0LWNoYWxsZW5nZQ","rpId":"auth.paddock.localhost","allowCredentials":[{"type":"public-key","id":"` +
		w.CredentialIDBase64URL() + `"}],"userVerification":"preferred"}`
	cred, err := w.Assert("https://auth.paddock.localhost", json.RawMessage(opts))
	if err != nil {
		t.Fatal(err)
	}
	verifyAssertion(t, w, cred, "c2VjcmV0LWNoYWxsZW5nZQ", "https://auth.paddock.localhost", "auth.paddock.localhost")

	// Without rpId the RP ID is the origin's host.
	cred, err = w.Assert("https://auth.example.test:8443", json.RawMessage(`{"challenge":"YWJj"}`))
	if err != nil {
		t.Fatal(err)
	}
	verifyAssertion(t, w, cred, "YWJj", "https://auth.example.test:8443", "auth.example.test")

	other, _ := NewWebAuthn()
	if _, err := other.Assert("https://a", json.RawMessage(opts)); err == nil || !strings.Contains(err.Error(), "does not allow") {
		t.Fatalf("another credential: %v", err)
	}
	if _, err := w.Assert("https://a", json.RawMessage(`{"rpId":"a"}`)); err == nil {
		t.Fatal("options without a challenge are accepted")
	}
}

func TestWebAuthnValidateStage(t *testing.T) {
	w, _ := NewWebAuthn()
	page, _ := url.Parse("https://auth.paddock.localhost/if/flow/paddock-stepup/?x=1")
	raw := json.RawMessage(`{"component":"ak-stage-authenticator-validate","device_challenges":[` +
		`{"device_class":"totp","device_uid":"1","challenge":{}},` +
		`{"device_class":"webauthn","device_uid":"2","challenge":{"challenge":"Zm9v","rpId":"auth.paddock.localhost"}}]}`)
	answer, err := w.validate(context.Background(), raw, page)
	if err != nil {
		t.Fatal(err)
	}
	verifyAssertion(t, w, answer["webauthn"].(map[string]any), "Zm9v", "https://auth.paddock.localhost", "auth.paddock.localhost")
	if _, err := w.validate(context.Background(), json.RawMessage(`{"device_challenges":[{"device_class":"totp"}]}`), page); err == nil {
		t.Fatal("a stage without a WebAuthn challenge is answered")
	}
}

func TestWebAuthnSaveLoad(t *testing.T) {
	w, _ := NewWebAuthn()
	path := filepath.Join(t.TempDir(), "passkey.pem")
	if err := w.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := LoadWebAuthn(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Key.Equal(w.Key) || !bytes.Equal(got.CredentialID, w.CredentialID) {
		t.Fatal("the loaded authenticator differs")
	}
	script := w.RegistrationScript("ci@paddock.test", "auth.paddock.localhost", "ci-passkey")
	for _, want := range []string{`User.objects.get(username="ci@paddock.test")`, w.CredentialIDBase64URL(), w.PublicKeyBase64URL(), "paddock-webauthn ok"} {
		if !strings.Contains(script, want) {
			t.Fatalf("registration script lacks %q:\n%s", want, script)
		}
	}
}
