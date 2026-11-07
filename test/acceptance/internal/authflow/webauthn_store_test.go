package authflow

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWebAuthnSaveLoad: an authenticator written by one process signs, after LoadWebAuthn in another, assertions that
// verify with the public key registered before (the upgrade job's sign-ins before and after the upgrade).
func TestWebAuthnSaveLoad(t *testing.T) {
	w, err := NewWebAuthn()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "passkey.pem")
	if err := w.Save(path); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("saved file: %v %v", fi, err)
	}
	got, err := LoadWebAuthn(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.CredentialID() != w.CredentialID() || got.PublicKey() != w.PublicKey() {
		t.Fatal("the loaded authenticator has another credential")
	}
	page, _ := url.Parse("https://auth.paddock.localhost/if/flow/paddock-admin-login/")
	ans, err := got.answer(context.Background(), page, webauthnChallenge(t, w.CredentialID()))
	if err != nil {
		t.Fatal(err)
	}
	resp := ans["webauthn"].(map[string]any)["response"].(map[string]any)
	decode := func(k string) []byte {
		b, err := b64url.DecodeString(resp[k].(string))
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		return b
	}
	clientHash := sha256.Sum256(decode("clientDataJSON"))
	digest := sha256.Sum256(append(decode("authenticatorData"), clientHash[:]...))
	if !ecdsa.VerifyASN1(decodeCOSE(t, w.PublicKey()), digest[:], decode("signature")) {
		t.Fatal("an assertion of the loaded authenticator does not verify with the key registered before saving")
	}

	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadWebAuthn(path); err == nil {
		t.Fatal("a file without a key loads")
	}
}

func TestWebAuthnRegistrationScript(t *testing.T) {
	w, _ := NewWebAuthn()
	script := w.RegistrationScript("ci@paddock.test", "auth.paddock.localhost", "ci-passkey")
	for _, want := range []string{`User.objects.get(username="ci@paddock.test")`, `"credential_id": "` + w.CredentialID() + `"`,
		`"public_key": "` + w.PublicKey() + `"`, `"rp_id": "auth.paddock.localhost"`, `filter(user=user, name="ci-passkey").delete()`,
		`print("paddock-webauthn ok")`} {
		if !strings.Contains(script, want) {
			t.Fatalf("registration script lacks %q:\n%s", want, script)
		}
	}
}
