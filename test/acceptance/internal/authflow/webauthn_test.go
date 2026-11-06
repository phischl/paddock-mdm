package authflow

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

// decodeCOSE reads the EC2 key that PublicKey encodes, as a relying party does.
func decodeCOSE(t *testing.T, s string) *ecdsa.PublicKey {
	t.Helper()
	b, err := b64url.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	head := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20}
	if len(b) != len(head)+32+3+32 || string(b[:len(head)]) != string(head) || string(b[42:45]) != "\x22\x58\x20" {
		t.Fatalf("COSE key %x is not EC2/ES256/P-256 with 32-byte coordinates", b)
	}
	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{0x04}, b[10:42]...), b[45:77]...))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func webauthnChallenge(t *testing.T, allow ...string) json.RawMessage {
	t.Helper()
	var creds []map[string]string
	for _, id := range allow {
		creds = append(creds, map[string]string{"id": id, "type": "public-key"})
	}
	raw, err := json.Marshal(map[string]any{
		"component": "ak-stage-authenticator-validate",
		"device_challenges": []map[string]any{
			{"device_class": "totp", "device_uid": "1", "challenge": map[string]any{}},
			{"device_class": "webauthn", "device_uid": "2", "challenge": map[string]any{
				"challenge": "c2VydmVyLWNoYWxsZW5nZQ", "rpId": "auth.paddock.localhost", "allowCredentials": creds,
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestWebAuthnAssertionVerifies checks the assertion the way a relying party (py_webauthn in Authentik) does: client
// data type, challenge and origin, the rpId hash, the UP and UV flags, and the signature with the registered key.
func TestWebAuthnAssertionVerifies(t *testing.T) {
	w, err := NewWebAuthn()
	if err != nil {
		t.Fatal(err)
	}
	page, _ := url.Parse("https://auth.paddock.localhost/if/flow/paddock-stepup/")
	ans, err := w.answer(context.Background(), page, webauthnChallenge(t, w.CredentialID()))
	if err != nil {
		t.Fatal(err)
	}
	cred := ans["webauthn"].(map[string]any)
	if cred["id"] != w.CredentialID() || cred["rawId"] != w.CredentialID() || cred["type"] != "public-key" {
		t.Fatalf("credential %v", cred)
	}
	resp := cred["response"].(map[string]any)
	decode := func(k string) []byte {
		b, err := b64url.DecodeString(resp[k].(string))
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		return b
	}
	clientData, authData, sig := decode("clientDataJSON"), decode("authenticatorData"), decode("signature")
	var cd struct{ Type, Challenge, Origin string }
	if err := json.Unmarshal(clientData, &cd); err != nil {
		t.Fatal(err)
	}
	if cd.Type != "webauthn.get" || cd.Challenge != "c2VydmVyLWNoYWxsZW5nZQ" || cd.Origin != "https://auth.paddock.localhost" {
		t.Fatalf("client data %+v", cd)
	}
	rpHash := sha256.Sum256([]byte("auth.paddock.localhost"))
	if len(authData) != 37 || string(authData[:32]) != string(rpHash[:]) || authData[32]&0x05 != 0x05 {
		t.Fatalf("authenticator data %x", authData)
	}
	clientHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, authData...), clientHash[:]...))
	if !ecdsa.VerifyASN1(decodeCOSE(t, w.PublicKey()), digest[:], sig) {
		t.Fatal("the signature does not verify with the registered public key")
	}
}

func TestWebAuthnRefusesForeignCredentialAndMissingChallenge(t *testing.T) {
	w, err := NewWebAuthn()
	if err != nil {
		t.Fatal(err)
	}
	page, _ := url.Parse("https://auth.paddock.localhost/")
	if _, err := w.answer(context.Background(), page, webauthnChallenge(t, "b3RoZXI")); err == nil ||
		!strings.Contains(err.Error(), "does not allow") {
		t.Fatalf("a challenge for another credential: %v", err)
	}
	totpOnly := json.RawMessage(`{"device_challenges":[{"device_class":"totp","challenge":{}}]}`)
	if _, err := w.answer(context.Background(), page, totpOnly); err == nil {
		t.Fatal("a stage without a WebAuthn challenge was answered")
	}
}
