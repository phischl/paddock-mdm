package authflow

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestWebAuthnRegistration: the passkey setup answer carries clientData of type webauthn.create for the challenge and
// the page's origin, and an attestation "none" whose authenticator data names the relying party, sets UP, UV and AT and
// holds this authenticator's credential ID and public key.
func TestWebAuthnRegistration(t *testing.T) {
	w, err := NewWebAuthn()
	if err != nil {
		t.Fatal(err)
	}
	page, _ := url.Parse("https://auth.paddock.localhost:8443/if/flow/paddock-recovery/?flow_token=x")
	raw := json.RawMessage(`{"component":"ak-stage-authenticator-webauthn","registration":{"challenge":"Y2hhbGxlbmdl",` +
		`"rp":{"id":"paddock.localhost","name":"Paddock"},"user":{"id":"dQ","name":"erin"}}}`)
	cred, err := w.registration(page, raw)
	if err != nil {
		t.Fatal(err)
	}
	if cred["id"] != w.CredentialID() || cred["rawId"] != w.CredentialID() || cred["type"] != "public-key" {
		t.Fatalf("credential %+v", cred)
	}
	resp := cred["response"].(map[string]any)
	cd, _ := b64url.DecodeString(resp["clientDataJSON"].(string))
	var clientData map[string]any
	if err := json.Unmarshal(cd, &clientData); err != nil || clientData["type"] != "webauthn.create" ||
		clientData["challenge"] != "Y2hhbGxlbmdl" || clientData["origin"] != "https://auth.paddock.localhost:8443" {
		t.Fatalf("clientData %s %v", cd, err)
	}
	att, _ := b64url.DecodeString(resp["attestationObject"].(string))
	head := []byte("\xa3\x63fmt\x64none\x67attStmt\xa0\x68authData\x58")
	if !bytes.HasPrefix(att, head) {
		t.Fatalf("attestation object % x", att[:min(len(att), 40)])
	}
	authData := att[len(head)+1:]
	if int(att[len(head)]) != len(authData) {
		t.Fatalf("authData length %d, have %d", att[len(head)], len(authData))
	}
	rp := sha256.Sum256([]byte("paddock.localhost"))
	cose, _ := b64url.DecodeString(w.PublicKey())
	idLen := int(authData[53])<<8 | int(authData[54])
	switch {
	case !bytes.Equal(authData[:32], rp[:]):
		t.Fatal("rpIdHash")
	case authData[32] != 0x45:
		t.Fatalf("flags %#x, want UP|UV|AT", authData[32])
	case !bytes.Equal(authData[37:53], make([]byte, 16)):
		t.Fatal("aaguid")
	case idLen != 32 || !bytes.Equal(authData[55:55+idLen], w.id):
		t.Fatal("credential ID")
	case !bytes.Equal(authData[55+idLen:], cose):
		t.Fatal("public key")
	}
	if _, err := w.registration(page, json.RawMessage(`{"registration":{}}`)); err == nil {
		t.Fatal("a challenge without relying party was answered")
	}
}

func TestFlowSlug(t *testing.T) {
	u, _ := url.Parse("https://auth.test/if/flow/paddock-recovery/?flow_token=x")
	if got := flowSlug(u); got != "paddock-recovery" {
		t.Fatalf("slug %q", got)
	}
}

// TestSetupLinkExecutorRefusal: a link the flow executor refuses with an HTTP status returns an ExecutorError with that
// status, so a caller can tell a refusal from a transport error.
func TestSetupLinkExecutorRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"detail":"flow not applicable"}`, http.StatusBadRequest)
	}))
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	seen, err := SetupLink(context.Background(), client, srv.URL+"/if/flow/paddock-recovery/?flow_token=x", "", nil)
	var refused *ExecutorError
	if !errors.As(err, &refused) || refused.Status != http.StatusBadRequest ||
		refused.Path != "/api/v3/flows/executor/paddock-recovery/" || len(seen) != 0 ||
		!strings.Contains(err.Error(), "HTTP 400") {
		t.Fatalf("refused link: %v, stages %v", err, seen)
	}

	srv.Close()
	if _, err := SetupLink(context.Background(), client, srv.URL+"/if/flow/paddock-recovery/?flow_token=x", "", nil); err == nil ||
		errors.As(err, &refused) {
		t.Fatalf("unreachable executor: %v, want a transport error that is no ExecutorError", err)
	}
}
