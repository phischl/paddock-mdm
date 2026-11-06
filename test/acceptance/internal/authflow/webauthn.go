package authflow

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// WebAuthn is a software passkey (a virtual WebAuthn authenticator) that answers Authentik's authenticator validation
// stage through the flow executor, as a browser with a security key would (decisions-alpha9 item 53, PDK-567). A
// production stack validates WebAuthn at every portal sign-in and step-up; the acceptance gates' TOTP helpers only
// serve the development stack. It signs ES256 assertions with user presence and user verification and a signature
// counter of 0 (no counter, as many platform authenticators). Its credential is registered with Authentik out of band
// (RegistrationScript in an `ak shell`), never through the setup stage.
type WebAuthn struct {
	Key          *ecdsa.PrivateKey
	CredentialID []byte
}

// NewWebAuthn creates an authenticator with a fresh P-256 key and a random 32-byte credential ID.
func NewWebAuthn() (*WebAuthn, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	return &WebAuthn{Key: key, CredentialID: id}, nil
}

const webAuthnPEMType = "PADDOCK TEST WEBAUTHN KEY"

// Save writes the authenticator to path (0600): the PKCS#8 key as PEM with the credential ID as a header.
func (w *WebAuthn) Save(path string) error {
	der, err := x509.MarshalPKCS8PrivateKey(w.Key)
	if err != nil {
		return err
	}
	block := &pem.Block{Type: webAuthnPEMType, Headers: map[string]string{"Credential-Id": b64url(w.CredentialID)}, Bytes: der}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0o600)
}

// LoadWebAuthn reads an authenticator that Save wrote.
func LoadWebAuthn(path string) (*WebAuthn, error) {
	data, err := os.ReadFile(path) //nolint:gosec // test helper
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != webAuthnPEMType {
		return nil, fmt.Errorf("authflow: %s holds no WebAuthn key", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("authflow: %s: not a P-256 key", path)
	}
	id, err := base64.RawURLEncoding.DecodeString(block.Headers["Credential-Id"])
	if err != nil || len(id) == 0 {
		return nil, fmt.Errorf("authflow: %s: no credential ID", path)
	}
	return &WebAuthn{Key: key, CredentialID: id}, nil
}

// CredentialIDBase64URL is the credential ID as Authentik stores it (WebAuthnDevice.credential_id).
func (w *WebAuthn) CredentialIDBase64URL() string { return b64url(w.CredentialID) }

// PublicKeyBase64URL is the COSE public key as Authentik stores it (WebAuthnDevice.public_key).
func (w *WebAuthn) PublicKeyBase64URL() string { return b64url(w.COSEPublicKey()) }

// COSEPublicKey is the credential's public key as a COSE_Key (RFC 9053 EC2, alg ES256) in canonical CBOR:
// {1: 2, 3: -7, -1: 1, -2: x, -3: y}.
func (w *WebAuthn) COSEPublicKey() []byte {
	pub, err := w.Key.PublicKey.ECDH()
	if err != nil {
		panic(err) // a P-256 key always converts
	}
	raw := pub.Bytes() // 0x04 || x || y
	out := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20}
	out = append(out, raw[1:33]...)
	out = append(out, 0x22, 0x58, 0x20)
	return append(out, raw[33:65]...)
}

// RegistrationScript is the Python for Authentik's `ak shell` that registers this authenticator for username,
// replacing an earlier registration of the same name. Only model fields the installed Authentik has are set.
func (w *WebAuthn) RegistrationScript(username, rpID, name string) string {
	return fmt.Sprintf(`from authentik.core.models import User
from authentik.stages.authenticator_webauthn.models import WebAuthnDevice
user = User.objects.get(username=%q)
fields = {f.name for f in WebAuthnDevice._meta.get_fields()}
values = {"credential_id": %q, "public_key": %q, "sign_count": 0, "rp_id": %q, "confirmed": True}
WebAuthnDevice.objects.filter(user=user, name=%q).delete()
WebAuthnDevice.objects.create(user=user, name=%q, **{k: v for k, v in values.items() if k in fields})
print("paddock-webauthn ok")
`, username, w.CredentialIDBase64URL(), w.PublicKeyBase64URL(), rpID, name, name)
}

// Assert returns the credential of a WebAuthn assertion (the JSON a browser's navigator.credentials.get() gives, as
// Authentik's validation stage takes it) for the request options and the page origin.
func (w *WebAuthn) Assert(origin string, options json.RawMessage) (map[string]any, error) {
	var opts struct {
		Challenge        string `json:"challenge"`
		RPID             string `json:"rpId"`
		AllowCredentials []struct {
			ID string `json:"id"`
		} `json:"allowCredentials"`
	}
	if err := json.Unmarshal(options, &opts); err != nil {
		return nil, fmt.Errorf("authflow: WebAuthn options: %w", err)
	}
	if opts.Challenge == "" {
		return nil, errors.New("authflow: WebAuthn options without a challenge")
	}
	if len(opts.AllowCredentials) > 0 {
		allowed := false
		for _, c := range opts.AllowCredentials {
			allowed = allowed || strings.TrimRight(c.ID, "=") == w.CredentialIDBase64URL()
		}
		if !allowed {
			return nil, errors.New("authflow: the WebAuthn challenge does not allow this authenticator's credential")
		}
	}
	rpID := opts.RPID
	if rpID == "" {
		u, err := url.Parse(origin)
		if err != nil {
			return nil, err
		}
		rpID = u.Hostname()
	}
	clientData, err := json.Marshal(map[string]any{
		"type": "webauthn.get", "challenge": opts.Challenge, "origin": origin, "crossOrigin": false,
	})
	if err != nil {
		return nil, err
	}
	rpHash := sha256.Sum256([]byte(rpID))
	// Flags: user present (0x01) and user verified (0x04); the signature counter stays 0.
	authData := append(append([]byte{}, rpHash[:]...), 0x05, 0, 0, 0, 0)
	clientHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, authData...), clientHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, w.Key, digest[:])
	if err != nil {
		return nil, err
	}
	id := w.CredentialIDBase64URL()
	return map[string]any{
		"id": id, "rawId": id, "type": "public-key", "authenticatorAttachment": "cross-platform",
		"clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON": b64url(clientData), "authenticatorData": b64url(authData), "signature": b64url(sig),
		},
	}, nil
}

// validate answers Authentik's authenticator validation stage with an assertion for its WebAuthn device challenge.
func (w *WebAuthn) validate(_ context.Context, raw json.RawMessage, page *url.URL) (map[string]any, error) {
	var ch struct {
		DeviceChallenges []struct {
			DeviceClass string          `json:"device_class"`
			Challenge   json.RawMessage `json:"challenge"`
		} `json:"device_challenges"`
	}
	if err := json.Unmarshal(raw, &ch); err != nil {
		return nil, err
	}
	for _, c := range ch.DeviceChallenges {
		if c.DeviceClass != "webauthn" {
			continue
		}
		cred, err := w.Assert(page.Scheme+"://"+page.Host, c.Challenge)
		if err != nil {
			return nil, err
		}
		return map[string]any{"webauthn": cred}, nil
	}
	return nil, fmt.Errorf("authflow: MFA stage without a WebAuthn challenge: %s", truncate(raw))
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
