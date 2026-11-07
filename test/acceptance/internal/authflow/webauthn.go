package authflow

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
)

// Authenticator answers the MFA stage (ak-stage-authenticator-validate) of an Authentik flow.
type Authenticator interface {
	answer(ctx context.Context, page *url.URL, raw json.RawMessage) (map[string]any, error)
}

func (t *TOTP) answer(ctx context.Context, _ *url.URL, raw json.RawMessage) (map[string]any, error) {
	return validateAnswer(ctx, raw, t)
}

// totpAuthenticator keeps a nil *TOTP a nil Authenticator, so runFlow still refuses an MFA stage it cannot answer.
func totpAuthenticator(t *TOTP) Authenticator {
	if t == nil {
		return nil
	}
	return t
}

// WebAuthn is a software WebAuthn authenticator with one ES256 credential. A production-profile installation accepts
// only WebAuthn for its sign-in and step-up (plan M8f decision 13, plan M8s decision 40), so the system gates that
// drive one register this credential with the user's Authentik account (CredentialID, PublicKey) and answer the
// assertion headlessly. The signature counter stays 0, which WebAuthn allows for an authenticator without one.
type WebAuthn struct {
	key *ecdsa.PrivateKey
	id  []byte
}

// NewWebAuthn creates an authenticator with a new random credential.
func NewWebAuthn() (*WebAuthn, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	return &WebAuthn{key: key, id: id}, nil
}

var b64url = base64.RawURLEncoding

// CredentialID is the credential's ID, base64url without padding (Authentik's WebAuthnDevice.credential_id).
func (w *WebAuthn) CredentialID() string { return b64url.EncodeToString(w.id) }

// PublicKey is the credential's public key as a COSE_Key (RFC 9053: EC2, ES256, P-256), base64url without padding
// (Authentik's WebAuthnDevice.public_key).
func (w *WebAuthn) PublicKey() string {
	// The uncompressed point 0x04 || x || y of a P-256 key never fails to encode.
	point, _ := w.key.PublicKey.Bytes()
	x, y := point[1:33], point[33:65]
	// CBOR map of five entries: 1 (kty) = 2 (EC2), 3 (alg) = -7 (ES256), -1 (crv) = 1 (P-256), -2 = x, -3 = y; the
	// 32-byte strings are major type 2 with a one-byte length (0x58 0x20).
	cose := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20}
	cose = append(cose, x...)
	cose = append(cose, 0x22, 0x58, 0x20)
	cose = append(cose, y...)
	return b64url.EncodeToString(cose)
}

// authenticatorFlags are user present (UP) and user verified (UV): the authenticator stands in for a key whose user
// verification a stage may require.
const authenticatorFlags = 0x01 | 0x04

func (w *WebAuthn) answer(_ context.Context, page *url.URL, raw json.RawMessage) (map[string]any, error) {
	var ch struct {
		DeviceChallenges []struct {
			DeviceClass string `json:"device_class"`
			Challenge   struct {
				Challenge        string `json:"challenge"`
				RPID             string `json:"rpId"`
				AllowCredentials []struct {
					ID string `json:"id"`
				} `json:"allowCredentials"`
			} `json:"challenge"`
		} `json:"device_challenges"`
	}
	if err := json.Unmarshal(raw, &ch); err != nil {
		return nil, err
	}
	for _, dc := range ch.DeviceChallenges {
		if dc.DeviceClass != "webauthn" {
			continue
		}
		c := dc.Challenge
		if c.Challenge == "" || c.RPID == "" {
			return nil, fmt.Errorf("authflow: WebAuthn challenge without challenge or rpId: %s", truncate(raw))
		}
		allowed := len(c.AllowCredentials) == 0
		for _, a := range c.AllowCredentials {
			allowed = allowed || a.ID == w.CredentialID()
		}
		if !allowed {
			return nil, errors.New("authflow: the WebAuthn challenge does not allow this authenticator's credential")
		}
		assertion, err := w.assert(c.Challenge, c.RPID, page.Scheme+"://"+page.Host)
		if err != nil {
			return nil, err
		}
		return map[string]any{"webauthn": assertion}, nil
	}
	return nil, fmt.Errorf("authflow: MFA stage without WebAuthn challenge: %s", truncate(raw))
}

// assert signs a WebAuthn assertion (navigator.credentials.get) for challenge at the relying party rpID, as a browser
// on origin presents it, in the JSON form of a PublicKeyCredential.
func (w *WebAuthn) assert(challenge, rpID, origin string) (map[string]any, error) {
	clientData, err := json.Marshal(map[string]any{
		"type": "webauthn.get", "challenge": challenge, "origin": origin, "crossOrigin": false,
	})
	if err != nil {
		return nil, err
	}
	rpHash := sha256.Sum256([]byte(rpID))
	authData := append(rpHash[:], authenticatorFlags)
	authData = binary.BigEndian.AppendUint32(authData, 0)
	clientHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(slices.Clone(authData), clientHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, w.key, digest[:])
	if err != nil {
		return nil, err
	}
	id := w.CredentialID()
	return map[string]any{
		"id": id, "rawId": id, "type": "public-key", "clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    b64url.EncodeToString(clientData),
			"authenticatorData": b64url.EncodeToString(authData),
			"signature":         b64url.EncodeToString(sig),
		},
	}, nil
}
