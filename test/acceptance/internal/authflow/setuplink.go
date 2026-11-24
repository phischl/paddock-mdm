package authflow

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// SetupLink runs a one-time sign-in setup link (the flow behind it, ADR 0053 decision 2) with the session in client: it
// answers the password prompt with password when the flow asks for one and registers w as the account's passkey. It
// returns the components the flow showed, in order, also on an error.
func SetupLink(ctx context.Context, client *http.Client, link, password string, w *WebAuthn) ([]string, error) {
	page, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	exec := &url.URL{Scheme: page.Scheme, Host: page.Host, Path: "/api/v3/flows/executor/" + flowSlug(page) + "/",
		RawQuery: url.Values{"query": {page.RawQuery}}.Encode()}
	ch, err := executor(ctx, client, http.MethodGet, exec, nil)
	if err != nil {
		return nil, err
	}
	var seen []string
	for step := 0; step < 10; step++ {
		seen = append(seen, ch.Component)
		var answer map[string]any
		switch ch.Component {
		case "xak-flow-redirect":
			return seen, nil
		case "ak-stage-prompt":
			if len(seen) > 1 && seen[len(seen)-2] == ch.Component {
				return seen, fmt.Errorf("authflow: the setup link's password prompt refused the password: %s", truncate(ch.Raw))
			}
			answer = map[string]any{"component": ch.Component, "password": password, "password_repeat": password}
		case "ak-stage-authenticator-webauthn":
			if w == nil {
				return seen, &StageError{Flow: exec.Path, Component: ch.Component, Raw: truncate(ch.Raw)}
			}
			cred, err := w.registration(page, ch.Raw)
			if err != nil {
				return seen, err
			}
			answer = map[string]any{"component": ch.Component, "response": cred}
		case "ak-stage-access-denied":
			return seen, fmt.Errorf("%w: Authentik denied the setup link: %s", ErrAccessDenied, ch.Error)
		default:
			return seen, &StageError{Flow: exec.Path, Component: ch.Component, Raw: truncate(ch.Raw)}
		}
		if ch, err = executor(ctx, client, http.MethodPost, exec, answer); err != nil {
			return seen, err
		}
	}
	return seen, errors.New("authflow: the setup link's flow did not finish")
}

// flowSlug is the flow of a flow page URL ("…/if/flow/<slug>/").
func flowSlug(page *url.URL) string {
	p := page.Path
	const prefix = "/if/flow/"
	if len(p) > len(prefix) && p[:len(prefix)] == prefix {
		p = p[len(prefix):]
	}
	if n := len(p); n > 0 && p[n-1] == '/' {
		p = p[:n-1]
	}
	return p
}

// registration answers the passkey setup challenge raw (navigator.credentials.create) for the relying party it names,
// as a browser on the page's origin presents it: attestation "none" with this authenticator's credential.
func (w *WebAuthn) registration(page *url.URL, raw json.RawMessage) (map[string]any, error) {
	var ch struct {
		Registration struct {
			Challenge string `json:"challenge"`
			RP        struct {
				ID string `json:"id"`
			} `json:"rp"`
		} `json:"registration"`
	}
	if err := json.Unmarshal(raw, &ch); err != nil {
		return nil, err
	}
	r := ch.Registration
	if r.Challenge == "" || r.RP.ID == "" {
		return nil, fmt.Errorf("authflow: passkey setup without challenge or relying party: %s", truncate(raw))
	}
	clientData, err := json.Marshal(map[string]any{
		"type": "webauthn.create", "challenge": r.Challenge, "origin": page.Scheme + "://" + page.Host, "crossOrigin": false,
	})
	if err != nil {
		return nil, err
	}
	cose, err := b64url.DecodeString(w.PublicKey())
	if err != nil {
		return nil, err
	}
	rpHash := sha256.Sum256([]byte(r.RP.ID))
	// Flags: user present, user verified and attested credential data (AT, 0x40); counter 0; an all-zero AAGUID.
	authData := append(rpHash[:], authenticatorFlags|0x40)
	authData = binary.BigEndian.AppendUint32(authData, 0)
	authData = append(authData, make([]byte, 16)...)
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(w.id)))
	authData = append(authData, w.id...)
	authData = append(authData, cose...)
	// CBOR map of three entries: "fmt" = "none", "attStmt" = {}, "authData" = the bytes above.
	att := []byte{0xa3, 0x63, 'f', 'm', 't', 0x64, 'n', 'o', 'n', 'e', 0x67, 'a', 't', 't', 'S', 't', 'm', 't', 0xa0,
		0x68, 'a', 'u', 't', 'h', 'D', 'a', 't', 'a'}
	att = append(att, cborBytesHeader(len(authData))...)
	att = append(att, authData...)
	id := w.CredentialID()
	return map[string]any{
		"id": id, "rawId": id, "type": "public-key", "clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    b64url.EncodeToString(clientData),
			"attestationObject": b64url.EncodeToString(att),
			"transports":        []string{"internal"},
		},
	}, nil
}

// cborBytesHeader is the head of a CBOR byte string (major type 2) of n bytes.
func cborBytesHeader(n int) []byte {
	switch {
	case n < 24:
		return []byte{0x40 | byte(n)}
	case n < 256:
		return []byte{0x58, byte(n)}
	default:
		return []byte{0x59, byte(n >> 8), byte(n)}
	}
}
