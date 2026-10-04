// Package dsse implements the Dead Simple Signing Envelope (DSSE v1) with Ed25519 signatures: pre-authentication
// encoding, envelope encoding and verification (architecture §7.2).
package dsse

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// MaxEnvelopeSize bounds the envelopes Decode accepts.
const MaxEnvelopeSize = 16 << 20

// Signature is one signature of an envelope.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"` // standard base64
}

// Envelope is a DSSE envelope. Payload is standard base64 of the payload bytes.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

var (
	// ErrMalformed means the envelope is not valid DSSE JSON.
	ErrMalformed = errors.New("dsse: malformed envelope")
	// ErrNoValidSignature means no signature verified against a trusted key.
	ErrNoValidSignature = errors.New("dsse: no valid signature from a trusted key")
)

// PAE is the pre-authentication encoding that is signed:
// "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body.
func PAE(payloadType string, payload []byte) []byte {
	out := make([]byte, 0, 32+len(payloadType)+len(payload))
	out = append(out, "DSSEv1 "...)
	out = strconv.AppendInt(out, int64(len(payloadType)), 10)
	out = append(out, ' ')
	out = append(out, payloadType...)
	out = append(out, ' ')
	out = strconv.AppendInt(out, int64(len(payload)), 10)
	out = append(out, ' ')
	return append(out, payload...)
}

// New builds an envelope from payload and signatures over PAE(payloadType, payload).
func New(payloadType string, payload []byte, sigs ...Signature) Envelope {
	return Envelope{PayloadType: payloadType, Payload: base64.StdEncoding.EncodeToString(payload), Signatures: sigs}
}

// SignEd25519 signs PAE(payloadType, payload) with key and returns the signature entry.
func SignEd25519(key ed25519.PrivateKey, keyID, payloadType string, payload []byte) Signature {
	return Signature{KeyID: keyID, Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(key, PAE(payloadType, payload)))}
}

// Encode returns the JSON form of the envelope.
func (e Envelope) Encode() ([]byte, error) { return json.Marshal(e) }

// Decode parses an envelope and its payload. Both standard and URL-safe base64 are accepted, as the DSSE
// specification requires.
func Decode(b []byte) (Envelope, []byte, error) {
	if len(b) > MaxEnvelopeSize {
		return Envelope{}, nil, fmt.Errorf("%w: larger than %d bytes", ErrMalformed, MaxEnvelopeSize)
	}
	var e Envelope
	if err := json.Unmarshal(b, &e); err != nil {
		return Envelope{}, nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if e.PayloadType == "" || len(e.Signatures) == 0 {
		return Envelope{}, nil, fmt.Errorf("%w: missing payloadType or signatures", ErrMalformed)
	}
	payload, err := decodeBase64(e.Payload)
	if err != nil {
		return Envelope{}, nil, fmt.Errorf("%w: payload: %v", ErrMalformed, err)
	}
	return e, payload, nil
}

// VerifyEd25519 checks that at least one signature verifies against the key of the same key ID in trusted and
// returns that key ID.
func (e Envelope) VerifyEd25519(payload []byte, trusted map[string]ed25519.PublicKey) (string, error) {
	msg := PAE(e.PayloadType, payload)
	for _, s := range e.Signatures {
		key, ok := trusted[s.KeyID]
		if !ok || len(key) != ed25519.PublicKeySize {
			continue
		}
		sig, err := decodeBase64(s.Sig)
		if err != nil {
			continue
		}
		if ed25519.Verify(key, msg, sig) {
			return s.KeyID, nil
		}
	}
	return "", ErrNoValidSignature
}

func decodeBase64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("invalid base64")
}
