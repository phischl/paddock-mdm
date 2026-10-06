// Package revocation defines revocation tokens (architecture §12.3, plan M4c decisions 3, 8 and 15): the canonical
// payload, its DSSE envelope signed with the revocation-signing key, the device's pinned trust anchor
// (/etc/paddock/revoke-trust.json) and the verification paddock-revoke runs before it touches a keyslot.
package revocation

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/phischl/paddock-mdm/pkg/canonicaljson"
	"github.com/phischl/paddock-mdm/pkg/dsse"
)

// PayloadType is the DSSE payload type of revocation tokens.
const PayloadType = "application/vnd.paddock.revocation.v1+json"

// Actions of a revocation token.
const (
	ActionLock     = "lock"
	ActionDestroy  = "destroy"
	ActionSelfLock = "self_lock" // the dead man's switch; valid only after PeriodDays of uptime without contact
)

// Lifetime is the validity of a Lock or Destroy token (plan M4c decision 8).
const Lifetime = 30 * 24 * time.Hour

// ClockTolerance is the device clock skew Verify accepts for issued_at in the future.
const ClockTolerance = 5 * time.Minute

// MaxEnvelopeSize bounds a revocation envelope.
const MaxEnvelopeSize = 8 << 10

// Token is the signed payload.
type Token struct {
	CommandID      string    `json:"command_id"`
	DeviceID       string    `json:"device_id"`
	OrganizationID string    `json:"organization_id"`
	Action         string    `json:"action"`
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	RequestID      string    `json:"request_id"`
	// PeriodDays is the dead man's switch period of a self_lock token (0 otherwise).
	PeriodDays int `json:"period_days,omitempty"`
}

// Encode returns the canonical JSON payload (RFC 8785).
func Encode(t Token) ([]byte, error) {
	t.IssuedAt, t.ExpiresAt = t.IssuedAt.UTC(), t.ExpiresAt.UTC()
	return canonicaljson.Marshal(t)
}

// Key is a revocation-signing public key with its DSSE key ID, e.g. "revocation-signing:v1".
type Key struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"` // standard base64 raw Ed25519 public key
}

// TrustFile is /etc/paddock/revoke-trust.json.
type TrustFile struct {
	RevocationKeys []Key `json:"revocation_keys"`
}

// Trust holds the trusted revocation-signing keys by key ID.
type Trust struct{ Keys map[string]ed25519.PublicKey }

// TrustFromKeys builds a Trust; it needs at least one valid key.
func TrustFromKeys(keys []Key) (Trust, error) {
	t := Trust{Keys: map[string]ed25519.PublicKey{}}
	for _, k := range keys {
		pub, err := base64.StdEncoding.DecodeString(k.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize || k.KeyID == "" {
			return Trust{}, fmt.Errorf("revocation: invalid public key %q", k.KeyID)
		}
		t.Keys[k.KeyID] = pub
	}
	if len(t.Keys) == 0 {
		return Trust{}, errors.New("revocation: no trusted keys")
	}
	return t, nil
}

// ParseTrust parses the content of revoke-trust.json.
func ParseTrust(data []byte) (Trust, error) {
	var f TrustFile
	if err := json.Unmarshal(data, &f); err != nil {
		return Trust{}, fmt.Errorf("revocation: trust file: %w", err)
	}
	return TrustFromKeys(f.RevocationKeys)
}

// Verification errors.
var (
	ErrSignature   = errors.New("revocation: signature invalid or not from a trusted key")
	ErrMalformed   = errors.New("revocation: unsupported payload type or malformed payload")
	ErrWrongDevice = errors.New("revocation: device does not match")
	ErrExpired     = errors.New("revocation: expired")
	ErrNotYetValid = errors.New("revocation: issued in the future")
)

// Verify checks, in this order, the DSSE signature against a trusted key, the payload type and encoding, the action,
// the device and the lifetime on the device clock now (expires_at must be after now; issued_at at most
// ClockTolerance in the future). Whether the token was executed before is the caller's check.
func Verify(envelope []byte, trust Trust, deviceID string, now time.Time) (*Token, error) {
	if len(envelope) > MaxEnvelopeSize {
		return nil, fmt.Errorf("%w: envelope larger than %d bytes", ErrMalformed, MaxEnvelopeSize)
	}
	env, payload, err := dsse.Decode(envelope)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignature, err)
	}
	if _, err := env.VerifyEd25519(payload, trust.Keys); err != nil {
		return nil, ErrSignature
	}
	if env.PayloadType != PayloadType {
		return nil, fmt.Errorf("%w: payload type %q", ErrMalformed, env.PayloadType)
	}
	var t Token
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if err := t.validate(); err != nil {
		return nil, err
	}
	if t.DeviceID != deviceID {
		return nil, ErrWrongDevice
	}
	if now.Add(ClockTolerance).Before(t.IssuedAt) {
		return nil, ErrNotYetValid
	}
	if !now.Before(t.ExpiresAt) {
		return nil, ErrExpired
	}
	return &t, nil
}

func (t Token) validate() error {
	switch {
	case t.CommandID == "" || t.DeviceID == "" || t.OrganizationID == "" || t.RequestID == "":
		return fmt.Errorf("%w: missing command_id, device_id, organization_id or request_id", ErrMalformed)
	case t.IssuedAt.IsZero() || !t.ExpiresAt.After(t.IssuedAt):
		return fmt.Errorf("%w: missing or empty lifetime", ErrMalformed)
	case t.Action == ActionSelfLock && t.PeriodDays <= 0:
		return fmt.Errorf("%w: self_lock without period_days", ErrMalformed)
	case t.Action != ActionSelfLock && t.PeriodDays != 0:
		return fmt.Errorf("%w: period_days on a %s token", ErrMalformed, t.Action)
	case t.Action != ActionLock && t.Action != ActionDestroy && t.Action != ActionSelfLock:
		return fmt.Errorf("%w: action %q", ErrMalformed, t.Action)
	}
	return nil
}

// IsRevocation reports whether a DSSE envelope carries a revocation token, by its payload type only: paddockd uses
// it to hand an envelope to paddock-revoke without interpreting the payload (plan M4c decision 11).
func IsRevocation(envelope []byte) bool {
	var e struct {
		PayloadType string `json:"payloadType"`
	}
	return json.Unmarshal(envelope, &e) == nil && e.PayloadType == PayloadType
}
