// Package command defines device commands (architecture §11.4, plan M4a decisions 1–3): the closed registry of
// command types with their lifetimes, the canonical payload and its DSSE envelope signed with the command-signing
// key, and the verification a device runs before it executes a command.
package command

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/canonicaljson"
	"github.com/phischl/paddock-mdm/pkg/dsse"
)

// PayloadType is the DSSE payload type of commands.
const PayloadType = "application/vnd.paddock.command.v1+json"

// Command types (closed registry).
const (
	TypeRotateAdminPassword = "rotate_admin_password"
)

// lifetimes are the registered types with their default lifetime (architecture §11.4).
var lifetimes = map[string]time.Duration{
	TypeRotateAdminPassword: 7 * 24 * time.Hour,
}

// Lifetime returns the default lifetime of a registered type; ok is false for any other type.
func Lifetime(typ string) (d time.Duration, ok bool) {
	d, ok = lifetimes[typ]
	return d, ok
}

// ClockTolerance is the device clock skew Verify accepts around issued_at and expires_at.
const ClockTolerance = 5 * time.Minute

// MaxEnvelopeSize bounds a command envelope.
const MaxEnvelopeSize = 16 << 10

// Command is the signed payload.
type Command struct {
	CommandID      string          `json:"command_id"`
	DeviceID       string          `json:"device_id"`
	OrganizationID string          `json:"organization_id"`
	Type           string          `json:"type"`
	Params         json.RawMessage `json:"params"` // a JSON object, {} without parameters
	IssuedAt       time.Time       `json:"issued_at"`
	ExpiresAt      time.Time       `json:"expires_at"`
}

// Encode returns the canonical JSON payload (RFC 8785); nil params are encoded as {}.
func Encode(c Command) ([]byte, error) {
	if len(c.Params) == 0 {
		c.Params = json.RawMessage(`{}`)
	}
	c.IssuedAt, c.ExpiresAt = c.IssuedAt.UTC(), c.ExpiresAt.UTC()
	return canonicaljson.Marshal(c)
}

// Trust holds the trusted command-signing keys by key ID.
type Trust struct{ Keys map[string]ed25519.PublicKey }

// TrustFromKeys builds a Trust from the keys of a bundle.
func TrustFromKeys(keys []bundle.SigningKey) (Trust, error) {
	t := Trust{Keys: map[string]ed25519.PublicKey{}}
	for _, k := range keys {
		pub, err := base64.StdEncoding.DecodeString(k.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return Trust{}, fmt.Errorf("command: invalid public key %q", k.KeyID)
		}
		t.Keys[k.KeyID] = pub
	}
	if len(t.Keys) == 0 {
		return Trust{}, errors.New("command: no trusted keys")
	}
	return t, nil
}

// Verification errors.
var (
	ErrSignature   = errors.New("command: signature invalid or not from a trusted key")
	ErrMalformed   = errors.New("command: unsupported payload type or malformed payload")
	ErrWrongDevice = errors.New("command: device or organization does not match")
	ErrExpired     = errors.New("command: expired")
	ErrNotYetValid = errors.New("command: issued in the future")
)

// Verify checks, in this order, the DSSE signature against any trusted key, the payload type and encoding, device
// and organization, and the lifetime on the device clock now with ClockTolerance. It returns the command or one of
// the verification errors. Whether the device executed the command before is the caller's check.
func Verify(envelope []byte, trust Trust, deviceID, orgID string, now time.Time) (*Command, error) {
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
	var c Command
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if c.CommandID == "" || c.Type == "" || c.IssuedAt.IsZero() || !c.ExpiresAt.After(c.IssuedAt) {
		return nil, fmt.Errorf("%w: missing command_id, type or lifetime", ErrMalformed)
	}
	if c.DeviceID != deviceID || c.OrganizationID != orgID {
		return nil, ErrWrongDevice
	}
	if now.Add(ClockTolerance).Before(c.IssuedAt) {
		return nil, ErrNotYetValid
	}
	if !now.Before(c.ExpiresAt.Add(ClockTolerance)) {
		return nil, ErrExpired
	}
	return &c, nil
}
