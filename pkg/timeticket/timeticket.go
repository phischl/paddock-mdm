// Package timeticket defines the time tickets of the dead man's switch (architecture §12.6, plan M4c decision 14):
// every check-in response carries the organization's newest ticket {organization_id, issued_at}, signed with the
// Transit key time-ticket; a device that accepts a newer ticket knows it reached Paddock and resets its counter.
package timeticket

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/phischl/paddock-mdm/pkg/canonicaljson"
	"github.com/phischl/paddock-mdm/pkg/dsse"
)

// PayloadType is the DSSE payload type of time tickets.
const PayloadType = "application/vnd.paddock.time-ticket.v1+json"

// Interval is how often the compiler issues a ticket per organization.
const Interval = 10 * time.Minute

// MaxEnvelopeSize bounds a ticket envelope.
const MaxEnvelopeSize = 4 << 10

// Ticket is the signed payload.
type Ticket struct {
	OrganizationID string    `json:"organization_id"`
	IssuedAt       time.Time `json:"issued_at"`
}

// Encode returns the canonical JSON payload (RFC 8785).
func Encode(t Ticket) ([]byte, error) {
	t.IssuedAt = t.IssuedAt.UTC()
	return canonicaljson.Marshal(t)
}

// ErrInvalid is wrapped by every refusal of a ticket.
var ErrInvalid = errors.New("timeticket: invalid ticket")

// Verify checks the signature against the trusted time-ticket keys, the payload type and the organization and
// returns the ticket. Whether it is newer than the last accepted one is the caller's check.
func Verify(envelope []byte, keys map[string]ed25519.PublicKey, orgID string) (*Ticket, error) {
	if len(envelope) > MaxEnvelopeSize {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrInvalid, MaxEnvelopeSize)
	}
	env, payload, err := dsse.Decode(envelope)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if _, err := env.VerifyEd25519(payload, keys); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if env.PayloadType != PayloadType {
		return nil, fmt.Errorf("%w: payload type %q", ErrInvalid, env.PayloadType)
	}
	var t Ticket
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil || t.IssuedAt.IsZero() {
		return nil, fmt.Errorf("%w: payload", ErrInvalid)
	}
	if t.OrganizationID != orgID {
		return nil, fmt.Errorf("%w: organization", ErrInvalid)
	}
	return &t, nil
}
