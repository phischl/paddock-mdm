// Package stepupproof checks and keeps the ID tokens of step-up authentications (plan M4b.1 decisions 6–8): their
// signature against the issuer's cached JWKS and their claims, the raw token in Valkey for the decryptions of the
// session that ran the step-up, and a use counter per token.
package stepupproof

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// ErrInvalid is wrapped by every refusal of a token.
var ErrInvalid = errors.New("stepupproof: invalid step-up token")

// clockSkew is the tolerance for an auth_time in the future.
const clockSkew = time.Minute

// Claims are the checked claims of a step-up ID token.
type Claims struct {
	Subject  string
	JTI      string
	AuthTime time.Time
	Expiry   time.Time
}

// Verifier checks step-up ID tokens of one issuer and client: signature (JWKS, fetched and cached by go-oidc),
// iss, aud and exp, an auth_time at most Window old, MFA in amr, and sub and jti present. Discovery is retried in the
// background until the issuer answers.
type Verifier struct {
	issuer, clientID string
	window           time.Duration
	now              func() time.Time

	mu       sync.RWMutex
	verifier *oidc.IDTokenVerifier
}

// NewVerifier creates a verifier; call Discover to connect. now is the clock (time.Now in production).
func NewVerifier(issuer, clientID string, window time.Duration, now func() time.Time) *Verifier {
	return &Verifier{issuer: issuer, clientID: clientID, window: window, now: now}
}

// Ready reports whether discovery succeeded.
func (v *Verifier) Ready() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.verifier != nil
}

// Discover retries provider discovery every 5 s until it succeeds or ctx ends. ctx also bounds the JWKS fetches of
// the discovered key set, so it is the role's lifetime context.
func (v *Verifier) Discover(ctx context.Context) {
	for {
		provider, err := oidc.NewProvider(ctx, v.issuer)
		if err == nil {
			v.mu.Lock()
			v.verifier = provider.Verifier(&oidc.Config{ClientID: v.clientID, Now: v.now})
			v.mu.Unlock()
			slog.InfoContext(ctx, "step-up issuer discovered", "issuer", v.issuer)
			return
		}
		slog.WarnContext(ctx, "step-up issuer discovery failed; retrying", "issuer", v.issuer, "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// Verify checks raw and returns its claims; every refusal wraps ErrInvalid.
func (v *Verifier) Verify(ctx context.Context, raw string) (Claims, error) {
	v.mu.RLock()
	verifier := v.verifier
	v.mu.RUnlock()
	if verifier == nil {
		return Claims{}, errors.New("stepupproof: issuer not discovered")
	}
	idt, err := verifier.Verify(ctx, raw)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	var c struct {
		AuthTime int64    `json:"auth_time"`
		AMR      []string `json:"amr"`
		JTI      string   `json:"jti"`
	}
	if err := idt.Claims(&c); err != nil {
		return Claims{}, fmt.Errorf("%w: claims: %v", ErrInvalid, err)
	}
	out := Claims{Subject: idt.Subject, JTI: c.JTI, AuthTime: time.Unix(c.AuthTime, 0), Expiry: idt.Expiry}
	return out, v.check(out, c.AuthTime, c.AMR)
}

func (v *Verifier) check(c Claims, authTime int64, amr []string) error {
	age := v.now().Sub(c.AuthTime)
	switch {
	case c.Subject == "" || c.JTI == "":
		return fmt.Errorf("%w: sub or jti missing", ErrInvalid)
	case authTime == 0 || age > v.window || age < -clockSkew:
		return fmt.Errorf("%w: auth_time missing or older than %s", ErrInvalid, v.window)
	case !slices.Contains(amr, "mfa"):
		return fmt.Errorf("%w: no MFA in amr", ErrInvalid)
	}
	return nil
}
