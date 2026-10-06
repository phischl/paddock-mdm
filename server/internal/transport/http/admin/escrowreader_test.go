package admin_test

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/escrowreader"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/stepupproof"
)

// stepUpProofs stands in for Authentik's step-up ID tokens and for Valkey: steppedUp registers a token per step-up,
// the bff and the use cases keep and read it by jti, and the escrow-reader verifies it (window 300 s) and counts its
// uses.
type stepUpProofs struct {
	mu     sync.Mutex
	tokens map[string]string             // jti → raw token
	claims map[string]stepupproof.Claims // raw token → claims
	uses   map[string]int64
}

func newStepUpProofs() *stepUpProofs {
	return &stepUpProofs{tokens: map[string]string{}, claims: map[string]stepupproof.Claims{}, uses: map[string]int64{}}
}

// issue registers the token of a step-up of sub at at and returns its jti.
func (p *stepUpProofs) issue(sub string, at time.Time) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	jti := fmt.Sprintf("jti-%d", len(p.claims)+1)
	raw := "token-" + jti
	p.tokens[jti] = raw
	p.claims[raw] = stepupproof.Claims{Subject: sub, JTI: jti, AuthTime: at, Expiry: at.Add(5 * time.Minute)}
	return jti
}

func (p *stepUpProofs) Put(_ context.Context, jti, raw string, _ time.Duration) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokens[jti] = raw
	return nil
}

func (p *stepUpProofs) Get(_ context.Context, jti string) (string, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	raw, ok := p.tokens[jti]
	return raw, ok, nil
}

func (p *stepUpProofs) Verify(_ context.Context, raw string) (stepupproof.Claims, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c, ok := p.claims[raw]
	if !ok || time.Since(c.AuthTime) > app.StepUpValidity {
		return stepupproof.Claims{}, stepupproof.ErrInvalid
	}
	return c, nil
}

func (p *stepUpProofs) Use(_ context.Context, jti string, _ time.Time) (int64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.uses[jti]++
	return p.uses[jti], nil
}

// escrowKeys stands in for OpenBao's escrow-wrap: RSA-OAEP ciphertexts of the disk escrow key open with it; any other
// ciphertext "decrypts" into "pw-" plus itself, and "broken" fails like a sealed OpenBao.
type escrowKeys struct{ disk *diskEscrow }

func (k escrowKeys) Decrypt(_ context.Context, version int, ciphertext string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil || version != 1 || string(raw) == "broken" {
		return nil, errors.New("decrypt failed")
	}
	if len(raw) == k.disk.key.Size() {
		return rsa.DecryptOAEP(sha256.New(), nil, k.disk.key, raw, nil)
	}
	return []byte("pw-" + string(raw)), nil
}

// newEscrowAccess runs the escrow-reader service with role paddock_escrow_reader behind its client, as the api uses
// it.
func newEscrowAccess(t *testing.T, dsn string, proofs *stepUpProofs, disk *diskEscrow) *app.EscrowAccess {
	t.Helper()
	pool, err := db.NewOrgPool(context.Background(), dsn, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	const secret = "escrow-reader-test-secret"
	srv := httptest.NewServer(escrowreader.NewService(secret, pool, proofs, proofs, escrowKeys{disk: disk}).Handler())
	t.Cleanup(srv.Close)
	return app.NewEscrowAccess(escrowreader.NewClient(srv.URL, secret), proofs)
}
