package auditwriter

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
)

// keyCacheTTL bounds how long the audit-chain public keys read from OpenBao are reused (plan M10 decision 36). A
// rotation is picked up at the latest after this time; a version the cache does not know forces a read at once.
const keyCacheTTL = 10 * time.Minute

// signingKeyLen is the size of an ed25519 public key (the audit_signing_key CHECK).
const signingKeyLen = 32

// KeyPublisher records the public key of every version the audit writer signed with in audit_signing_key, so the
// portal and the API can show the fingerprints without reading Transit (ADR 0032 §5).
type KeyPublisher struct {
	keys PublicKeys
	now  func() time.Time

	mu     sync.Mutex
	cached map[int][]byte
	at     time.Time
}

// NewKeyPublisher creates a publisher that reads the public keys with keys and caches them for ten minutes.
func NewKeyPublisher(keys PublicKeys) *KeyPublisher {
	return &KeyPublisher{keys: keys, now: time.Now}
}

// Ensure records the public key of version; an already published version is left untouched.
func (p *KeyPublisher) Ensure(ctx context.Context, q *auditstore.Queries, version int) error {
	pub, err := p.lookup(ctx, version)
	if err != nil {
		return err
	}
	return ensureSigningKey(ctx, q, version, pub)
}

func (p *KeyPublisher) lookup(ctx context.Context, version int) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if pub, ok := p.cached[version]; ok && p.now().Sub(p.at) < keyCacheTTL {
		return pub, nil
	}
	keys, err := p.keys(ctx)
	if err != nil {
		return nil, fmt.Errorf("public keys: %w", err)
	}
	p.cached, p.at = keys, p.now()
	pub, ok := keys[version]
	if !ok {
		return nil, fmt.Errorf("%w: audit-chain v%d has no public key", ErrKeyVersion, version)
	}
	return pub, nil
}

func ensureSigningKey(ctx context.Context, q *auditstore.Queries, version int, pub []byte) error {
	if version < 1 || version > math.MaxInt32 {
		return fmt.Errorf("%w: %d", ErrKeyVersion, version)
	}
	if len(pub) != signingKeyLen {
		return fmt.Errorf("audit-chain v%d: public key has %d bytes, want %d", version, len(pub), signingKeyLen)
	}
	if err := q.EnsureAuditSigningKey(ctx, auditstore.EnsureAuditSigningKeyParams{KeyVersion: int32(version), PublicKey: pub}); err != nil { //nolint:gosec // range checked above
		return fmt.Errorf("publish audit-chain v%d: %w", version, err)
	}
	return nil
}
