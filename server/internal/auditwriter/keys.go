package auditwriter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/phischl/paddock-mdm/pkg/auditevidence"
	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

// ErrSigningKeyMismatch means OpenBao's public key for an audit-chain version differs from the one already published.
// Signing on would use a key whose fingerprint auditors cannot find, so the seal or export stops instead.
var ErrSigningKeyMismatch = errors.New("published audit signing key differs from the OpenBao key")

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

// Ensure records the public key of version; an already published version is left untouched and must
// match pub, otherwise ErrSigningKeyMismatch.
func (p *KeyPublisher) Ensure(ctx context.Context, q *auditstore.Queries, version int) error {
	pub, err := p.lookup(ctx, version)
	if err != nil {
		return err
	}
	return ensureSigningKey(ctx, q, version, pub)
}

// EnsureCurrent publishes the public key of OpenBao's newest audit-chain version, the one the next seal or export
// signs with, so GET /api/v1/audit/keys lists it before the first seal (PDK-652). It is idempotent and safe with
// several replicas; an already published version whose key differs is ErrSigningKeyMismatch, as for a seal.
func (p *KeyPublisher) EnsureCurrent(ctx context.Context, pool *db.AuditWriterPool) error {
	version, pub, err := p.current(ctx)
	if err != nil {
		return err
	}
	return pool.InWriter(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		return ensureSigningKey(ctx, q, version, pub)
	})
}

func (p *KeyPublisher) current(ctx context.Context) (int, []byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cached == nil || p.now().Sub(p.at) >= keyCacheTTL {
		if err := p.refresh(ctx); err != nil {
			return 0, nil, err
		}
	}
	version := 0
	for v := range p.cached {
		version = max(version, v)
	}
	if version == 0 {
		return 0, nil, fmt.Errorf("%w: OpenBao has no audit-chain public key", ErrKeyVersion)
	}
	return version, p.cached[version], nil
}

func (p *KeyPublisher) refresh(ctx context.Context) error {
	keys, err := p.keys(ctx)
	if err != nil {
		return fmt.Errorf("public keys: %w", err)
	}
	p.cached, p.at = keys, p.now()
	return nil
}

func (p *KeyPublisher) lookup(ctx context.Context, version int) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if pub, ok := p.cached[version]; ok && p.now().Sub(p.at) < keyCacheTTL {
		return pub, nil
	}
	if err := p.refresh(ctx); err != nil {
		return nil, err
	}
	pub, ok := p.cached[version]
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
	stored, err := q.GetAuditSigningKey(ctx, int32(version)) //nolint:gosec // range checked above
	if err != nil {
		return fmt.Errorf("read published audit-chain v%d: %w", version, err)
	}
	if !bytes.Equal(stored, pub) {
		slog.ErrorContext(ctx, "audit signing key differs from the published one", "key_version", version,
			"published_fingerprint", auditevidence.Fingerprint(stored), "openbao_fingerprint", auditevidence.Fingerprint(pub))
		return fmt.Errorf("%w: audit-chain v%d", ErrSigningKeyMismatch, version)
	}
	return nil
}
