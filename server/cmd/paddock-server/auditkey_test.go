package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/auditwriter"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

type auditKeyEnv struct {
	pool    *db.AuditWriterPool
	super   *pgx.Conn
	version int
	pub     ed25519.PublicKey
}

// newAuditKeyEnv uses a key version no other test uses, because audit_signing_key is insert-only.
func newAuditKeyEnv(t *testing.T) auditKeyEnv {
	t.Helper()
	ctx := context.Background()
	env := pgtest.SharedAudit(t)
	pool, err := db.NewAuditWriterPool(ctx, env.Writer, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return auditKeyEnv{pool: pool, super: super, version: 1000 + int(uuid.New().ID()%1_000_000), pub: pub}
}

func (e auditKeyEnv) published(t *testing.T) []byte {
	t.Helper()
	var pub []byte
	err := e.super.QueryRow(context.Background(), "SELECT public_key FROM audit_signing_key WHERE key_version = $1", e.version).Scan(&pub)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// TestPublishCurrentKeyRetriesUntilOpenBaoAnswers: a freshly started audit writer publishes the current key without
// any seal, retrying while OpenBao does not answer, and keeps running until it is stopped (PDK-652).
func TestPublishCurrentKeyRetriesUntilOpenBaoAnswers(t *testing.T) {
	e := newAuditKeyEnv(t)
	var calls atomic.Int32
	keys := func(context.Context) (map[int][]byte, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New("openbao sealed")
		}
		return map[int][]byte{e.version: e.pub}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		publishCurrentKey(ctx, auditwriter.NewKeyPublisher(keys), e.pool)
		close(done)
	}()
	deadline := time.Now().Add(15 * time.Second)
	for e.published(t) == nil {
		if time.Now().After(deadline) {
			t.Fatalf("v%d not published after %d reads of the public keys", e.version, calls.Load())
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := e.published(t); string(got) != string(e.pub) {
		t.Fatalf("published key = %x, want %x", got, []byte(e.pub))
	}
	select {
	case <-done:
		t.Fatal("publishCurrentKey returned before its context ended; runAll would stop the audit writer")
	case <-time.After(100 * time.Millisecond):
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("publishCurrentKey did not return after its context ended")
	}
}

// TestPublishCurrentKeyStopsOnAMismatch: a published key that differs from OpenBao's stays as it is and is not retried.
func TestPublishCurrentKeyStopsOnAMismatch(t *testing.T) {
	e := newAuditKeyEnv(t)
	other, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.super.Exec(context.Background(), "INSERT INTO audit_signing_key (key_version, public_key) VALUES ($1, $2)", e.version, []byte(other)); err != nil {
		t.Fatal(err)
	}
	keys := func(context.Context) (map[int][]byte, error) { return map[int][]byte{e.version: e.pub}, nil }
	// The publisher caches the keys, so only the log shows whether the publication was attempted again.
	var logs lockedBuffer
	defer slog.SetDefault(slog.Default())
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	publishCurrentKey(ctx, auditwriter.NewKeyPublisher(keys), e.pool)
	if n := strings.Count(logs.String(), "audit signing key differs from the published one"); n != 1 {
		t.Fatalf("the mismatch was reported %d times, want 1 (no retry after a mismatch):\n%s", n, logs.String())
	}
	if got := e.published(t); string(got) != string(other) {
		t.Fatalf("published key was rewritten to %x", got)
	}
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
