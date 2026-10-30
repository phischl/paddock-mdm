package auditwriter_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/auditwriter"
)

// keyTestEnv is an export environment whose signer uses a key version no other test uses, because audit_signing_key
// is insert-only and shared by every test of the package.
type keyTestEnv struct {
	exportEnv
	version int
	pub     ed25519.PublicKey
	signer  edSigner
	calls   *atomic.Int32
	keyFn   auditwriter.PublicKeys
}

func newKeyTestEnv(t *testing.T) keyTestEnv {
	t.Helper()
	e := newExportEnv(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	k := keyTestEnv{
		exportEnv: e, version: 1000 + int(uuid.New().ID()%1_000_000), pub: pub, calls: &atomic.Int32{},
	}
	k.signer = edSigner{priv: priv, version: k.version}
	k.keyFn = func(context.Context) (map[int][]byte, error) {
		k.calls.Add(1)
		return map[int][]byte{k.version: pub}, nil
	}
	return k
}

func (k keyTestEnv) published(t *testing.T) [][]byte {
	t.Helper()
	rows, err := k.super.Query(context.Background(), "SELECT public_key FROM audit_signing_key WHERE key_version = $1", k.version)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			t.Fatal(err)
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSealPublishesSigningKey(t *testing.T) {
	k := newKeyTestEnv(t)
	org := uuid.Must(uuid.NewV7())
	day := pastDay(5)
	k.object(t, org, day.Add(time.Hour), 1)
	sealer := auditwriter.NewSealer(k.pool, k.writer, k.signer, auditwriter.NewKeyPublisher(k.keyFn))
	if _, err := sealer.SealOrganizationThrough(context.Background(), org, day); err != nil {
		t.Fatal(err)
	}
	got := k.published(t)
	if len(got) != 1 || string(got[0]) != string(k.pub) {
		t.Fatalf("published keys of v%d = %x, want exactly %x", k.version, got, []byte(k.pub))
	}

	// Insert-only: a later, different key for the same version neither replaces the published one nor is sealed with.
	other, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	changed := func(context.Context) (map[int][]byte, error) { return map[int][]byte{k.version: other}, nil }
	org2 := uuid.Must(uuid.NewV7())
	k.object(t, org2, day.Add(time.Hour), 1)
	sealer = auditwriter.NewSealer(k.pool, k.writer, k.signer, auditwriter.NewKeyPublisher(changed))
	if _, err := sealer.SealOrganizationThrough(context.Background(), org2, day); !errors.Is(err, auditwriter.ErrSigningKeyMismatch) {
		t.Fatalf("seal with a different key: err = %v, want ErrSigningKeyMismatch", err)
	}
	var n int
	if err := k.super.QueryRow(context.Background(), "SELECT count(*) FROM audit_manifest WHERE organization_id = $1", org2).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d manifests recorded despite the key mismatch", n)
	}
	if got := k.published(t); len(got) != 1 || string(got[0]) != string(k.pub) {
		t.Fatalf("published key of v%d changed to %x", k.version, got)
	}
}

func TestSealFailsWhenTheKeyCannotBePublished(t *testing.T) {
	k := newKeyTestEnv(t)
	org := uuid.Must(uuid.NewV7())
	day := pastDay(5)
	k.object(t, org, day.Add(time.Hour), 1)
	for name, keys := range map[string]auditwriter.PublicKeys{
		"unknown version": func(context.Context) (map[int][]byte, error) { return map[int][]byte{k.version + 1: k.pub}, nil },
		"short key":       func(context.Context) (map[int][]byte, error) { return map[int][]byte{k.version: k.pub[:16]}, nil },
		"read fails":      func(context.Context) (map[int][]byte, error) { return nil, errors.New("openbao down") },
	} {
		sealer := auditwriter.NewSealer(k.pool, k.writer, k.signer, auditwriter.NewKeyPublisher(keys))
		if _, err := sealer.SealOrganizationThrough(context.Background(), org, day); err == nil {
			t.Fatalf("%s: seal succeeded without a published key", name)
		}
		var n int
		if err := k.super.QueryRow(context.Background(), "SELECT count(*) FROM audit_manifest WHERE organization_id = $1", org).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("%s: %d manifests recorded", name, n)
		}
	}
	if got := k.published(t); len(got) != 0 {
		t.Fatalf("a key was published: %x", got)
	}
}

func TestKeyPublisherReadsOpenBaoOncePerTenMinutes(t *testing.T) {
	k := newKeyTestEnv(t)
	now := time.Now()
	publisher := auditwriter.NewKeyPublisher(k.keyFn)
	auditwriter.SetKeyPublisherClock(publisher, func() time.Time { return now })
	sealer := auditwriter.NewSealer(k.pool, k.writer, k.signer, publisher)
	seal := func() {
		t.Helper()
		org := uuid.Must(uuid.NewV7())
		day := pastDay(5)
		k.object(t, org, day.Add(time.Hour), 1)
		if _, err := sealer.SealOrganizationThrough(context.Background(), org, day); err != nil {
			t.Fatal(err)
		}
	}
	seal()
	seal()
	if n := k.calls.Load(); n != 1 {
		t.Fatalf("%d reads of the public keys for two seals, want 1", n)
	}
	now = now.Add(9 * time.Minute)
	seal()
	if n := k.calls.Load(); n != 1 {
		t.Fatalf("%d reads after 9 minutes, want 1", n)
	}
	now = now.Add(2 * time.Minute)
	seal()
	if n := k.calls.Load(); n != 2 {
		t.Fatalf("%d reads after 11 minutes, want 2", n)
	}
}

func TestExportBuildPublishesSigningKey(t *testing.T) {
	k := newKeyTestEnv(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	day := pastDay(5)
	k.object(t, org, day.Add(time.Hour), 2)
	sealer := auditwriter.NewSealer(k.pool, k.writer, k.signer, auditwriter.NewKeyPublisher(k.keyFn))
	if _, err := sealer.SealOrganizationThrough(ctx, org, day); err != nil {
		t.Fatal(err)
	}
	if _, err := k.super.Exec(ctx, "DELETE FROM audit_signing_key WHERE key_version = $1", k.version); err != nil {
		t.Fatal(err)
	}
	exporter := auditwriter.NewExporter(k.pool, k.writer, k.store, k.signer, k.keyFn,
		auditwriter.NewVerifier(k.pool, k.store, k.keyFn), "test", time.Second)
	if err := exporter.Build(ctx, k.running(t, org, day, day, "keys")); err != nil {
		t.Fatal(err)
	}
	if got := k.published(t); len(got) != 1 || string(got[0]) != string(k.pub) {
		t.Fatalf("published keys of v%d after Build = %x, want %x", k.version, got, []byte(k.pub))
	}
}

func TestExportBuildFailsOnSigningKeyMismatch(t *testing.T) {
	k := newKeyTestEnv(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	day := pastDay(5)
	k.object(t, org, day.Add(time.Hour), 2)
	sealer := auditwriter.NewSealer(k.pool, k.writer, k.signer, auditwriter.NewKeyPublisher(k.keyFn))
	if _, err := sealer.SealOrganizationThrough(ctx, org, day); err != nil {
		t.Fatal(err)
	}
	other, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.super.Exec(ctx, "UPDATE audit_signing_key SET public_key = $1 WHERE key_version = $2", []byte(other), k.version); err != nil {
		t.Fatal(err)
	}
	exporter := auditwriter.NewExporter(k.pool, k.writer, k.store, k.signer, k.keyFn,
		auditwriter.NewVerifier(k.pool, k.store, k.keyFn), "test", time.Second)
	if err := exporter.Build(ctx, k.running(t, org, day, day, "mismatch")); !errors.Is(err, auditwriter.ErrSigningKeyMismatch) {
		t.Fatalf("Build with a mismatching published key: err = %v, want ErrSigningKeyMismatch", err)
	}
	if got := k.published(t); len(got) != 1 || string(got[0]) != string([]byte(other)) {
		t.Fatalf("published key of v%d was rewritten: %x", k.version, got)
	}
}
