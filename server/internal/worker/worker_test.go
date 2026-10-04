package worker

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paddock-mdm/paddock/pkg/protocol"
	"github.com/paddock-mdm/paddock/server/internal/app"
	"github.com/paddock-mdm/paddock/server/internal/devicecache"
	"github.com/paddock-mdm/paddock/server/internal/domain/enrollment"
	"github.com/paddock-mdm/paddock/server/internal/ingest"
	"github.com/paddock-mdm/paddock/server/internal/platform/db"
	"github.com/paddock-mdm/paddock/server/internal/platform/httpx"
	"github.com/paddock-mdm/paddock/server/internal/testsupport/pgtest"
	"github.com/paddock-mdm/paddock/server/internal/testsupport/valkeytest"
)

type fixture struct {
	pool  *db.OrgPool
	super *pgx.Conn
	cache *devicecache.Cache
	org   uuid.UUID
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	pool, err := db.NewOrgPool(ctx, env.Worker, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	f := fixture{pool: pool, super: super, cache: devicecache.New(valkeytest.Start(t).Client(t)), org: uuid.Must(uuid.NewV7())}
	if _, err := super.Exec(ctx, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'W', 'active')",
		f.org, "w"+f.org.String()[24:]); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f fixture) token(t *testing.T, autoApprove bool) (string, uuid.UUID) {
	t.Helper()
	secret, hash, err := enrollment.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.Must(uuid.NewV7())
	if _, err := f.super.Exec(context.Background(), `INSERT INTO enrollment_token
		(id, organization_id, name, secret_sha256, auto_approve, max_uses, expires_at, created_by)
		VALUES ($1, $2, 'test', $3, $4, 1, $5, $6)`, id, f.org, hash, autoApprove, time.Now().Add(time.Hour), uuid.New()); err != nil {
		t.Fatal(err)
	}
	return secret, id
}

func (f fixture) message(t *testing.T, secret string) (ingest.Enroll, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spki, _ := protocol.MarshalPublicKey(&key.PublicKey)
	req := ingest.Enroll{
		EnrollmentID: uuid.Must(uuid.NewV7()), OrganizationID: f.org, TokenSHA256: enrollment.HashSecret(secret),
		KeyID: protocol.KeyID(spki), PublicKey: spki, KeyProtection: "file", Hostname: "lt-worker",
		AgentVersion: "0.1.0", ReceivedAt: time.Now(),
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return req, body
}

func TestEnrollmentProcess(t *testing.T) {
	f := newFixture(t)
	runner := app.NewActionRunner(f.pool, nil, httpx.RequestID)
	consumer := NewEnrollment(app.NewEnrollments(runner, f.pool), f.cache)
	ctx := context.Background()

	auto, _ := f.token(t, true)
	req, body := f.message(t, auto)
	if o := consumer.process(ctx, req.EnrollmentID.String(), body); o != ack {
		t.Fatalf("outcome %v", o)
	}
	enr, ok, err := f.cache.Enrollment(ctx, req.EnrollmentID)
	if err != nil || !ok || enr.Status != "active" || enr.DeviceID != req.EnrollmentID {
		t.Fatalf("enr: %+v %v %v", enr, ok, err)
	}
	if key, ok, _ := f.cache.DeviceKey(ctx, req.KeyID); !ok || key.Status != "active" || key.DeviceID != req.EnrollmentID {
		t.Fatalf("dk: %+v %v", key, ok)
	}

	manual, _ := f.token(t, false)
	pending, body := f.message(t, manual)
	if o := consumer.process(ctx, pending.EnrollmentID.String(), body); o != ack {
		t.Fatalf("outcome %v", o)
	}
	if enr, _, _ := f.cache.Enrollment(ctx, pending.EnrollmentID); enr.Status != "pending" {
		t.Fatalf("pending enr: %+v", enr)
	}
	if _, ok, _ := f.cache.DeviceKey(ctx, pending.KeyID); ok {
		t.Fatal("pending device key cached")
	}

	exhausted, body := f.message(t, manual)
	if o := consumer.process(ctx, exhausted.EnrollmentID.String(), body); o != ack {
		t.Fatalf("outcome %v", o)
	}
	if enr, _, _ := f.cache.Enrollment(ctx, exhausted.EnrollmentID); enr.Status != "rejected" || enr.Reason != "token_exhausted" {
		t.Fatalf("rejected enr: %+v", enr)
	}

	if o := consumer.process(ctx, "other-id", body); o != poison {
		t.Fatalf("message id mismatch: %v", o)
	}
	if o := consumer.process(ctx, exhausted.EnrollmentID.String(), []byte(`{"unknown":1}`)); o != poison {
		t.Fatalf("garbage: %v", o)
	}
}

func TestCacheSync(t *testing.T) {
	f := newFixture(t)
	s := NewCacheSync(f.pool, f.cache)
	s.interval = time.Hour // only the initial reconcile and notifications
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Run(ctx) }()

	secret, tokenID := f.token(t, true)
	hash := enrollment.HashSecret(secret)
	waitFor(t, "token cached", func() bool {
		tok, ok, _ := f.cache.Token(ctx, hash)
		return ok && tok.OrganizationID == f.org && !tok.Revoked
	})
	if _, err := f.super.Exec(ctx, "UPDATE enrollment_token SET revoked_at = now() WHERE id = $1", tokenID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "revocation cached", func() bool {
		tok, _, _ := f.cache.Token(ctx, hash)
		return tok.Revoked
	})

	dev := uuid.Must(uuid.NewV7())
	if _, err := f.super.Exec(ctx, "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'h', 'active')", dev, f.org); err != nil {
		t.Fatal(err)
	}
	keyID := "k-" + dev.String()
	if _, err := f.super.Exec(ctx, `INSERT INTO device_identity_key (key_id, organization_id, device_id, public_key, key_protection, status)
		VALUES ($1, $2, $3, '\x01', 'file', 'active')`, keyID, f.org, dev); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "device key cached", func() bool {
		k, ok, _ := f.cache.DeviceKey(ctx, keyID)
		return ok && k.Status == "active"
	})
	if _, err := f.super.Exec(ctx, "UPDATE device SET state = 'quarantined' WHERE id = $1", dev); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "quarantine cached", func() bool {
		k, _, _ := f.cache.DeviceKey(ctx, keyID)
		return k.Status == "quarantined"
	})

	// An emptied Valkey is rebuilt by the reconcile.
	if err := f.cache.PutDeviceKey(ctx, keyID, devicecache.DeviceKey{Status: "stale"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Reconcile(ctx, f.org); err != nil {
		t.Fatal(err)
	}
	if k, _, _ := f.cache.DeviceKey(ctx, keyID); k.Status != "quarantined" || k.DeviceID != dev {
		t.Fatalf("reconciled key %+v", k)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timeout waiting for %s", what)
}
