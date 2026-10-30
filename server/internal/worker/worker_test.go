package worker

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	"github.com/phischl/paddock-mdm/server/internal/domain/enrollment"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/valkeytest"
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
	if n, err := f.cache.NextSeq(ctx, req.EnrollmentID); err != nil || n != 1 {
		t.Fatalf("first seq of the new device: %d %v", n, err)
	}
	// PDK-475: a redelivered request after Valkey lost its data restores the counter of the device, which checked in
	// meanwhile, from device_status.last_seq.
	if _, err := f.super.Exec(ctx, "INSERT INTO device_status (device_id, organization_id, last_seq) VALUES ($1, $2, 7)", req.EnrollmentID, f.org); err != nil {
		t.Fatal(err)
	}
	redelivered := NewEnrollment(app.NewEnrollments(runner, f.pool), devicecache.New(valkeytest.Start(t).Client(t)))
	if o := redelivered.process(ctx, req.EnrollmentID.String(), body); o != ack {
		t.Fatalf("redelivery outcome %v", o)
	}
	if n, err := redelivered.cache.NextSeq(ctx, req.EnrollmentID); err != nil || n != 8 {
		t.Fatalf("first seq after the redelivery: %d %v", n, err)
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
	if err := f.cache.PutDeviceKey(ctx, keyID, devicecache.DeviceKey{Status: "stale"}, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.Reconcile(ctx, f.org); err != nil {
		t.Fatal(err)
	}
	if k, _, _ := f.cache.DeviceKey(ctx, keyID); k.Status != "quarantined" || k.DeviceID != dev {
		t.Fatalf("reconciled key %+v", k)
	}

	// PDK-475: on an emptied Valkey, a change notification that rewrites the key before the reconcile restores the
	// counter from device_status.last_seq too, so the first check-in continues the sequence instead of restarting at 1.
	if _, err := f.super.Exec(ctx, "INSERT INTO device_status (device_id, organization_id, last_seq) VALUES ($1, $2, 41)", dev, f.org); err != nil {
		t.Fatal(err)
	}
	emptied := devicecache.New(valkeytest.Start(t).Client(t))
	if err := NewCacheSync(f.pool, emptied).Changed(ctx, "device:"+f.org.String()+":"+dev.String()); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := emptied.DeviceKey(ctx, keyID); !ok {
		t.Fatal("key not rewritten")
	}
	if n, err := emptied.NextSeq(ctx, dev); err != nil || n != 42 {
		t.Fatalf("first seq after the cache loss: %d %v", n, err)
	}
	emptied = devicecache.New(valkeytest.Start(t).Client(t))
	if err := NewCacheSync(f.pool, emptied).Reconcile(ctx, f.org); err != nil {
		t.Fatal(err)
	}
	if n, err := emptied.NextSeq(ctx, dev); err != nil || n != 42 {
		t.Fatalf("first seq after the reconcile: %d %v", n, err)
	}

	// The reconcile never changes a live counter: one below last_seq (restored from a stale value while heartbeats were
	// still queued, or rolled back by an AOF replay) may be what the device holds, and raising it could quarantine the
	// device as a clone (PDK-475); one ahead of last_seq is not lowered either.
	for _, live := range []int64{5, 100} {
		stale := devicecache.New(valkeytest.Start(t).Client(t))
		if err := stale.RestoreSeq(ctx, dev, live); err != nil {
			t.Fatal(err)
		}
		if err := NewCacheSync(f.pool, stale).Reconcile(ctx, f.org); err != nil {
			t.Fatal(err)
		}
		if n, err := stale.NextSeq(ctx, dev); err != nil || n != live+1 {
			t.Fatalf("seq after reconciling a live counter of %d (last_seq 41): %d %v", live, n, err)
		}
	}
}

// TestReconcileAllContinuesPastFailingOrg (PDK-475): a device whose counter is missing gets 503 until a reconcile
// restores it, so an organization whose reconcile fails must not stop the organizations after it.
func TestReconcileAllContinuesPastFailingOrg(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	other := uuid.Must(uuid.NewV7()) // sorts after f.org: ReconcileAll walks the organizations by ID
	if _, err := f.super.Exec(ctx, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'W', 'active')",
		other, "w"+other.String()[24:]); err != nil {
		t.Fatal(err)
	}
	deviceWithKey := func(org uuid.UUID) (uuid.UUID, string) {
		dev := uuid.Must(uuid.NewV7())
		if _, err := f.super.Exec(ctx, "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'h', 'active')", dev, org); err != nil {
			t.Fatal(err)
		}
		keyID := "k-" + dev.String()
		if _, err := f.super.Exec(ctx, `INSERT INTO device_identity_key (key_id, organization_id, device_id, public_key, key_protection, status)
			VALUES ($1, $2, $3, '\x01', 'file', 'active')`, keyID, org, dev); err != nil {
			t.Fatal(err)
		}
		return dev, keyID
	}
	deviceWithKey(f.org) // its counter is made unwritable below
	dev, keyID := deviceWithKey(other)

	client := valkeytest.Start(t).Client(t)
	// Denying access to one counter makes restoring it, and so the reconcile of f.org, fail (NOPERM).
	if err := client.Do(ctx, client.B().AclSetuser().Username("default").Rule("resetkeys", "~dk:*", "~et:*", "~au:*",
		"~seq:"+dev.String()).Build()).Error(); err != nil {
		t.Fatal(err)
	}
	cache := devicecache.New(client)
	err := NewCacheSync(f.pool, cache).ReconcileAll(ctx)
	if err == nil || !strings.Contains(err.Error(), f.org.String()) {
		t.Fatalf("error of the failing organization not reported: %v", err)
	}
	if strings.Contains(err.Error(), other.String()) {
		t.Fatalf("healthy organization reported as failed: %v", err)
	}
	if _, ok, _ := cache.DeviceKey(ctx, keyID); !ok {
		t.Fatal("organization after the failing one not reconciled")
	}
	if n, err := cache.NextSeq(ctx, dev); err != nil || n != 1 {
		t.Fatalf("seq in the organization after the failing one: %d %v", n, err)
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

func (f fixture) device(t *testing.T, state string) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	if _, err := f.super.Exec(context.Background(), "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'hb', $3)", id, f.org, state); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f fixture) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := f.super.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestHeartbeatsAndClones(t *testing.T) {
	f := newFixture(t)
	runner := app.NewActionRunner(f.pool, nil, httpx.RequestID)
	r := NewReports(app.NewDeviceReports(runner, f.pool), app.NewDeviceCommands(runner, f.pool), f.cache)
	ctx := context.Background()
	dev := f.device(t, "active")
	hb := func(seq, reported int64, clone bool, at time.Time) []byte {
		b, _ := json.Marshal(ingest.Heartbeat{DeviceID: dev, OrganizationID: f.org, ReceivedAt: at, AppliedBundleVersion: 2,
			AgentVersion: "0.1.0", Health: json.RawMessage(`{"reconcile":"ok"}`), Seq: seq, ReportedSeq: reported, CloneSuspected: clone})
		return b
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	if o := r.heartbeat(ctx, "m1", hb(1, 0, false, now)); o != ack {
		t.Fatalf("outcome %v", o)
	}
	var last time.Time
	var applied, seq int64
	if err := f.super.QueryRow(ctx, "SELECT last_contact_at, applied_bundle_version, last_seq FROM device_status WHERE device_id = $1", dev).Scan(&last, &applied, &seq); err != nil {
		t.Fatal(err)
	}
	if !last.Equal(now) || applied != 2 || seq != 1 {
		t.Fatalf("status %s %d %d", last, applied, seq)
	}
	// Coalesced: a second heartbeat within 60 s does not write.
	if o := r.heartbeat(ctx, "m2", hb(2, 1, false, now.Add(time.Second))); o != ack {
		t.Fatalf("outcome %v", o)
	}
	if f.count(t, "SELECT count(*) FROM device_status WHERE device_id = $1 AND last_seq = 1", dev) != 1 {
		t.Fatal("heartbeat within 60 s was materialized")
	}

	// Two clone reports quarantine the device once, with exactly one audit event.
	for i, id := range []string{"m3", "m4"} {
		if o := r.heartbeat(ctx, id, hb(int64(5+i), 1, true, now.Add(2*time.Second))); o != ack {
			t.Fatalf("outcome %v", o)
		}
	}
	if f.count(t, "SELECT count(*) FROM device WHERE id = $1 AND state = 'quarantined'", dev) != 1 {
		t.Fatal("device not quarantined")
	}
	if n := f.count(t, "SELECT count(*) FROM action WHERE code = 'device.clone_suspected' AND target->>'id' = $1", dev.String()); n != 1 {
		t.Fatalf("%d clone events, want 1", n)
	}
	if o := r.heartbeat(ctx, "m5", []byte("{")); o != poison {
		t.Fatalf("garbage: %v", o)
	}
}

func TestEventsAreRecordedOnce(t *testing.T) {
	f := newFixture(t)
	runner := app.NewActionRunner(f.pool, nil, httpx.RequestID)
	r := NewReports(app.NewDeviceReports(runner, f.pool), app.NewDeviceCommands(runner, f.pool), f.cache)
	ctx := context.Background()
	dev := f.device(t, "active")
	body, _ := json.Marshal(ingest.Events{DeviceID: dev, OrganizationID: f.org, ReceivedAt: time.Now(), Events: []protocol.Event{
		{EventSeq: 1, Type: protocol.EventBundleApplied, OccurredAt: time.Now(), Data: json.RawMessage(`{"bundle_version":3,"secret":"x"}`)},
		{EventSeq: 2, Type: protocol.EventBundleRejected, OccurredAt: time.Now(), Data: json.RawMessage(`{"reason":"signature"}`)},
	}})
	for range 2 { // redelivery
		if o := r.events(ctx, "batch", body); o != ack {
			t.Fatalf("outcome %v", o)
		}
	}
	rows, err := f.super.Query(ctx, `SELECT code || ':' || (actor->>'type') || ':' || params::text FROM action
		WHERE target->>'id' = $1 ORDER BY code`, dev.String())
	if err != nil {
		t.Fatal(err)
	}
	got, _ := pgx.CollectRows(rows, pgx.RowTo[string])
	if len(got) != 2 || !strings.HasPrefix(got[0], "device.bundle_applied:device:") || !strings.Contains(got[0], `"bundle_version": 3`) ||
		strings.Contains(got[0], "secret") || !strings.Contains(got[1], `"reason": "signature"`) {
		t.Fatalf("events %v", got)
	}
}
