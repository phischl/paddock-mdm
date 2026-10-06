package app_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/enrollment"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// enrollHarness runs the enrollment use case as the worker does: role paddock_worker, system principal.
type enrollHarness struct {
	enrollments *app.Enrollments
	super       *pgx.Conn
	org         uuid.UUID
	group       uuid.UUID
}

func newEnrollHarness(t *testing.T) enrollHarness {
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
	h := enrollHarness{
		enrollments: app.NewEnrollments(app.NewActionRunner(pool, nil, httpx.RequestID), pool),
		super:       super, org: uuid.Must(uuid.NewV7()), group: uuid.Must(uuid.NewV7()),
	}
	if _, err := super.Exec(ctx, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'Test', 'active')",
		h.org, "e"+h.org.String()[24:]); err != nil {
		t.Fatal(err)
	}
	if _, err := super.Exec(ctx, "INSERT INTO device_group (id, organization_id, name) VALUES ($1, $2, 'laptops')", h.group, h.org); err != nil {
		t.Fatal(err)
	}
	return h
}

// token inserts an enrollment token and returns its secret.
func (h enrollHarness) token(t *testing.T, maxUses int, autoApprove bool, expires time.Time) string {
	t.Helper()
	secret, hash, err := enrollment.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.super.Exec(context.Background(), `INSERT INTO enrollment_token
		(id, organization_id, name, secret_sha256, device_group_id, auto_approve, max_uses, expires_at, created_by)
		VALUES ($1, $2, 'test', $3, $4, $5, $6, $7, $8)`,
		uuid.Must(uuid.NewV7()), h.org, hash, h.group, autoApprove, maxUses, expires, uuid.New()); err != nil {
		t.Fatal(err)
	}
	return secret
}

func newRequest(t *testing.T, org uuid.UUID, secret string) ingest.Enroll {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := protocol.MarshalPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return ingest.Enroll{
		EnrollmentID: uuid.Must(uuid.NewV7()), OrganizationID: org, TokenSHA256: enrollment.HashSecret(secret),
		KeyID: protocol.KeyID(spki), PublicKey: spki, KeyProtection: "file", Hostname: "lt-" + uuid.NewString()[:6],
		OSRelease: map[string]string{"id": "ubuntu"}, AgentVersion: "0.1.0", ReceivedAt: time.Now(),
	}
}

func (h enrollHarness) enroll(req ingest.Enroll) (app.EnrollResult, error) {
	ctx := principal.With(context.Background(), principal.Principal{Kind: principal.KindSystem, OrganizationID: h.org})
	return h.enrollments.Enroll(httpx.WithRequestID(ctx, req.EnrollmentID.String()), req)
}

// events returns code:outcome:error_code:actor_type of the actions correlated with the enrollment.
func (h enrollHarness) events(t *testing.T, req ingest.Enroll) []string {
	t.Helper()
	rows, err := h.super.Query(context.Background(), `SELECT code || ':' || outcome || ':' || coalesce(error_code, '') || ':' || (actor->>'type')
		FROM action WHERE correlation_id = $1 ORDER BY started_at`, req.EnrollmentID.String())
	if err != nil {
		t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestEnrollCreatesDevice(t *testing.T) {
	h := newEnrollHarness(t)
	secret := h.token(t, 2, true, time.Now().Add(time.Hour))
	req := newRequest(t, h.org, secret)
	res, err := h.enroll(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.DeviceID != req.EnrollmentID || res.State != "active" || res.KeyStatus != "active" {
		t.Fatalf("result %+v", res)
	}
	var uses, members, keys, changes int
	ctx := context.Background()
	_ = h.super.QueryRow(ctx, "SELECT uses FROM enrollment_token WHERE secret_sha256 = $1", req.TokenSHA256).Scan(&uses)
	_ = h.super.QueryRow(ctx, "SELECT count(*) FROM device_group_member WHERE device_id = $1 AND device_group_id = $2", res.DeviceID, h.group).Scan(&members)
	_ = h.super.QueryRow(ctx, "SELECT count(*) FROM device_identity_key WHERE key_id = $1 AND device_id = $2", req.KeyID, res.DeviceID).Scan(&keys)
	_ = h.super.QueryRow(ctx, "SELECT count(*) FROM outbox WHERE subject = $1 AND payload->>'id' = $2", "state."+h.org.String(), res.DeviceID.String()).Scan(&changes)
	if uses != 1 || members != 1 || keys != 1 || changes != 1 {
		t.Fatalf("uses %d, members %d, keys %d, state changes %d", uses, members, keys, changes)
	}
	if got := h.events(t, req); len(got) != 1 || got[0] != "device.enrolled:success::device" {
		t.Fatalf("events %v", got)
	}

	// Redelivery: same device, no second token use, no second event.
	again, err := h.enroll(req)
	if err != nil || again != res {
		t.Fatalf("redelivery: %+v %v", again, err)
	}
	_ = h.super.QueryRow(ctx, "SELECT uses FROM enrollment_token WHERE secret_sha256 = $1", req.TokenSHA256).Scan(&uses)
	if got := h.events(t, req); uses != 1 || len(got) != 1 {
		t.Fatalf("redelivery used the token again (%d) or recorded %v", uses, got)
	}
}

func TestEnrollPendingAndRejections(t *testing.T) {
	h := newEnrollHarness(t)
	manual := h.token(t, 1, false, time.Now().Add(time.Hour))
	res, err := h.enroll(newRequest(t, h.org, manual))
	if err != nil || res.State != "pending" {
		t.Fatalf("manual token: %+v %v", res, err)
	}
	exhausted := newRequest(t, h.org, manual)
	if _, err := h.enroll(exhausted); !errors.Is(err, problem.TokenExhausted) {
		t.Fatalf("exhausted: %v", err)
	}
	if got := h.events(t, exhausted); len(got) != 1 || got[0] != "device.enrolled:failure:token_exhausted:device" {
		t.Fatalf("events %v", got)
	}

	expired := h.token(t, 5, true, time.Now().Add(-time.Minute))
	if _, err := h.enroll(newRequest(t, h.org, expired)); !errors.Is(err, problem.TokenExpired) {
		t.Fatalf("expired: %v", err)
	}
	revoked := h.token(t, 5, true, time.Now().Add(time.Hour))
	if _, err := h.super.Exec(context.Background(), "UPDATE enrollment_token SET revoked_at = now() WHERE secret_sha256 = $1", enrollment.HashSecret(revoked)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.enroll(newRequest(t, h.org, revoked)); !errors.Is(err, problem.TokenRevoked) {
		t.Fatalf("revoked: %v", err)
	}
	if _, err := h.enroll(newRequest(t, h.org, "not-a-token")); !errors.Is(err, problem.InvalidToken) {
		t.Fatalf("unknown token: %v", err)
	}

	valid := h.token(t, 5, true, time.Now().Add(time.Hour))
	badKey := newRequest(t, h.org, valid)
	badKey.KeyID = "00"
	if _, err := h.enroll(badKey); !errors.Is(err, problem.InvalidRequest) {
		t.Fatalf("key id mismatch: %v", err)
	}
	badHost := newRequest(t, h.org, valid)
	badHost.Hostname = "two\nlines"
	if _, err := h.enroll(badHost); !errors.Is(err, problem.InvalidRequest) {
		t.Fatalf("bad hostname: %v", err)
	}

	// A token of another organization is invisible (RLS): the request is rejected as unknown.
	other := newEnrollHarness(t)
	foreign := other.token(t, 5, true, time.Now().Add(time.Hour))
	if _, err := h.enroll(newRequest(t, h.org, foreign)); !errors.Is(err, problem.InvalidToken) {
		t.Fatalf("foreign token: %v", err)
	}
}
