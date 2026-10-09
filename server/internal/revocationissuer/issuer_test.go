package revocationissuer_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/pkg/revocation"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/platform/valkey"
	"github.com/phischl/paddock-mdm/server/internal/revocationissuer"
	"github.com/phischl/paddock-mdm/server/internal/stepupproof"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/valkeytest"
)

// proofs accepts the raw tokens it knows: token → claims.
type proofs struct {
	mu     sync.Mutex
	claims map[string]stepupproof.Claims
}

func (p *proofs) VerifyApproval(_ context.Context, raw string, _ time.Time) (stepupproof.Claims, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c, ok := p.claims[raw]
	if !ok {
		return c, stepupproof.ErrInvalid
	}
	return c, nil
}

// signer signs like Transit with one Ed25519 key (version 1).
type signer struct{ key ed25519.PrivateKey }

func (s signer) SignBatch(_ context.Context, key string, messages [][]byte) ([]bao.RawSignature, error) {
	if key != "revocation-signing" {
		return nil, fmt.Errorf("signer: key %s", key)
	}
	out := make([]bao.RawSignature, len(messages))
	for i, m := range messages {
		out[i] = bao.RawSignature{Value: ed25519.Sign(s.key, m), KeyVersion: 1}
	}
	return out, nil
}

// commands records cmd:<device_id>.
type commands struct {
	mu  sync.Mutex
	put map[uuid.UUID]devicecache.Command
}

func (c *commands) PutCommand(_ context.Context, _, id uuid.UUID, cmd devicecache.Command) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.put[id] = cmd
	return nil
}

func (c *commands) DeleteCommand(_ context.Context, _, id uuid.UUID) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.put, id)
	return nil
}

func (c *commands) HasCommand(_ context.Context, _, id uuid.UUID) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.put[id]
	return ok, nil
}

// shredder records the prefixes it deleted; fail makes it fail.
type shredder struct {
	mu       sync.Mutex
	prefixes []string
	fail     bool
}

func (s *shredder) DeleteAllVersions(_ context.Context, prefix string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return 0, errors.New("object store down")
	}
	s.prefixes = append(s.prefixes, prefix)
	return 2, nil
}

type world struct {
	t        *testing.T
	super    *pgx.Conn
	proofs   *proofs
	commands *commands
	shredder *shredder
	trust    revocation.Trust
	issuer   *revocationissuer.Issuer
	org      uuid.UUID
	// admins of the organization and their subjects
	alice, bob, carol uuid.UUID
	tokens            int
}

func newWorld(t *testing.T, enabled bool) *world {
	t.Helper()
	ctx := context.Background()
	pg := pgtest.SharedPaddock(t)
	super, err := pgx.Connect(ctx, pg.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	pool, err := db.NewOrgPool(ctx, pg.Revocation, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	vk, err := valkey.New(valkeytest.Start(t).Config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(vk.Close)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	trust, _ := revocation.TrustFromKeys([]revocation.Key{{KeyID: "revocation-signing:v1", PublicKey: base64.StdEncoding.EncodeToString(pub)}})
	w := &world{t: t, super: super, proofs: &proofs{claims: map[string]stepupproof.Claims{}},
		commands: &commands{put: map[uuid.UUID]devicecache.Command{}}, shredder: &shredder{}, trust: trust,
		org: uuid.Must(uuid.NewV7())}
	w.issuer = revocationissuer.New(pool, app.NewActionRunner(pool, nil, httpx.RequestID), w.proofs,
		revocationissuer.NewJTIClaims(vk), signer{priv}, w.commands, w.shredder, enabled)
	w.exec("INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'R', 'active')", w.org, "r"+w.org.String()[24:])
	w.alice, w.bob, w.carol = w.admin("org_admin"), w.admin("org_admin"), w.admin("org_operator")
	return w
}

func (w *world) exec(sql string, args ...any) {
	w.t.Helper()
	if _, err := w.super.Exec(context.Background(), sql, args...); err != nil {
		w.t.Fatalf("%s: %v", sql, err)
	}
}

func (w *world) admin(role string) uuid.UUID {
	id := uuid.Must(uuid.NewV7())
	w.exec(`INSERT INTO admin_account (id, organization_id, authentik_sub, username, display_name, role)
		VALUES ($1, $2, $3, $3, $3, $4)`, id, w.org, "sub-"+id.String(), role)
	return id
}

func subject(admin uuid.UUID) string { return "sub-" + admin.String() }

func (w *world) device() uuid.UUID {
	id := uuid.Must(uuid.NewV7())
	w.exec("INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, $3, 'active')", id, w.org, "lt-"+id.String()[30:])
	return id
}

// token registers a valid step-up token of sub and returns raw token and jti.
func (w *world) token(sub string) (string, string) {
	w.tokens++
	jti := fmt.Sprintf("jti-%s-%d", w.org.String()[24:], w.tokens)
	raw := "token-" + jti
	w.proofs.mu.Lock()
	w.proofs.claims[raw] = stepupproof.Claims{Subject: sub, JTI: jti, AuthTime: time.Now(), Expiry: time.Now().Add(time.Minute)}
	w.proofs.mu.Unlock()
	return raw, jti
}

// approval is one approval row as the api writes it.
type approval struct {
	role, subject, raw, jti string
	admin                   uuid.UUID
}

func (w *world) approval(role string, admin uuid.UUID) approval {
	raw, jti := w.token(subject(admin))
	return approval{role: role, admin: admin, subject: subject(admin), raw: raw, jti: jti}
}

// request inserts an approved request with its approvals and returns its ID.
func (w *world) request(action string, dev, requester uuid.UUID, approvals ...approval) uuid.UUID {
	id := uuid.Must(uuid.NewV7())
	w.exec(`INSERT INTO revocation_request (id, organization_id, device_id, action, status, requested_by, approved_at)
		VALUES ($1, $2, $3, $4, 'approved', $5, now())`, id, w.org, dev, action, requester)
	for _, a := range approvals {
		w.exec(`INSERT INTO revocation_approval (request_id, organization_id, role, admin_id, subject, stepup_jti, stepup_id_token)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`, id, w.org, a.role, a.admin, a.subject, a.jti, a.raw)
	}
	return id
}

func (w *world) lock(dev, admin uuid.UUID) uuid.UUID {
	return w.request("lock", dev, admin, w.approval("requester", admin))
}

func (w *world) status(id uuid.UUID) (string, string) {
	w.t.Helper()
	var status string
	var rejection *string
	if err := w.super.QueryRow(context.Background(), "SELECT status, rejection FROM revocation_request WHERE id = $1", id).Scan(&status, &rejection); err != nil {
		w.t.Fatal(err)
	}
	if rejection == nil {
		return status, ""
	}
	return status, *rejection
}

// events returns code:outcome of the audit events of a request.
func (w *world) events(id uuid.UUID) []string {
	w.t.Helper()
	rows, err := w.super.Query(context.Background(),
		"SELECT code || ':' || outcome FROM action WHERE params ->> 'request_id' = $1 ORDER BY started_at", id.String())
	if err != nil {
		w.t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		w.t.Fatal(err)
	}
	return out
}

func (w *world) issue(id uuid.UUID) {
	w.t.Helper()
	if err := w.issuer.Issue(context.Background(), w.org, id); err != nil {
		w.t.Fatalf("issue %s: %v", id, err)
	}
}

// TestIssueLock (architecture §12.3): a verified Lock is signed for the device, recorded as issued and put into
// cmd:<device_id>.
func TestIssueLock(t *testing.T) {
	w := newWorld(t, true)
	dev := w.device()
	id := w.lock(dev, w.alice)
	w.issue(id)
	if s, _ := w.status(id); s != "issued" {
		t.Fatalf("status %s", s)
	}
	cmd, ok := w.commands.put[id]
	if !ok {
		t.Fatal("not in cmd:<device_id>")
	}
	tok, err := revocation.Verify(cmd.Envelope, w.trust, dev.String(), time.Now())
	if err != nil || tok.Action != "lock" || tok.CommandID != id.String() || tok.RequestID != id.String() ||
		tok.OrganizationID != w.org.String() || !tok.ExpiresAt.Equal(cmd.ExpiresAt) || tok.ExpiresAt.Sub(tok.IssuedAt) != revocation.Lifetime {
		t.Fatalf("token %+v, %v", tok, err)
	}
	if got := w.events(id); !slices.Equal(got, []string{"revocation.issued:success"}) {
		t.Fatalf("events %v", got)
	}
	// A second message for the same request changes nothing.
	w.issue(id)
	if got := w.events(id); len(got) != 1 {
		t.Fatalf("events after a redelivery %v", got)
	}
}

// TestIssueDestroy (plan M4c decision 9, gate R2): two distinct administrators; every header object version and
// every LUKS escrow row is deleted before the token is issued; Lock keeps the escrow.
func TestIssueDestroy(t *testing.T) {
	w := newWorld(t, true)
	dev := w.device()
	for _, kind := range []string{"luks_recovery_key", "admin_password"} {
		w.exec(`INSERT INTO escrow_secret (id, organization_id, device_id, kind, generation, status, ciphertext, key_version)
			VALUES ($1, $2, $3, $4, 1, 'stored', '\x01', 1)`, uuid.New(), w.org, dev, kind)
	}
	w.exec(`INSERT INTO escrow_secret (id, organization_id, device_id, kind, generation, status, key_version, object_key, wrapped_dek,
		nonce, sha256, size) VALUES ($1, $2, $3, 'luks_header', 1, 'stored', 1, 'k', '\x01', '\x000000000000000000000000', $4, 1)`,
		uuid.New(), w.org, dev, strings.Repeat("a", 64))
	w.shredder.fail = true
	id := w.request("destroy", dev, w.alice, w.approval("requester", w.alice), w.approval("approver", w.bob))
	if err := w.issuer.Issue(context.Background(), w.org, id); err == nil {
		t.Fatal("issued although the escrow objects could not be deleted")
	}
	if s, _ := w.status(id); s != "approved" {
		t.Fatalf("after a failed deletion: %s", s)
	}
	w.shredder.fail = false
	w.issue(id)
	if s, _ := w.status(id); s != "issued" {
		t.Fatalf("status %s", s)
	}
	want := "org/" + w.org.String() + "/devices/" + dev.String() + "/luks-header/"
	if !slices.Equal(w.shredder.prefixes, []string{want}) {
		t.Fatalf("deleted prefixes %v", w.shredder.prefixes)
	}
	var kinds []string
	rows, _ := w.super.Query(context.Background(), "SELECT kind FROM escrow_secret WHERE device_id = $1", dev)
	kinds, _ = pgx.CollectRows(rows, pgx.RowTo[string])
	if !slices.Equal(kinds, []string{"admin_password"}) {
		t.Fatalf("escrow left %v", kinds)
	}
	if got := w.events(id); !slices.Equal(got, []string{"device.escrow_destroyed:failure", "device.escrow_destroyed:success"}) {
		t.Fatalf("events %v", got)
	}
}

// TestIssuerRefusesForgedApprovals (gate R3): an invalid token, a token of another subject, a token that proved
// another request, the same administrator or subject twice, a missing approval and an operator are refused; the
// request is rejected and audited as denied, nothing is signed.
func TestIssuerRefusesForgedApprovals(t *testing.T) {
	w := newWorld(t, true)
	reused := w.approval("requester", w.alice)
	w.issue(w.request("lock", w.device(), w.alice, reused))
	// Bob's account approving with alice's identity (a forged row of a compromised api or database).
	sameSubject := approval{role: "approver", admin: w.bob, subject: subject(w.alice)}
	sameSubject.raw, sameSubject.jti = w.token(subject(w.alice))
	otherSubject := w.approval("requester", w.alice)
	otherSubject.raw, otherSubject.jti = w.token(subject(w.bob))
	cases := map[string]struct {
		action    string
		approvals []approval
		reason    string
	}{
		"forged token":       {"lock", []approval{{role: "requester", admin: w.alice, subject: subject(w.alice), raw: "forged", jti: "jti-forged"}}, "stepup_invalid"},
		"other subject":      {"lock", []approval{otherSubject}, "stepup_invalid"},
		"reused token":       {"lock", []approval{{role: "requester", admin: w.alice, subject: reused.subject, raw: reused.raw, jti: reused.jti + "-x"}}, "stepup_invalid"},
		"same admin twice":   {"destroy", []approval{w.approval("requester", w.alice), w.approval("approver", w.alice)}, "approvals_invalid"},
		"same subject twice": {"destroy", []approval{w.approval("requester", w.alice), sameSubject}, "not_org_admin"},
		"single approval":    {"destroy", []approval{w.approval("requester", w.alice)}, "approvals_invalid"},
		"operator":           {"lock", []approval{w.approval("requester", w.carol)}, "not_org_admin"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			requester := c.approvals[0].admin
			id := w.request(c.action, w.device(), requester, c.approvals...)
			w.issue(id)
			if s, r := w.status(id); s != "rejected" || r != c.reason {
				t.Fatalf("status %s, rejection %s; want %s", s, r, c.reason)
			}
			if _, signed := w.commands.put[id]; signed {
				t.Fatal("signed")
			}
			if got := w.events(id); !slices.Equal(got, []string{"revocation.issue_refused:denied"}) {
				t.Fatalf("events %v", got)
			}
		})
	}
}

// TestIssuerLimits (ADR 0014, gate R3): the fourth Lock within an hour by the same administrator is rejected, alerts
// and freezes the administrator for 24 h; the organization limit applies analogously.
func TestIssuerLimits(t *testing.T) {
	w := newWorld(t, true)
	for range 3 {
		id := w.lock(w.device(), w.alice)
		w.issue(id)
		if s, _ := w.status(id); s != "issued" {
			t.Fatalf("lock within the limit: %s", s)
		}
	}
	fourth := w.lock(w.device(), w.alice)
	w.issue(fourth)
	if s, r := w.status(fourth); s != "rejected" || r != "limit_admin_hour" {
		t.Fatalf("fourth lock: %s %s", s, r)
	}
	if got := w.events(fourth); !slices.Equal(got, []string{"revocation.limit_exceeded:denied"}) {
		t.Fatalf("events %v", got)
	}
	var until time.Time
	if err := w.super.QueryRow(context.Background(), "SELECT frozen_until FROM revocation_freeze WHERE admin_id = $1", w.alice).Scan(&until); err != nil ||
		time.Until(until) < 23*time.Hour {
		t.Fatalf("freeze until %s, %v", until, err)
	}
	// Frozen: even within the limits nothing is issued for the administrator.
	w.exec("UPDATE revocation_request SET issued_at = issued_at - interval '2 hours' WHERE requested_by = $1", w.alice)
	frozen := w.lock(w.device(), w.alice)
	w.issue(frozen)
	if s, r := w.status(frozen); s != "rejected" || r != "admin_frozen" {
		t.Fatalf("frozen administrator: %s %s", s, r)
	}

	// Organization: 20 Lock and Destroy issued in 24 h (alice's 3 and 17 more; self-locks do not count).
	other := w.admin("org_admin")
	w.exec(`INSERT INTO revocation_request (id, organization_id, device_id, action, status, requested_by, issued_at, expires_at)
		SELECT gen_random_uuid(), $1, $2, 'lock', 'confirmed', $3, now() - interval '2 hours', now() + interval '1 day'
		FROM generate_series(1, 17)`, w.org, w.device(), other)
	id := w.lock(w.device(), w.bob)
	w.issue(id)
	if s, r := w.status(id); s != "rejected" || r != "limit_organization_day" {
		t.Fatalf("21st revocation in the organization: %s %s", s, r)
	}
}

// TestIssuerDisabled (gate R5): with the feature flag off the issuer refuses to sign.
func TestIssuerDisabled(t *testing.T) {
	w := newWorld(t, false)
	id := w.lock(w.device(), w.alice)
	w.issue(id)
	if s, r := w.status(id); s != "rejected" || r != "revocation_disabled" {
		t.Fatalf("status %s %s", s, r)
	}
	if len(w.commands.put) != 0 {
		t.Fatal("signed with the flag off")
	}
}

// TestRoundRepublishes: an issued token missing in cmd:<device_id> is put back; an approved request without message
// is issued.
func TestRoundRepublishes(t *testing.T) {
	w := newWorld(t, true)
	id := w.lock(w.device(), w.alice)
	if err := w.issuer.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s, _ := w.status(id); s != "issued" {
		t.Fatalf("round did not issue: %s", s)
	}
	delete(w.commands.put, id)
	if err := w.issuer.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.commands.put[id]; !ok {
		t.Fatal("round did not republish")
	}
}

// selfLocks returns the open self-lock tokens of a device: request ID → period.
func (w *world) selfLocks(dev uuid.UUID) map[uuid.UUID]int {
	w.t.Helper()
	rows, err := w.super.Query(context.Background(), `SELECT id, period_days FROM revocation_request
		WHERE device_id = $1 AND action = 'self_lock' AND status IN ('issued','delivered')`, dev)
	if err != nil {
		w.t.Fatal(err)
	}
	defer rows.Close()
	out := map[uuid.UUID]int{}
	for rows.Next() {
		var id uuid.UUID
		var period int
		if err := rows.Scan(&id, &period); err != nil {
			w.t.Fatal(err)
		}
		out[id] = period
	}
	return out
}

// TestSelfLocks (plan M4c decision 15): while the switch is on every active device has one self-lock token with the
// period in it, without approvals; a new period replaces it; turning the switch off cancels it and removes it from
// cmd:<device_id>; with revocation disabled nothing is signed.
func TestSelfLocks(t *testing.T) {
	w := newWorld(t, true)
	dev, retired := w.device(), w.device()
	w.exec("UPDATE device SET state = 'retired' WHERE id = $1", retired)
	ctx := context.Background()
	if err := w.issuer.Round(ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(w.selfLocks(dev)); n != 0 {
		t.Fatalf("%d self-locks with the switch off", n)
	}
	w.exec("INSERT INTO organization_dms_settings (organization_id, enabled, period_days) VALUES ($1, true, 14)", w.org)
	if err := w.issuer.Round(ctx); err != nil {
		t.Fatal(err)
	}
	locks := w.selfLocks(dev)
	if len(locks) != 1 || len(w.selfLocks(retired)) != 0 {
		t.Fatalf("self-locks %v, retired %v", locks, w.selfLocks(retired))
	}
	var first uuid.UUID
	for id := range locks {
		first = id
	}
	tok, err := revocation.Verify(w.commands.put[first].Envelope, w.trust, dev.String(), time.Now())
	if err != nil || tok.Action != revocation.ActionSelfLock || tok.PeriodDays != 14 || tok.ExpiresAt.Sub(tok.IssuedAt) != 365*24*time.Hour {
		t.Fatalf("self-lock token %+v %v", tok, err)
	}
	if err := w.issuer.Round(ctx); err != nil || len(w.selfLocks(dev)) != 1 {
		t.Fatalf("second round: %v %v", w.selfLocks(dev), err)
	}

	w.exec("UPDATE organization_dms_settings SET period_days = 21 WHERE organization_id = $1", w.org)
	if err := w.issuer.Round(ctx); err != nil {
		t.Fatal(err)
	}
	locks = w.selfLocks(dev)
	if _, old := locks[first]; old || len(locks) != 1 {
		t.Fatalf("after a new period: %v", locks)
	}
	if _, kept := w.commands.put[first]; kept {
		t.Fatal("the replaced token stays in cmd:<device_id>")
	}
	var second uuid.UUID
	for id := range locks {
		second = id
	}

	w.exec("UPDATE organization_dms_settings SET enabled = false WHERE organization_id = $1", w.org)
	if err := w.issuer.Round(ctx); err != nil {
		t.Fatal(err)
	}
	// The round repairs the cmd:<device_id> of every organization of the shared database; only this device counts.
	if _, kept := w.commands.put[second]; kept || len(w.selfLocks(dev)) != 0 {
		t.Fatalf("switch off: self-locks %v, token kept in cmd: %v", w.selfLocks(dev), kept)
	}

	off := newWorld(t, false)
	d := off.device()
	off.exec("INSERT INTO organization_dms_settings (organization_id, enabled, period_days) VALUES ($1, true, 14)", off.org)
	if err := off.issuer.Round(ctx); err != nil || len(off.selfLocks(d)) != 0 {
		t.Fatalf("revocation disabled: %v %v", off.selfLocks(d), err)
	}
}

// Volumes of the PDK-009 tests, in ascending order.
const (
	volRoot = "0d8f4c62-0000-4000-8000-0000000000aa"
	volData = "0d8f4c62-0000-4000-8000-0000000000bb"
	volHome = "0d8f4c62-0000-4000-8000-0000000000cc"
)

// escrowHeader records a header generation of volume ("" none) with status.
func (w *world) escrowHeader(dev uuid.UUID, volume string, generation int, status string) {
	w.t.Helper()
	var vol *string
	if volume != "" {
		vol = &volume
	}
	w.exec(`INSERT INTO escrow_secret (id, organization_id, device_id, kind, generation, status, key_version, object_key, wrapped_dek,
		nonce, sha256, size, volume) VALUES ($1, $2, $3, 'luks_header', $4, $5, 1, 'k', '\x01', '\x000000000000000000000000', $6, 1, $7)`,
		uuid.New(), w.org, dev, generation, status, strings.Repeat("a", 64), vol)
}

// capable records the check-in health of a device whose paddock-revoke understands the volumes of a token.
func (w *world) capable(dev uuid.UUID) {
	w.exec(`INSERT INTO device_status (device_id, organization_id, last_contact_at, health)
		VALUES ($1, $2, now(), '{"revoke_capabilities":["volumes"]}')`, dev, w.org)
}

// TestLockCarriesConfirmedVolumes (PDK-009 decision 6): a Lock lists the volumes with a stored header — not a pending
// or failed one, and not a header without a volume (the root volume's before PDK-009) —, sorted; a device whose
// paddock-revoke does not understand volumes gets a token without them.
func TestLockCarriesConfirmedVolumes(t *testing.T) {
	w := newWorld(t, true)
	dev, old := w.device(), w.device()
	w.capable(dev)
	for _, d := range []uuid.UUID{dev, old} {
		w.escrowHeader(d, "", 1, "stored")
		w.escrowHeader(d, volRoot, 2, "stored")
		w.escrowHeader(d, volHome, 3, "stored")
		w.escrowHeader(d, volData, 4, "stored")
		w.escrowHeader(d, volData, 5, "stored")
		w.escrowHeader(d, "0d8f4c62-0000-4000-8000-0000000000dd", 6, "pending")
		w.escrowHeader(d, "0d8f4c62-0000-4000-8000-0000000000ee", 7, "failed")
	}
	id := w.lock(dev, w.alice)
	w.issue(id)
	tok, err := revocation.Verify(w.commands.put[id].Envelope, w.trust, dev.String(), time.Now())
	if err != nil || !slices.Equal(tok.Volumes, []string{volRoot, volData, volHome}) {
		t.Fatalf("token %+v %v", tok, err)
	}
	var stored []uuid.UUID
	var n string
	if err := w.super.QueryRow(context.Background(), `SELECT r.volumes, a.params ->> 'volumes' FROM revocation_request r
		JOIN action a ON a.params ->> 'request_id' = r.id::text WHERE r.id = $1`, id).Scan(&stored, &n); err != nil || len(stored) != 3 || n != "3" {
		t.Fatalf("recorded volumes %v, audit %q: %v", stored, n, err)
	}
	plain := w.lock(old, w.bob)
	w.issue(plain)
	if tok, err := revocation.Verify(w.commands.put[plain].Envelope, w.trust, old.String(), time.Now()); err != nil || tok.Volumes != nil {
		t.Fatalf("token for a paddock-revoke before PDK-009 %+v %v", tok, err)
	}
}

// TestDestroyDeletesEveryVolume (PDK-009 decision 5): a Destroy deletes the headers of every volume and carries no
// volumes; paddock-revoke erases every volume.
func TestDestroyDeletesEveryVolume(t *testing.T) {
	w := newWorld(t, true)
	dev := w.device()
	w.capable(dev)
	w.escrowHeader(dev, "", 1, "stored")
	w.escrowHeader(dev, volRoot, 2, "stored")
	w.escrowHeader(dev, volData, 3, "stored")
	id := w.request("destroy", dev, w.alice, w.approval("requester", w.alice), w.approval("approver", w.bob))
	w.issue(id)
	var left int
	if err := w.super.QueryRow(context.Background(), "SELECT count(*) FROM escrow_secret WHERE device_id = $1", dev).Scan(&left); err != nil || left != 0 {
		t.Fatalf("%d headers left: %v", left, err)
	}
	if !slices.Equal(w.shredder.prefixes, []string{"org/" + w.org.String() + "/devices/" + dev.String() + "/luks-header/"}) {
		t.Fatalf("deleted prefixes %v", w.shredder.prefixes)
	}
	if tok, err := revocation.Verify(w.commands.put[id].Envelope, w.trust, dev.String(), time.Now()); err != nil || tok.Volumes != nil {
		t.Fatalf("destroy token %+v %v", tok, err)
	}
}

// TestSelfLockFollowsVolumes (PDK-009 decision 6): a self-lock token carries the confirmed volumes and is re-issued
// when that set changes; the replaced token leaves cmd:<device_id>.
func TestSelfLockFollowsVolumes(t *testing.T) {
	w := newWorld(t, true)
	dev := w.device()
	w.capable(dev)
	w.escrowHeader(dev, volRoot, 1, "stored")
	w.exec("INSERT INTO organization_dms_settings (organization_id, enabled, period_days) VALUES ($1, true, 14)", w.org)
	ctx := context.Background()
	token := func() (uuid.UUID, *revocation.Token) {
		t.Helper()
		if err := w.issuer.Round(ctx); err != nil {
			t.Fatal(err)
		}
		locks := w.selfLocks(dev)
		if len(locks) != 1 {
			t.Fatalf("self-locks %v", locks)
		}
		for id := range locks {
			tok, err := revocation.Verify(w.commands.put[id].Envelope, w.trust, dev.String(), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			return id, tok
		}
		return uuid.UUID{}, nil
	}
	first, tok := token()
	if !slices.Equal(tok.Volumes, []string{volRoot}) {
		t.Fatalf("first token %+v", tok)
	}
	if again, _ := token(); again != first {
		t.Fatal("an unchanged set replaced the token")
	}
	w.escrowHeader(dev, volData, 2, "pending")
	if again, _ := token(); again != first {
		t.Fatal("a pending header replaced the token")
	}
	w.exec("UPDATE escrow_secret SET status = 'stored' WHERE device_id = $1 AND generation = 2", dev)
	second, tok := token()
	if second == first || !slices.Equal(tok.Volumes, []string{volRoot, volData}) {
		t.Fatalf("after a new volume: %s %+v", second, tok)
	}
	if _, kept := w.commands.put[first]; kept {
		t.Fatal("the replaced token stays in cmd:<device_id>")
	}
}

// TestLockVolumesCapped (PDK-009 review round 1, decision 1): with more than 32 volumes — rows the worker would refuse,
// written here directly — a Lock carries the first 32 by UUID and is issued, and the self-lock token carries the same
// 32 and is not replaced round after round.
func TestLockVolumesCapped(t *testing.T) {
	w := newWorld(t, true)
	dev := w.device()
	w.capable(dev)
	var want []string
	for i := 0; i < 33; i++ {
		v := fmt.Sprintf("0d8f4c62-0000-4000-8000-%012d", i)
		w.escrowHeader(dev, v, i+1, "stored")
		if i < revocation.MaxVolumes {
			want = append(want, v)
		}
	}
	id := w.lock(dev, w.alice)
	w.issue(id)
	if s, _ := w.status(id); s != "issued" {
		t.Fatalf("status %s", s)
	}
	tok, err := revocation.Verify(w.commands.put[id].Envelope, w.trust, dev.String(), time.Now())
	if err != nil || !slices.Equal(tok.Volumes, want) {
		t.Fatalf("lock token: %d volumes, %v", len(tok.Volumes), err)
	}
	w.exec("INSERT INTO organization_dms_settings (organization_id, enabled, period_days) VALUES ($1, true, 14)", w.org)
	ctx := context.Background()
	var first uuid.UUID
	for round := 0; round < 3; round++ {
		if err := w.issuer.Round(ctx); err != nil {
			t.Fatal(err)
		}
		locks := w.selfLocks(dev)
		if len(locks) != 1 {
			t.Fatalf("round %d: self-locks %v", round, locks)
		}
		for id := range locks {
			if round > 0 && id != first {
				t.Fatalf("round %d replaced the self-lock token", round)
			}
			first = id
		}
	}
	tok, err = revocation.Verify(w.commands.put[first].Envelope, w.trust, dev.String(), time.Now())
	if err != nil || !slices.Equal(tok.Volumes, want) {
		t.Fatalf("self-lock token: %d volumes, %v", len(tok.Volumes), err)
	}
}

// TestLockVolumesNewestStored (PDK-009 review round 1, decision 3): a volume whose newest header generation is
// pending is left out until it is stored; a failed newest generation does not count.
func TestLockVolumesNewestStored(t *testing.T) {
	w := newWorld(t, true)
	dev := w.device()
	w.capable(dev)
	w.escrowHeader(dev, volData, 1, "stored")
	w.escrowHeader(dev, volData, 2, "pending")
	w.escrowHeader(dev, volHome, 3, "stored")
	w.escrowHeader(dev, volHome, 4, "failed")
	id := w.lock(dev, w.alice)
	w.issue(id)
	tok, err := revocation.Verify(w.commands.put[id].Envelope, w.trust, dev.String(), time.Now())
	if err != nil || !slices.Equal(tok.Volumes, []string{volHome}) {
		t.Fatalf("token %+v %v", tok, err)
	}
}
