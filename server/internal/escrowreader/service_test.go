package escrowreader_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/escrowreader"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/stepupproof"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

const secret = "shared-secret"

// proofs accepts the raw tokens it knows (subject per token) and counts their uses.
type proofs struct {
	subjects map[string]string
	uses     map[string]int64
}

func (p *proofs) Verify(_ context.Context, raw string) (stepupproof.Claims, error) {
	sub, ok := p.subjects[raw]
	if !ok {
		return stepupproof.Claims{}, stepupproof.ErrInvalid
	}
	return stepupproof.Claims{Subject: sub, JTI: "jti-" + raw, AuthTime: time.Now(), Expiry: time.Now().Add(time.Minute)}, nil
}

func (p *proofs) Use(_ context.Context, jti string, _ time.Time) (int64, error) {
	p.uses[jti]++
	return p.uses[jti], nil
}

// plainKeys "decrypts" into "plain-" plus the ciphertext.
type plainKeys struct{}

func (plainKeys) Decrypt(_ context.Context, _ int, ciphertext string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	return append([]byte("plain-"), raw...), err
}

type world struct {
	t       *testing.T
	super   *pgx.Conn
	proofs  *proofs
	srv     *httptest.Server
	client  *escrowreader.Client
	orgs    [2]uuid.UUID
	devices [2]uuid.UUID
	// escrows per organization: an admin password, a recovery key and a header of its device.
	passwords, recovery, headers [2]uuid.UUID
}

func newWorld(t *testing.T) *world {
	t.Helper()
	ctx := context.Background()
	pg := pgtest.SharedPaddock(t)
	super, err := pgx.Connect(ctx, pg.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	pool, err := db.NewOrgPool(ctx, pg.EscrowReader, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	w := &world{t: t, super: super, proofs: &proofs{subjects: map[string]string{}, uses: map[string]int64{}}}
	w.srv = httptest.NewServer(escrowreader.NewService(secret, pool, w.proofs, w.proofs, plainKeys{}).Handler())
	t.Cleanup(w.srv.Close)
	w.client = escrowreader.NewClient(w.srv.URL, secret)
	for i := range 2 {
		w.orgs[i] = uuid.New()
		w.devices[i] = uuid.New()
		w.exec(`INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'org', 'active')`, w.orgs[i], "er-"+w.orgs[i].String()[:8])
		w.exec(`INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'host', 'active')`, w.devices[i], w.orgs[i])
		w.passwords[i] = w.escrow(i, "admin_password", "ct", nil)
		w.recovery[i] = w.escrow(i, "luks_recovery_key", "ct", nil)
		w.headers[i] = w.escrow(i, "luks_header", "", []byte("dek"))
		for _, role := range []string{"org_admin", "org_operator"} {
			sub := role + "-" + w.orgs[i].String()
			w.exec(`INSERT INTO admin_account (id, organization_id, authentik_sub, username, display_name, role)
				VALUES ($1, $2, $3, $3, $3, $4)`, uuid.New(), w.orgs[i], sub, role)
			w.proofs.subjects["token-"+sub] = sub
		}
	}
	return w
}

func (w *world) exec(sql string, args ...any) {
	w.t.Helper()
	if _, err := w.super.Exec(context.Background(), sql, args...); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) escrow(i int, kind, ciphertext string, dek []byte) uuid.UUID {
	w.t.Helper()
	id := uuid.New()
	var ct []byte
	if ciphertext != "" {
		ct = []byte(ciphertext + "-" + kind)
	}
	var objectKey, sha *string
	var nonce []byte
	if kind == "luks_header" {
		k, s := "org/x/"+id.String(), strings.Repeat("a", 64)
		objectKey, sha, nonce = &k, &s, make([]byte, 12)
	}
	w.exec(`INSERT INTO escrow_secret (id, organization_id, device_id, kind, generation, status, ciphertext, key_version,
		wrapped_dek, nonce, object_key, sha256, size) VALUES ($1, $2, $3, $4, 1, 'stored', $5, 1, $6, $7, $8, $9, CASE WHEN $8::text IS NULL THEN NULL ELSE 1 END)`,
		id, w.orgs[i], w.devices[i], kind, ct, dek, nonce, objectKey, sha)
	return id
}

func (w *world) token(i int, role string) string { return "token-" + role + "-" + w.orgs[i].String() }

func (w *world) decrypt(req app.EscrowDecryptRequest) (map[uuid.UUID][]byte, error) {
	return w.client.Decrypt(context.Background(), req)
}

// TestDecrypt: the escrow-reader decrypts exactly the escrows of the device and the purpose, for a valid step-up
// token of an administrator of the organization, at most MaxUses times per token; it refuses everything else.
func TestDecrypt(t *testing.T) {
	w := newWorld(t)
	admin := w.token(0, "org_admin")
	ok := app.EscrowDecryptRequest{OrganizationID: w.orgs[0], DeviceID: w.devices[0], EscrowIDs: []uuid.UUID{w.passwords[0]},
		StepUpIDToken: admin, Purpose: app.PurposeLocalAdminReveal}
	plain, err := w.decrypt(ok)
	if err != nil || string(plain[w.passwords[0]]) != "plain-ct-admin_password" {
		t.Fatalf("password: %q, %v", plain, err)
	}
	header := ok
	header.EscrowIDs, header.Purpose = []uuid.UUID{w.headers[0]}, app.PurposeDiskHeader
	if plain, err := w.decrypt(header); err != nil || string(plain[w.headers[0]]) != "plain-dek" {
		t.Fatalf("header key: %q, %v", plain, err)
	}

	refused := map[string]func(r *app.EscrowDecryptRequest){
		"forged or stale token":           func(r *app.EscrowDecryptRequest) { r.StepUpIDToken = "forged" },
		"operator":                        func(r *app.EscrowDecryptRequest) { r.StepUpIDToken = w.token(0, "org_operator") },
		"administrator of another org":    func(r *app.EscrowDecryptRequest) { r.StepUpIDToken = w.token(1, "org_admin") },
		"foreign organization in request": func(r *app.EscrowDecryptRequest) { r.OrganizationID = w.orgs[1] },
		"foreign org with its own admin": func(r *app.EscrowDecryptRequest) {
			r.OrganizationID, r.StepUpIDToken = w.orgs[1], w.token(1, "org_admin")
		},
		"escrow of another device":          func(r *app.EscrowDecryptRequest) { r.EscrowIDs = []uuid.UUID{w.passwords[1]} },
		"escrow of another kind":            func(r *app.EscrowDecryptRequest) { r.EscrowIDs = []uuid.UUID{w.recovery[0]} },
		"unknown escrow":                    func(r *app.EscrowDecryptRequest) { r.EscrowIDs = []uuid.UUID{uuid.New()} },
		"device of another org":             func(r *app.EscrowDecryptRequest) { r.DeviceID = w.devices[1] },
		"mixed escrows of the right device": func(r *app.EscrowDecryptRequest) { r.EscrowIDs = []uuid.UUID{w.passwords[0], w.recovery[0]} },
	}
	for name, change := range refused {
		req := ok
		change(&req)
		if plain, err := w.decrypt(req); !errors.Is(err, app.ErrEscrowRefused) || plain != nil {
			t.Errorf("%s: %v, %d plaintexts", name, err, len(plain))
		}
	}

	// Two uses so far; the token allows MaxUses.
	for range stepupproof.MaxUses - 2 {
		if _, err := w.decrypt(ok); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.decrypt(ok); !errors.Is(err, app.ErrEscrowRefused) || !strings.Contains(err.Error(), "stepup_exhausted") {
		t.Fatalf("use beyond MaxUses: %v", err)
	}
}

// TestDecryptAuthentication: requests need the bearer secret, and the client accepts answers only with the
// escrow-reader's MAC under the same secret.
func TestDecryptAuthentication(t *testing.T) {
	w := newWorld(t)
	req := app.EscrowDecryptRequest{OrganizationID: w.orgs[0], DeviceID: w.devices[0], EscrowIDs: []uuid.UUID{w.passwords[0]},
		StepUpIDToken: w.token(0, "org_admin"), Purpose: app.PurposeLocalAdminReveal}
	for _, s := range []string{"wrong-secret", ""} {
		if _, err := escrowreader.NewClient(w.srv.URL, s).Decrypt(context.Background(), req); err == nil ||
			errors.Is(err, app.ErrEscrowRefused) || !strings.Contains(err.Error(), "401") {
			t.Errorf("secret %q: %v", s, err)
		}
	}
	// An impostor without the secret answers like the escrow-reader.
	impostor := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write([]byte(`{"plaintexts":{"` + w.passwords[0].String() + `":"c3B5"}}`))
	}))
	t.Cleanup(impostor.Close)
	if _, err := escrowreader.NewClient(impostor.URL, secret).Decrypt(context.Background(), req); err == nil {
		t.Fatal("the client accepted an answer without MAC")
	}
	if _, err := w.client.Decrypt(context.Background(), app.EscrowDecryptRequest{OrganizationID: w.orgs[0]}); err == nil ||
		!strings.Contains(err.Error(), "400") {
		t.Fatalf("malformed request: %v", err)
	}
}
