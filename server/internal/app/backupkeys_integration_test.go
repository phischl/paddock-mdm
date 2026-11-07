package app_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/auditwriter"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// wrapRecorder stands in for Transit backup-wrap: it records the key names and plaintexts it was asked to encrypt and
// returns a ciphertext that never holds the plaintext.
// While fail is set it refuses like a sealed OpenBao and records nothing.
type wrapRecorder struct {
	mu     sync.Mutex
	fail   error
	keys   []string
	plains [][]byte
}

func (w *wrapRecorder) EncryptPlatform(_ context.Context, key string, plaintext []byte) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fail != nil {
		return "", w.fail
	}
	w.keys = append(w.keys, key)
	w.plains = append(w.plains, slices.Clone(plaintext))
	return fmt.Sprintf("vault:v1:wrapped-%d", len(w.keys)), nil
}

type backupKeyHarness struct {
	t     *testing.T
	uc    *app.BackupKeys
	wrap  *wrapRecorder
	super *pgx.Conn
	root  principal.Principal
}

func newBackupKeyHarness(t *testing.T) *backupKeyHarness {
	t.Helper()
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	orgPool, err := db.NewOrgPool(ctx, env.API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(orgPool.Close)
	platform, err := db.NewPlatformPool(ctx, env.Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	// backup_key is platform-wide: every test starts from and leaves an empty table.
	reset := func() {
		if _, err := super.Exec(context.Background(), "DELETE FROM backup_key"); err != nil {
			t.Fatal(err)
		}
	}
	reset()
	t.Cleanup(reset)
	wrap := &wrapRecorder{}
	runner := app.NewActionRunner(orgPool, platform, httpx.RequestID)
	return &backupKeyHarness{t: t, uc: app.NewBackupKeys(runner, platform, wrap), wrap: wrap, super: super,
		root: principal.Principal{Kind: principal.KindPlatformAdmin, ID: uuid.Must(uuid.NewV7()), Subject: "sub-root",
			Display: "Root Admin", Role: principal.RolePlatform, StepUpAt: time.Now()}}
}

func (h *backupKeyHarness) ctx(p principal.Principal) (context.Context, string) {
	id := uuid.NewString()
	return principal.With(httpx.WithRequestID(context.Background(), id), p), id
}

// event returns "code:outcome:error_code" and the params of the single action of requestID.
func (h *backupKeyHarness) event(requestID string) (string, map[string]any) {
	h.t.Helper()
	var ev string
	var params map[string]any
	if err := h.super.QueryRow(context.Background(), `SELECT code || ':' || coalesce(outcome, status) || ':' ||
		coalesce(error_code, ''), params FROM action WHERE correlation_id = $1`, requestID).Scan(&ev, &params); err != nil {
		h.t.Fatalf("event of %s: %v", requestID, err)
	}
	return ev, params
}

// expect runs fn with a fresh request and checks its single event and the error code it returned.
func (h *backupKeyHarness) expect(p principal.Principal, wantEvent string, fn func(ctx context.Context) error) map[string]any {
	h.t.Helper()
	ctx, id := h.ctx(p)
	err := fn(ctx)
	got, params := h.event(id)
	if got != wantEvent {
		h.t.Fatalf("event %s (err %v), want %s", got, err, wantEvent)
	}
	parts := strings.Split(wantEvent, ":")
	if code := parts[2]; (code == "") != (err == nil) || (err != nil && problem.From(err).Code != code) {
		h.t.Fatalf("error %v, want code %q", err, code)
	}
	return params
}

// answer returns the characters of text at the 1-based positions.
func answer(text string, positions []int) string {
	var b strings.Builder
	for _, p := range positions {
		b.WriteByte(text[p-1])
	}
	return b.String()
}

// wrong returns an answer of the same length that differs from right.
func wrong(right string) string {
	if right == "AAAAAA" {
		return "BBBBBB"
	}
	return "AAAAAA"
}

func (h *backupKeyHarness) row(keyID string) (state string, attempts int, ciphertext string) {
	h.t.Helper()
	if err := h.super.QueryRow(context.Background(), "SELECT state, attempts, ciphertext FROM backup_key WHERE key_id = $1",
		keyID).Scan(&state, &attempts, &ciphertext); err != nil {
		h.t.Fatal(err)
	}
	return state, attempts, ciphertext
}

// noKeyMaterial fails when the params hold the key text or the typed characters.
func (h *backupKeyHarness) noKeyMaterial(params map[string]any, secrets ...string) {
	h.t.Helper()
	b, _ := json.Marshal(params)
	for _, s := range secrets {
		if strings.Contains(string(b), s) {
			h.t.Fatalf("audit params %s hold key material", b)
		}
	}
	for _, k := range []string{"key", "answer", "positions", "text"} {
		if _, ok := params[k]; ok {
			h.t.Fatalf("audit params %s hold %s", b, k)
		}
	}
}

// TestBackupKeyLifecycle covers plan M15 decision 7: generate once (text only in the response, Transit-wrapped at
// rest), a second key only after the pending one is resolved, three wrong confirmations discard, the right one
// activates and a rotation retires the previous key in the same transaction.
func TestBackupKeyLifecycle(t *testing.T) {
	h := newBackupKeyHarness(t)

	var first app.GeneratedKey
	params := h.expect(h.root, "platform.backup_key_generated:success:", func(ctx context.Context) error {
		var err error
		first, err = h.uc.Generate(ctx)
		return err
	})
	raw, err := base64.StdEncoding.DecodeString(first.Text)
	if err != nil || len(first.Text) != 44 || len(raw) != 32 {
		t.Fatalf("key text %d characters, %d bytes, %v", len(first.Text), len(raw), err)
	}
	if !backupset.ValidKeyID(first.KeyID) || first.KeyID == backupset.LegacyKeyID || first.Fingerprint != backupset.Fingerprint(raw) ||
		first.DownloadName != "paddock-backup-key-"+first.KeyID+".txt" {
		t.Fatalf("generated %+v", first)
	}
	positions := first.Positions[:]
	if !slices.IsSorted(positions) || len(slices.Compact(slices.Clone(positions))) != 6 || positions[0] < 1 || positions[5] > 44 {
		t.Fatalf("positions %v", positions)
	}
	if params["rotation"] != false || params["legacy"] != false || params["key_id"] != first.KeyID || params["fingerprint"] != first.Fingerprint {
		t.Fatalf("params %v", params)
	}
	right := answer(first.Text, positions)
	h.noKeyMaterial(params, first.Text, right)
	state, attempts, ct := h.row(first.KeyID)
	if state != "unconfirmed" || attempts != 0 || strings.Contains(ct, first.Text) || h.wrap.keys[0] != app.BackupWrapKey ||
		string(h.wrap.plains[0]) != string(raw) {
		t.Fatalf("stored %s %d %q; wrapped %v", state, attempts, ct, h.wrap.keys)
	}
	var hash []byte
	if err := h.super.QueryRow(context.Background(), "SELECT challenge_sha256 FROM backup_key WHERE key_id = $1", first.KeyID).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if want := backupset.ChallengeHash(first.KeyID, right); string(hash) != string(want[:]) {
		t.Fatal("the stored challenge hash is not the hash of the characters at the positions")
	}

	h.expect(h.root, "platform.backup_key_generated:failure:invalid_state", func(ctx context.Context) error {
		_, err := h.uc.Generate(ctx)
		if err == nil || !strings.Contains(problem.From(err).Detail, first.KeyID) {
			t.Fatalf("second key while one is pending: %v", err)
		}
		return err
	})

	h.expect(h.root, "platform.backup_key_confirmed:failure:invalid_request", func(ctx context.Context) error {
		_, err := h.uc.Confirm(ctx, first.KeyID, right[:5])
		return err
	})
	for i, left := range []int{2, 1} {
		params := h.expect(h.root, "platform.backup_key_confirmed:failure:backup_key_mismatch", func(ctx context.Context) error {
			_, err := h.uc.Confirm(ctx, first.KeyID, wrong(right))
			if err == nil || !strings.Contains(problem.From(err).Detail, fmt.Sprintf("attempts_left=%d", left)) {
				t.Fatalf("mismatch %d: %v", i+1, err)
			}
			return err
		})
		if params["attempts"] != float64(i+1) || params["key_id"] != first.KeyID {
			t.Fatalf("mismatch %d params %v", i+1, params)
		}
		h.noKeyMaterial(params, first.Text, right, wrong(right))
	}
	if state, attempts, _ := h.row(first.KeyID); state != "unconfirmed" || attempts != 2 {
		t.Fatalf("after two mismatches: %s %d", state, attempts)
	}
	h.expect(h.root, "platform.backup_key_confirmed:failure:backup_key_mismatch", func(ctx context.Context) error {
		k, err := h.uc.Confirm(ctx, first.KeyID, wrong(right))
		if err == nil || !strings.Contains(problem.From(err).Detail, "discarded after three failed confirmations") ||
			k.State != "discarded" || k.Attempts != 3 {
			t.Fatalf("third mismatch: %+v %v", k, err)
		}
		return err
	})
	h.expect(h.root, "platform.backup_key_confirmed:failure:invalid_state", func(ctx context.Context) error {
		_, err := h.uc.Confirm(ctx, first.KeyID, right)
		return err
	})

	second := h.generate()
	k := h.confirm(second, "")
	if k.State != "confirmed" || k.ConfirmedBy == nil || *k.ConfirmedBy != "Root Admin" || k.ConfirmedAt == nil {
		t.Fatalf("confirmed %+v", k)
	}

	third := h.generate()
	ctx, _ := h.ctx(h.root)
	st, err := h.uc.Status(ctx)
	if err != nil || st.Active == nil || st.Active.KeyID != second.KeyID || st.Pending == nil || st.Pending.KeyID != third.KeyID {
		t.Fatalf("status during the rotation: %+v %v", st, err)
	}
	if !slices.Equal(st.Pending.Positions, third.Positions[:]) || st.Active.Positions != nil {
		t.Fatalf("positions during the rotation: pending %v (generated %v), active %v", st.Pending.Positions, third.Positions,
			st.Active.Positions)
	}
	h.confirm(third, second.KeyID)
	if state, _, _ := h.row(second.KeyID); state != "retired" {
		t.Fatalf("the previous key is %s", state)
	}
	st, err = h.uc.Status(ctx)
	if err != nil || st.Active == nil || st.Active.KeyID != third.KeyID || st.Pending != nil || len(st.Retired) != 1 ||
		st.Retired[0].KeyID != second.KeyID || st.Retired[0].RetiredAt == nil {
		t.Fatalf("status after the rotation: %+v %v", st, err)
	}
	if st.Active.Positions != nil || st.Retired[0].Positions != nil {
		t.Fatalf("positions after the confirmation: active %v, retired %v", st.Active.Positions, st.Retired[0].Positions)
	}

	fourth := h.generate()
	h.expect(h.root, "platform.backup_key_discarded:success:", func(ctx context.Context) error {
		k, err := h.uc.Discard(ctx, fourth.KeyID)
		if err == nil && k.State != "discarded" {
			t.Fatalf("discarded %+v", k)
		}
		return err
	})
	h.expect(h.root, "platform.backup_key_discarded:failure:invalid_state", func(ctx context.Context) error {
		_, err := h.uc.Discard(ctx, fourth.KeyID)
		return err
	})
	if st, err := h.uc.Status(ctx); err != nil || st.Pending != nil || st.Active == nil || st.Active.Positions != nil {
		t.Fatalf("status after the discard: %+v %v", st, err)
	}
	h.expect(h.root, "platform.backup_key_discarded:failure:invalid_state", func(ctx context.Context) error {
		_, err := h.uc.Discard(ctx, third.KeyID)
		return err
	})
	h.expect(h.root, "platform.backup_key_discarded:failure:not_found", func(ctx context.Context) error {
		_, err := h.uc.Discard(ctx, "bk-20260101-00000000")
		return err
	})
	h.expect(h.root, "platform.backup_key_confirmed:failure:not_found", func(ctx context.Context) error {
		_, err := h.uc.Confirm(ctx, "not a key", "abcdef")
		return err
	})
}

func (h *backupKeyHarness) generate() app.GeneratedKey {
	h.t.Helper()
	ctx, _ := h.ctx(h.root)
	k, err := h.uc.Generate(ctx)
	if err != nil {
		h.t.Fatal(err)
	}
	return k
}

func (h *backupKeyHarness) confirm(g app.GeneratedKey, rotatedFrom string) app.Key {
	h.t.Helper()
	var k app.Key
	params := h.expect(h.root, "platform.backup_key_confirmed:success:", func(ctx context.Context) error {
		var err error
		k, err = h.uc.Confirm(ctx, g.KeyID, answer(g.Text, g.Positions[:]))
		return err
	})
	var want any
	if rotatedFrom != "" {
		want = rotatedFrom
	}
	if params["rotated_from"] != want || params["fingerprint"] != g.Fingerprint || params["attempts"] != float64(0) {
		h.t.Fatalf("confirmed params %v", params)
	}
	h.noKeyMaterial(params, g.Text, answer(g.Text, g.Positions[:]))
	return k
}

// TestBackupKeyAuthorization: every write needs a platform administrator with a fresh step-up; API tokens never have
// one; organization administrators are forbidden; each refusal is recorded as denied and changes nothing.
func TestBackupKeyAuthorization(t *testing.T) {
	h := newBackupKeyHarness(t)
	pending := h.generate()

	stale := h.root
	stale.StepUpAt = time.Time{}
	token := h.root
	token.APITokenID = uuid.Must(uuid.NewV7())
	org := principal.Principal{Kind: principal.KindAdmin, ID: uuid.Must(uuid.NewV7()), OrganizationID: uuid.Must(uuid.NewV7()),
		Display: "Alice", Role: principal.RoleOrgAdmin, StepUpAt: time.Now()}
	right := answer(pending.Text, pending.Positions[:])
	for _, c := range []struct {
		name string
		p    principal.Principal
		code string
	}{
		{"without step-up", stale, "step_up_required"},
		{"API token", token, "step_up_required"},
		{"organization administrator", org, "forbidden"},
	} {
		t.Run(c.name, func(t *testing.T) {
			h.expect(c.p, "platform.backup_key_generated:denied:"+c.code, func(ctx context.Context) error {
				_, err := h.uc.Generate(ctx)
				return err
			})
			for _, a := range []string{right, wrong(right)} {
				h.expect(c.p, "platform.backup_key_confirmed:denied:"+c.code, func(ctx context.Context) error {
					_, err := h.uc.Confirm(ctx, pending.KeyID, a)
					return err
				})
			}
			h.expect(c.p, "platform.backup_key_discarded:denied:"+c.code, func(ctx context.Context) error {
				_, err := h.uc.Discard(ctx, pending.KeyID)
				return err
			})
		})
	}
	if state, attempts, _ := h.row(pending.KeyID); state != "unconfirmed" || attempts != 0 {
		t.Fatalf("a refused request changed the key: %s %d", state, attempts)
	}
	ctx, _ := h.ctx(org)
	if _, err := h.uc.Status(ctx); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("status by an organization administrator: %v", err)
	}
}

// TestBackupKeyLegacyImport covers plan M15 decision 9: the host file's key is imported once as legacy, unconfirmed,
// by the system actor paddock-api; later starts import and record nothing and report whether a key is confirmed.
func TestBackupKeyLegacyImport(t *testing.T) {
	h := newBackupKeyHarness(t)
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	text := base64.StdEncoding.EncodeToString(raw)
	ctx := context.Background()

	if _, err := h.uc.ImportLegacy(ctx, "not a key"); err == nil {
		t.Fatal("an invalid key file was imported")
	}
	res, err := h.uc.ImportLegacy(ctx, text+"\n")
	if err != nil || res != app.LegacyImported {
		t.Fatalf("first import: %v %v", res, err)
	}
	var state, fingerprint, actor string
	var legacy bool
	var positions []int32
	var params map[string]any
	if err := h.super.QueryRow(ctx, `SELECT k.state, k.fingerprint, k.legacy, k.challenge_positions, a.actor->>'display', a.params
		FROM backup_key k, action a WHERE k.key_id = 'legacy' AND a.code = 'platform.backup_key_generated'
		AND a.params->>'key_id' = 'legacy'`).
		Scan(&state, &fingerprint, &legacy, &positions, &actor, &params); err != nil {
		t.Fatal(err)
	}
	if state != "unconfirmed" || !legacy || fingerprint != backupset.Fingerprint(raw) || actor != "paddock-api" ||
		params["legacy"] != true || params["key_id"] != "legacy" || string(h.wrap.plains[0]) != string(raw) {
		t.Fatalf("imported %s %s %v by %s, params %v", state, fingerprint, legacy, actor, params)
	}
	h.noKeyMaterial(params, text)
	// The import runs at api start without a request: its event still carries a source, a system actor and a
	// correlation ID, or the audit writer dead-letters it (decisions-alpha9 item 69).
	var payload []byte
	if err := h.super.QueryRow(ctx, `SELECT payload FROM outbox WHERE payload ->> 'code' = 'platform.backup_key_generated'
		AND payload -> 'params' ->> 'key_id' = 'legacy'`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var ev audit.Event
	if err := json.Unmarshal(payload, &ev); err != nil {
		t.Fatal(err)
	}
	if err := auditwriter.Validate(ev); err != nil || ev.Source != audit.SourceSystem || ev.Actor.Type != audit.ActorSystem {
		t.Fatalf("legacy import event %+v: %v", ev, err)
	}

	if res, err := h.uc.ImportLegacy(ctx, text); err != nil || res != app.LegacyKeyPresent {
		t.Fatalf("second import: %v %v", res, err)
	}
	var events int
	if err := h.super.QueryRow(ctx, "SELECT count(*) FROM action WHERE code = 'platform.backup_key_generated' AND params->>'key_id' = 'legacy'").
		Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 || len(h.wrap.keys) != 1 {
		t.Fatalf("a second start recorded %d events and %d encryptions", events, len(h.wrap.keys))
	}

	// The administrator of key legacy holds the host file but never saw a generating response: the positions must
	// come from the status read (amendment 2026-11-04 of plan M15).
	sctx, _ := h.ctx(h.root)
	st, err := h.uc.Status(sctx)
	if err != nil || st.Pending == nil || st.Pending.KeyID != backupset.LegacyKeyID || !st.Pending.Legacy {
		t.Fatalf("status of the imported key: %+v %v", st, err)
	}
	stored := make([]int, len(positions))
	for i, p := range positions {
		stored[i] = int(p)
	}
	if !slices.Equal(st.Pending.Positions, stored) {
		t.Fatalf("status positions %v, stored %v", st.Pending.Positions, stored)
	}
	h.expect(h.root, "platform.backup_key_confirmed:success:", func(ctx context.Context) error {
		_, err := h.uc.Confirm(ctx, backupset.LegacyKeyID, answer(text, st.Pending.Positions))
		return err
	})
	if st, err := h.uc.Status(sctx); err != nil || st.Active == nil || st.Active.KeyID != backupset.LegacyKeyID ||
		st.Active.Positions != nil {
		t.Fatalf("status after confirming key legacy: %+v %v", st, err)
	}
	if res, err := h.uc.ImportLegacy(ctx, text); err != nil || res != app.LegacyKeyConfirmed {
		t.Fatalf("import after the confirmation: %v %v", res, err)
	}
}

// legacyEvents counts the recorded imports of the legacy key.
func (h *backupKeyHarness) legacyEvents() int {
	h.t.Helper()
	var n int
	if err := h.super.QueryRow(context.Background(), "SELECT count(*) FROM action WHERE code = 'platform.backup_key_generated' AND params->>'key_id' = 'legacy'").
		Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

func legacyKeyText(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestBackupKeyChallengeSkipsPadding(t *testing.T) {
	h := newBackupKeyHarness(t)
	// One generation draws a padding position with a chance of 6/44; 40 miss a regression with a chance below 0.3 %.
	for range 40 {
		g := h.generate()
		for _, p := range g.Positions {
			if g.Text[p-1] == '=' {
				t.Fatalf("position %d of %v points at the padding of %d characters", p, g.Positions, len(g.Text))
			}
		}
		ctx, _ := h.ctx(h.root)
		if _, err := h.uc.Discard(ctx, g.KeyID); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBackupKeyLegacyImportWhileSealed(t *testing.T) {
	h := newBackupKeyHarness(t)
	text := legacyKeyText(t)
	before := h.legacyEvents()
	h.wrap.fail = errors.New("Vault is sealed")
	for range 3 {
		if _, err := h.uc.ImportLegacy(context.Background(), text); err == nil {
			t.Fatal("the import succeeded without encryption")
		}
	}
	if n := h.legacyEvents() - before; n != 0 {
		t.Fatalf("the sealed retries recorded %d events", n)
	}
	var rows int
	if err := h.super.QueryRow(context.Background(), "SELECT count(*) FROM backup_key").Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("the sealed retries stored %d keys (%v)", rows, err)
	}
	h.wrap.fail = nil
	if res, err := h.uc.ImportLegacy(context.Background(), text); err != nil || res != app.LegacyImported {
		t.Fatalf("import after the unseal: %v %v", res, err)
	}
	if n := h.legacyEvents() - before; n != 1 {
		t.Fatalf("the import recorded %d events", n)
	}
}

func TestBackupKeyLegacyImportRace(t *testing.T) {
	h := newBackupKeyHarness(t)
	text := legacyKeyText(t)
	before := h.legacyEvents()
	const replicas = 8
	results := make([]app.LegacyImport, replicas)
	errs := make([]error, replicas)
	var wg sync.WaitGroup
	for i := range replicas {
		wg.Go(func() { results[i], errs[i] = h.uc.ImportLegacy(context.Background(), text) })
	}
	wg.Wait()
	imported := 0
	for i := range replicas {
		if errs[i] != nil {
			t.Fatalf("replica %d: %v", i, errs[i])
		}
		switch results[i] {
		case app.LegacyImported:
			imported++
		case app.LegacyKeyPresent:
		default:
			t.Fatalf("replica %d: %v", i, results[i])
		}
	}
	if n := h.legacyEvents() - before; imported != 1 || n != 1 {
		t.Fatalf("%d replicas imported, %d events recorded", imported, n)
	}
}
