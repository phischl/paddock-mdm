package admin_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

const backupKeyPath = "/api/platform/v1/backup/key"

func newBackupKeyEnv(t *testing.T) (*env, *app.BackupKeys) {
	t.Helper()
	platform, err := db.NewPlatformPool(context.Background(), pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	var keys *app.BackupKeys
	e := newEnvWith(t, func(d *admin.Deps) {
		keys = app.NewBackupKeys(d.Runner, platform, &countingWrap{})
		d.BackupKeys = keys
	})
	// backup_key is platform-wide: start from and leave an empty table.
	reset := func() {
		if _, err := e.super.Exec(context.Background(), "DELETE FROM backup_key"); err != nil {
			t.Fatal(err)
		}
	}
	reset()
	t.Cleanup(reset)
	return e, keys
}

func charsAt(text string, positions []int) string {
	var b strings.Builder
	for _, p := range positions {
		b.WriteByte(text[p-1])
	}
	return b.String()
}

// TestBackupKeyEndpoints (PDK-730) covers plan M15 decisions 7 and 8 at the handler: the key text only in the
// uncached generating response, never in a read; confirmation by typed characters with the mismatch problem; every
// write audited once.
func TestBackupKeyEndpoints(t *testing.T) {
	e, _ := newBackupKeyEnv(t)
	root := e.platformSession()
	su := e.steppedUp(root, time.Now())

	r := e.do(call{method: "GET", path: backupKeyPath, cookie: root})
	if r.status != http.StatusOK || string(r.body) != `{"active":null,"pending":null,"retired":[]}`+"\n" {
		t.Fatalf("GET without a key: %d %q", r.status, r.body)
	}
	if got := e.events(r.header.Get("X-Request-Id")); len(got) != 0 {
		t.Fatalf("a read recorded %v", got)
	}

	r = e.do(call{method: "POST", path: backupKeyPath, cookie: root})
	if r.status != http.StatusForbidden || r.problemCode(t) != "step_up_required" {
		t.Fatalf("generate without step-up: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.backup_key_generated:denied:step_up_required")

	r = e.do(call{method: "POST", path: backupKeyPath, cookie: su})
	if r.status != http.StatusCreated || r.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("generate: %d %v %s", r.status, r.header, r.body)
	}
	e.expectEvent(r, "platform.backup_key_generated:success:")
	var gen adminapi.BackupKeyGenerated
	r.decode(t, &gen)
	if raw, err := base64.StdEncoding.DecodeString(gen.Key); err != nil || len(gen.Key) != 44 || len(raw) != 32 ||
		len(gen.Positions) != 6 || gen.Fingerprint == "" || !strings.HasSuffix(gen.DownloadName, ".txt") {
		t.Fatalf("generated %+v", gen)
	}
	right := charsAt(gen.Key, gen.Positions)
	wrongAnswer := "AAAAAA"
	if right == wrongAnswer {
		wrongAnswer = "BBBBBB"
	}

	r = e.do(call{method: "POST", path: backupKeyPath, cookie: su})
	if r.status != http.StatusConflict || r.problemCode(t) != "invalid_state" {
		t.Fatalf("second generate: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.backup_key_generated:failure:invalid_state")

	st := getBackupKeyStatus(t, e, root, gen.Key)
	if st.Pending == nil || st.Pending.KeyId != gen.KeyId || st.Pending.State != "unconfirmed" || st.Active != nil ||
		st.Pending.Positions == nil || !slices.Equal(*st.Pending.Positions, gen.Positions) {
		t.Fatalf("status while the key is pending: %+v", st)
	}

	confirm := func(c *http.Cookie, id, answer string) result {
		return e.do(call{method: "POST", path: backupKeyPath + "/" + id + "/confirm", cookie: c, body: map[string]any{"answer": answer}})
	}
	r = confirm(root, gen.KeyId, right)
	if r.status != http.StatusForbidden || r.problemCode(t) != "step_up_required" {
		t.Fatalf("confirm without step-up: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.backup_key_confirmed:denied:step_up_required")

	r = confirm(su, gen.KeyId, right[:5])
	if r.status != http.StatusBadRequest || r.problemCode(t) != "invalid_request" {
		t.Fatalf("short answer: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.backup_key_confirmed:failure:invalid_request")

	r = confirm(su, gen.KeyId, wrongAnswer)
	if r.status != http.StatusConflict || r.problemCode(t) != "backup_key_mismatch" || !strings.Contains(string(r.body), "attempts_left=2") {
		t.Fatalf("wrong answer: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.backup_key_confirmed:failure:backup_key_mismatch")

	r = e.do(call{method: "POST", path: backupKeyPath + "/" + gen.KeyId + "/confirm", cookie: su, body: map[string]any{"answer": right},
		noCSRF: true, skipReqCheck: true})
	if r.status != http.StatusForbidden || r.problemCode(t) != "csrf_missing" {
		t.Fatalf("confirm without CSRF header: %d %s", r.status, r.body)
	}

	r = confirm(su, gen.KeyId, right)
	var k adminapi.BackupKey
	r.decode(t, &k)
	if r.status != http.StatusOK || k.State != "confirmed" || k.Attempts != 1 || k.ConfirmedBy == nil || k.Positions != nil {
		t.Fatalf("confirm: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.backup_key_confirmed:success:")
	if st := getBackupKeyStatus(t, e, root, gen.Key); st.Pending != nil || st.Active == nil || st.Active.Positions != nil {
		t.Fatalf("status after the confirmation: %+v", st)
	}
	confirmedKey := gen.Key

	r = e.do(call{method: "POST", path: backupKeyPath + "/" + gen.KeyId + "/discard", cookie: su})
	if r.status != http.StatusConflict || r.problemCode(t) != "invalid_state" {
		t.Fatalf("discard a confirmed key: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.backup_key_discarded:failure:invalid_state")

	r = e.do(call{method: "POST", path: backupKeyPath, cookie: su})
	r.decode(t, &gen)
	r = e.do(call{method: "POST", path: backupKeyPath + "/" + gen.KeyId + "/discard", cookie: su})
	r.decode(t, &k)
	if r.status != http.StatusOK || k.State != "discarded" || k.Positions != nil {
		t.Fatalf("discard: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.backup_key_discarded:success:")
	if st := getBackupKeyStatus(t, e, root, gen.Key, confirmedKey); st.Pending != nil || st.Active == nil || st.Active.Positions != nil {
		t.Fatalf("status after the discard: %+v", st)
	}

	r = e.do(call{method: "POST", path: backupKeyPath + "/bk-20260101-00000000/discard", cookie: su})
	if r.status != http.StatusNotFound || r.problemCode(t) != "not_found" {
		t.Fatalf("discard a missing key: %d %s", r.status, r.body)
	}
}

// getBackupKeyStatus reads GET /backup/key and fails when the raw JSON holds a key text, the challenge hash or the
// ciphertext (plan M15 AC 3, amendment 2026-11-04).
func getBackupKeyStatus(t *testing.T, e *env, c *http.Cookie, keyTexts ...string) adminapi.BackupKeyStatus {
	t.Helper()
	r := e.do(call{method: "GET", path: backupKeyPath, cookie: c})
	if r.status != http.StatusOK {
		t.Fatalf("GET: %d %s", r.status, r.body)
	}
	for _, s := range append([]string{"challenge", "sha256", "ciphertext", "vault:", `"key":`}, keyTexts...) {
		if strings.Contains(string(r.body), s) {
			t.Fatalf("GET shows key material %q: %s", s, r.body)
		}
	}
	var st adminapi.BackupKeyStatus
	r.decode(t, &st)
	return st
}

// TestBackupKeyLegacyConfirmByRead (PDK-730, plan M15 decision 9 and amendment 2026-11-04): the administrator of the
// imported key holds the host file but never saw a generating response; the positions in GET confirm it.
func TestBackupKeyLegacyConfirmByRead(t *testing.T) {
	e, keys := newBackupKeyEnv(t)
	root := e.platformSession()
	su := e.steppedUp(root, time.Now())
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	hostKey := base64.StdEncoding.EncodeToString(raw)
	if res, err := keys.ImportLegacy(context.Background(), hostKey+"\n"); err != nil || res != app.LegacyImported {
		t.Fatalf("import: %v %v", res, err)
	}

	st := getBackupKeyStatus(t, e, root, hostKey)
	if st.Pending == nil || st.Pending.KeyId != "legacy" || !st.Pending.Legacy || st.Pending.Positions == nil ||
		len(*st.Pending.Positions) != 6 || !slices.IsSorted(*st.Pending.Positions) {
		t.Fatalf("status of the imported key: %+v", st)
	}
	for _, p := range *st.Pending.Positions {
		if p < 1 || p > len(strings.TrimRight(hostKey, "=")) {
			t.Fatalf("position %d of %v is outside the key", p, *st.Pending.Positions)
		}
	}

	r := e.do(call{method: "POST", path: backupKeyPath + "/legacy/confirm", cookie: su,
		body: map[string]any{"answer": charsAt(hostKey, *st.Pending.Positions)}})
	var k adminapi.BackupKey
	r.decode(t, &k)
	if r.status != http.StatusOK || k.State != "confirmed" || !k.Legacy || k.Positions != nil {
		t.Fatalf("confirm key legacy: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.backup_key_confirmed:success:")
	if st := getBackupKeyStatus(t, e, root, hostKey); st.Pending != nil || st.Active == nil || st.Active.KeyId != "legacy" ||
		st.Active.Positions != nil {
		t.Fatalf("status after confirming key legacy: %+v", st)
	}
}

// TestBackupKeyEndpointsRefuseOthers (PDK-730): organization sessions and API tokens never reach the key; refused
// writes are audited as denied. API tokens are organization-scoped, so they are forbidden before the step-up rule
// (which refuses any token, app.TestBackupKeyAuthorization) is consulted.
func TestBackupKeyEndpointsRefuseOthers(t *testing.T) {
	e, _ := newBackupKeyEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	token := e.createAPIToken("acme", alice, "backup-key", adminapi.ApiTokenRoleOrgAdmin)
	steppedAlice := e.steppedUp(alice, time.Now())
	const id = "bk-20260101-00000000"
	for _, c := range []struct {
		method, path string
		body         any
		event        string
	}{
		{"GET", backupKeyPath, nil, ""},
		{"POST", backupKeyPath, nil, "platform.backup_key_generated"},
		{"POST", backupKeyPath + "/" + id + "/confirm", map[string]any{"answer": "abcdef"}, "platform.backup_key_confirmed"},
		{"POST", backupKeyPath + "/" + id + "/discard", nil, "platform.backup_key_discarded"},
	} {
		r := e.do(call{method: c.method, path: c.path, cookie: steppedAlice, body: c.body})
		if r.status != http.StatusForbidden || r.problemCode(t) != "forbidden" {
			t.Errorf("session %s %s: %d %s", c.method, c.path, r.status, r.body)
		}
		if c.event != "" {
			e.expectEvent(r, c.event+":denied:forbidden")
		}
		r = e.do(call{method: c.method, path: c.path, headers: bearer(token.Secret), body: c.body})
		if r.status != http.StatusForbidden {
			t.Errorf("token %s %s: %d %s", c.method, c.path, r.status, r.body)
		}
	}
	var n int
	if err := e.super.QueryRow(context.Background(), "SELECT count(*) FROM backup_key").Scan(&n); err != nil || n != 0 {
		t.Fatalf("a refused request stored %d keys (%v)", n, err)
	}
}
