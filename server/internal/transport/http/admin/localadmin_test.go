package admin_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// fakeDecrypter "decrypts" a ciphertext into "pw-" plus the ciphertext; "broken" fails like a sealed OpenBao.
type fakeDecrypter struct{}

func (fakeDecrypter) Decrypt(_ context.Context, version int, ciphertext string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil || version != 1 || string(raw) == "broken" {
		return nil, errors.New("decrypt failed")
	}
	return []byte("pw-" + string(raw)), nil
}

func (e *env) escrowSecret(org, device uuid.UUID, generation int, status, ciphertext string) {
	e.t.Helper()
	if _, err := e.super.Exec(context.Background(), `INSERT INTO escrow_secret (id, organization_id, device_id, kind, generation, status,
		ciphertext, key_version, activated_at) VALUES ($1, $2, $3, 'admin_password', $4, $5, $6, 1, CASE WHEN $5 = 'active' THEN now() END)`,
		uuid.New(), org, device, generation, status, []byte(ciphertext)); err != nil {
		e.t.Fatal(err)
	}
}

// TestLocalAdminReveal (plan M4a decision 17, gate U1 at the API): a reveal needs an organization administrator,
// a fresh step-up and the typed hostname; it returns the active and the pending password, records their
// generations (never the passwords) and schedules a rotation when the organization rotates after a reveal.
func TestLocalAdminReveal(t *testing.T) {
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	operator := e.session(e.acme, principal.RoleOrgOperator)
	device := e.insertDevice(e.acme, "lt-reveal", "active")
	path := "/api/v1/devices/" + device.String() + "/local-admin"
	body := map[string]any{"confirm_hostname": "lt-reveal"}
	reveal := func(cookie *http.Cookie, body map[string]any) result {
		t.Helper()
		return e.do(call{method: "POST", path: path + "/reveal", cookie: cookie, body: body})
	}

	res := reveal(alice, body)
	if res.status != http.StatusForbidden || res.problemCode(t) != "step_up_required" {
		t.Fatalf("without step-up: %d %s", res.status, res.body)
	}
	e.expectEvent(res, "local_admin.revealed:denied:step_up_required")
	if res := reveal(e.steppedUp(alice, time.Now().Add(-301*time.Second)), body); res.status != http.StatusForbidden {
		t.Fatalf("with an old step-up: %d %s", res.status, res.body)
	}
	if res := reveal(e.steppedUp(operator, time.Now()), body); res.status != http.StatusForbidden || res.problemCode(t) != "forbidden" {
		t.Fatalf("operator: %d %s", res.status, res.body)
	}
	fresh := e.steppedUp(alice, time.Now())
	if res := reveal(fresh, body); res.status != http.StatusConflict || res.problemCode(t) != "invalid_state" {
		t.Fatalf("without escrowed password: %d %s", res.status, res.body)
	}
	e.escrowSecret(e.acme, device, 1, "superseded", "zero")
	e.escrowSecret(e.acme, device, 2, "active", "one")
	e.escrowSecret(e.acme, device, 3, "stored", "two")
	if res := reveal(fresh, map[string]any{"confirm_hostname": "lt-other"}); res.status != http.StatusBadRequest {
		t.Fatalf("wrong hostname: %d %s", res.status, res.body)
	}

	res = reveal(fresh, body)
	var out adminapi.LocalAdminRevealed
	res.decode(t, &out)
	if res.status != http.StatusOK || len(out.Passwords) != 2 || out.Passwords[0].Generation != 2 || out.Passwords[0].State != "active" ||
		out.Passwords[0].Password != "pw-one" || out.Passwords[1].Generation != 3 || out.Passwords[1].State != "pending" ||
		out.Passwords[1].Password != "pw-two" || res.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("reveal: %d %s %v", res.status, res.body, res.header)
	}
	e.expectEvent(res, "local_admin.revealed:success:")
	var params, actor string
	if err := e.super.QueryRow(context.Background(), "SELECT params::text, actor::text FROM action WHERE correlation_id = $1",
		res.header.Get("X-Request-Id")).Scan(&params, &actor); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(params, "pw-") || !strings.Contains(params, `"generations": [2, 3]`) || !strings.Contains(actor, `"step_up": true`) {
		t.Fatalf("audit params %s, actor %s", params, actor)
	}

	var state adminapi.LocalAdmin
	got := e.do(call{method: "GET", path: path, cookie: e.session(e.acme, principal.RoleOrgAuditor)})
	got.decode(t, &state)
	if got.status != http.StatusOK || state.Username != "paddock-admin" || *state.ActiveGeneration != 2 || *state.PendingGeneration != 3 ||
		state.LastRotatedAt == nil || state.NextRotationAt.Sub(*state.LastRotatedAt) != 30*24*time.Hour || state.LastRotationError != nil {
		t.Fatalf("state: %d %s", got.status, got.body)
	}

	// Rotation after a reveal: a delayed rotate_admin_password command.
	if _, err := e.super.Exec(context.Background(), "UPDATE organization_login_settings SET rotate_after_reveal_hours = 2 WHERE organization_id = $1", e.acme); err != nil {
		t.Fatal(err)
	}
	res = reveal(fresh, body)
	if res.status != http.StatusOK || e.actionParam(res, "rotation_scheduled_at") == "" {
		t.Fatalf("reveal with rotation: %d %s", res.status, res.body)
	}
	var notBefore time.Time
	if err := e.super.QueryRow(context.Background(), `SELECT not_before FROM device_command WHERE device_id = $1
		AND type = 'rotate_admin_password'`, device).Scan(&notBefore); err != nil || time.Until(notBefore) < 119*time.Minute {
		t.Fatalf("scheduled rotation at %s (%v)", notBefore, err)
	}

	// A sealed key service: the reveal fails as one failure event, nothing is returned.
	broken := e.insertDevice(e.acme, "lt-broken", "active")
	e.escrowSecret(e.acme, broken, 1, "active", "broken")
	res = e.do(call{method: "POST", path: "/api/v1/devices/" + broken.String() + "/local-admin/reveal", cookie: fresh,
		body: map[string]any{"confirm_hostname": "lt-broken"}})
	if res.status != http.StatusBadGateway || strings.Contains(string(res.body), "pw-") {
		t.Fatalf("decrypt failure: %d %s", res.status, res.body)
	}
	e.expectEvent(res, "local_admin.revealed:failure:upstream_unavailable")

	// Another organization's device is not found.
	carol := e.steppedUp(e.session(e.globex, principal.RoleOrgAdmin), time.Now())
	if res := e.do(call{method: "POST", path: path + "/reveal", cookie: carol, body: body}); res.status != http.StatusNotFound {
		t.Fatalf("other organization: %d", res.status)
	}
	if res := e.do(call{method: "GET", path: path, cookie: carol}); res.status != http.StatusNotFound {
		t.Fatalf("other organization state: %d", res.status)
	}
}
