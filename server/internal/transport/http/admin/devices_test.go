package admin_test

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/server/internal/principal"
	"github.com/paddock-mdm/paddock/server/internal/transport/http/admin/adminapi"
)

// testBundleKey is the public key the fake bundle key source returns.
const testBundleKey = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="

// insertDevice creates a device with one active identity key directly in the database (the worker's job).
func (e *env) insertDevice(org uuid.UUID, hostname, state string) uuid.UUID {
	e.t.Helper()
	ctx := context.Background()
	id := uuid.Must(uuid.NewV7())
	if _, err := e.super.Exec(ctx, `INSERT INTO device (id, organization_id, hostname, state, hardware_uuid)
		VALUES ($1, $2, $3, $4, $5)`, id, org, hostname, state, "hw-"+hostname); err != nil {
		e.t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(id.String()))
	if _, err := e.super.Exec(ctx, `INSERT INTO device_identity_key (key_id, organization_id, device_id, public_key, key_protection, status)
		VALUES ($1, $2, $3, $4, 'file', 'active')`, uuid.NewString(), org, id, sum[:]); err != nil {
		e.t.Fatal(err)
	}
	return id
}

// stateChanges returns the scopes and IDs of the state change outbox rows of org, oldest first.
func (e *env) stateChanges(org uuid.UUID) []string {
	e.t.Helper()
	rows, err := e.super.Query(context.Background(),
		"SELECT payload->>'scope' || ':' || (payload->>'id') FROM outbox WHERE subject = $1 ORDER BY id", "state."+org.String())
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

func TestEnrollmentTokenLifecycle(t *testing.T) {
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	bob := e.session(e.acme, principal.RoleOrgOperator)
	carol := e.session(e.globex, principal.RoleOrgAdmin)
	expires := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)

	created := e.do(call{method: "POST", path: "/api/v1/enrollment-tokens", cookie: alice, body: map[string]any{
		"name": "Laptops", "expires_at": expires, "max_uses": 5, "auto_approve": true,
	}})
	if created.status != http.StatusCreated {
		t.Fatalf("create: %d %s", created.status, created.body)
	}
	e.expectEvent(created, "enrollment_token.created:success:")
	var tok adminapi.EnrollmentTokenCreated
	created.decode(t, &tok)
	if tok.Secret == "" || tok.EnrollmentConfig.Token != tok.Secret || tok.EnrollmentConfig.ServerUrl != "https://device.test" ||
		tok.EnrollmentConfig.OrganizationId != e.acme || len(tok.EnrollmentConfig.BundleKeys) != 1 ||
		tok.EnrollmentConfig.BundleKeys[0].PublicKey != testBundleKey || tok.Token.Status != "active" {
		t.Fatalf("created token %+v", tok)
	}
	// Only the hash of the secret is stored, and the secret is nowhere in the audit trail.
	var stored []byte
	if err := e.super.QueryRow(context.Background(), "SELECT secret_sha256 FROM enrollment_token WHERE id = $1", tok.Token.Id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256([]byte(tok.Secret)); string(stored) != string(sum[:]) {
		t.Fatal("stored value is not the SHA-256 of the secret")
	}
	var leaked int
	if err := e.super.QueryRow(context.Background(), "SELECT count(*) FROM action WHERE params::text LIKE '%' || $1 || '%' OR target::text LIKE '%' || $1 || '%'", tok.Secret).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatalf("secret found in %d action rows (%v)", leaked, err)
	}

	got := e.do(call{method: "GET", path: "/api/v1/enrollment-tokens/" + tok.Token.Id.String(), cookie: bob})
	if got.status != http.StatusOK || strings.Contains(string(got.body), tok.Secret) {
		t.Fatalf("get: %d %s", got.status, got.body)
	}
	if denied := e.do(call{method: "POST", path: "/api/v1/enrollment-tokens", cookie: bob, body: map[string]any{
		"name": "x", "expires_at": expires, "max_uses": 1, "auto_approve": false,
	}}); denied.status != http.StatusForbidden {
		t.Fatalf("operator create: %d", denied.status)
	} else {
		e.expectEvent(denied, "enrollment_token.created:denied:forbidden")
	}
	if tooLong := e.do(call{method: "POST", path: "/api/v1/enrollment-tokens", cookie: alice, body: map[string]any{
		"name": "x", "expires_at": time.Now().Add(31 * 24 * time.Hour), "max_uses": 1, "auto_approve": false,
	}}); tooLong.status != http.StatusBadRequest {
		t.Fatalf("31 days: %d", tooLong.status)
	}
	e.keysDown = true
	if down := e.do(call{method: "POST", path: "/api/v1/enrollment-tokens", cookie: alice, body: map[string]any{
		"name": "x", "expires_at": expires, "max_uses": 1, "auto_approve": false,
	}}); down.status != http.StatusBadGateway {
		t.Fatalf("keys unavailable: %d", down.status)
	} else {
		e.expectEvent(down, "enrollment_token.created:failure:upstream_unavailable")
	}
	e.keysDown = false

	revokePath := "/api/v1/enrollment-tokens/" + tok.Token.Id.String() + "/revoke"
	noCSRF := e.do(call{method: "POST", path: revokePath, cookie: alice, noCSRF: true, skipReqCheck: true})
	if noCSRF.status != http.StatusForbidden || noCSRF.problemCode(t) != "csrf_missing" {
		t.Fatalf("revoke without CSRF: %d %s", noCSRF.status, noCSRF.body)
	}
	e.expectEvent(noCSRF, "enrollment_token.revoked:denied:csrf_missing")
	if foreign := e.do(call{method: "POST", path: revokePath, cookie: carol}); foreign.status != http.StatusNotFound {
		t.Fatalf("revoke by globex: %d", foreign.status)
	}
	revoked := e.do(call{method: "POST", path: revokePath, cookie: alice})
	if revoked.status != http.StatusOK {
		t.Fatalf("revoke: %d %s", revoked.status, revoked.body)
	}
	e.expectEvent(revoked, "enrollment_token.revoked:success:")
	var rt adminapi.EnrollmentToken
	revoked.decode(t, &rt)
	if rt.Status != "revoked" || rt.RevokedAt == nil {
		t.Fatalf("revoked token %+v", rt)
	}
	// An action outside the contract is not routed (sent around the contract check on purpose).
	unknownReq := httptest.NewRequest(http.MethodPost, "https://admin.test/api/v1/enrollment-tokens/"+tok.Token.Id.String()+":explode", nil)
	unknownReq.Header.Set("X-Paddock-CSRF", "1")
	unknownReq.AddCookie(alice)
	unknown := httptest.NewRecorder()
	e.handler.ServeHTTP(unknown, unknownReq)
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown action: %d", unknown.Code)
	}

	page := e.list(alice, "/api/v1/enrollment-tokens", url.Values{"q": {"Laptops"}})
	if page.Total != 1 {
		t.Fatalf("list total %d", page.Total)
	}
	if page := e.list(carol, "/api/v1/enrollment-tokens", nil); page.Total != 0 {
		t.Fatalf("globex sees %d acme tokens", page.Total)
	}
}

func TestDeviceLifecycle(t *testing.T) {
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	bob := e.session(e.acme, principal.RoleOrgOperator)
	dave := e.session(e.acme, principal.RoleOrgAuditor)
	carol := e.session(e.globex, principal.RoleOrgAdmin)
	dev := e.insertDevice(e.acme, "lt-alice", "pending")
	base := "/api/v1/devices/" + dev.String()

	if r := e.do(call{method: "GET", path: base, cookie: dave}); r.status != http.StatusOK {
		t.Fatalf("auditor get: %d", r.status)
	}
	if r := e.do(call{method: "POST", path: base + "/approve", cookie: dave}); r.status != http.StatusForbidden {
		t.Fatalf("auditor approve: %d", r.status)
	}
	approved := e.do(call{method: "POST", path: base + "/approve", cookie: bob})
	if approved.status != http.StatusOK {
		t.Fatalf("approve: %d %s", approved.status, approved.body)
	}
	e.expectEvent(approved, "device.approved:success:")
	var d adminapi.Device
	approved.decode(t, &d)
	if d.State != "active" {
		t.Fatalf("state %s", d.State)
	}
	again := e.do(call{method: "POST", path: base + "/approve", cookie: bob})
	if again.status != http.StatusConflict || again.problemCode(t) != "invalid_state" {
		t.Fatalf("approve twice: %d %s", again.status, again.body)
	}
	e.expectEvent(again, "device.approved:failure:invalid_state")
	if r := e.do(call{method: "POST", path: base + "/retire", cookie: bob}); r.status != http.StatusForbidden {
		t.Fatalf("operator retire: %d", r.status)
	}
	if r := e.do(call{method: "POST", path: base + "/retire", cookie: carol}); r.status != http.StatusNotFound {
		t.Fatalf("globex retire: %d", r.status)
	}
	retired := e.do(call{method: "POST", path: base + "/retire", cookie: alice})
	if retired.status != http.StatusOK {
		t.Fatalf("retire: %d %s", retired.status, retired.body)
	}
	detail := e.do(call{method: "GET", path: base, cookie: alice})
	var dd adminapi.DeviceDetail
	detail.decode(t, &dd)
	if dd.State != "retired" || len(dd.IdentityKeys) != 1 || dd.IdentityKeys[0].Status != "revoked" {
		t.Fatalf("retired device %+v", dd)
	}
	if want := []string{"device:" + dev.String(), "device:" + dev.String()}; !slices.Equal(e.stateChanges(e.acme), want) {
		t.Fatalf("state changes %v, want %v (failed attempts emit none)", e.stateChanges(e.acme), want)
	}
	if r := e.do(call{method: "GET", path: base, cookie: carol}); r.status != http.StatusNotFound {
		t.Fatalf("globex get: %d", r.status)
	}

	quarantined := e.insertDevice(e.acme, "lt-clone", "quarantined")
	released := e.do(call{method: "POST", path: "/api/v1/devices/" + quarantined.String() + "/release-quarantine", cookie: bob})
	if released.status != http.StatusOK {
		t.Fatalf("release: %d %s", released.status, released.body)
	}
	e.expectEvent(released, "device.quarantine_released:success:")
	pending := e.insertDevice(e.acme, "lt-unknown", "pending")
	if r := e.do(call{method: "POST", path: "/api/v1/devices/" + pending.String() + "/reject", cookie: alice}); r.status != http.StatusOK {
		t.Fatalf("reject: %d %s", r.status, r.body)
	}
	if r := e.do(call{method: "POST", path: "/api/v1/devices/not-a-uuid/approve", cookie: alice, skipReqCheck: true}); r.status != http.StatusBadRequest {
		t.Fatalf("malformed id: %d", r.status)
	} else {
		e.expectEvent(r, "device.approved:failure:invalid_request")
	}
}

func TestDeviceGroupsAndEffectiveConfig(t *testing.T) {
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	carol := e.session(e.globex, principal.RoleOrgAdmin)
	dev := e.insertDevice(e.acme, "lt-config", "active")
	group := func(cookie *http.Cookie, name string) string {
		r := e.do(call{method: "POST", path: "/api/v1/device-groups", cookie: cookie, body: map[string]any{"name": name + " " + uuid.NewString()[:8]}})
		var g adminapi.DeviceGroup
		r.decode(t, &g)
		return g.Id.String()
	}
	g1, g2, foreign := group(alice, "g1"), group(alice, "g2"), group(carol, "foreign")

	if r := e.do(call{method: "PUT", path: "/api/v1/devices/" + dev.String() + "/groups", cookie: alice,
		body: map[string]any{"device_group_ids": []string{foreign}}}); r.status != http.StatusBadRequest {
		t.Fatalf("foreign group accepted: %d %s", r.status, r.body)
	}
	set := e.do(call{method: "PUT", path: "/api/v1/devices/" + dev.String() + "/groups", cookie: alice,
		body: map[string]any{"device_group_ids": []string{g1, g2, g1}}})
	if set.status != http.StatusOK {
		t.Fatalf("set groups: %d %s", set.status, set.body)
	}
	e.expectEvent(set, "device.groups_changed:success:")
	var dd adminapi.DeviceDetail
	set.decode(t, &dd)
	if len(dd.Groups) != 2 {
		t.Fatalf("groups %+v", dd.Groups)
	}
	members := e.list(alice, "/api/v1/device-groups/"+g1+"/devices", nil)
	if members.Total != 1 {
		t.Fatalf("group members %d", members.Total)
	}
	if r := e.do(call{method: "GET", path: "/api/v1/device-groups/" + foreign + "/devices", cookie: alice}); r.status != http.StatusNotFound {
		t.Fatalf("foreign group members: %d", r.status)
	}

	file := func(groupID, content string) result {
		body := map[string]any{"path": "/etc/motd", "content": content}
		if groupID != "" {
			body["device_group_id"] = groupID
		}
		return e.do(call{method: "POST", path: "/api/v1/managed-files", cookie: alice, body: body})
	}
	for _, r := range []result{file("", "org"), file(g1, "g1"), file(g2, "g2")} {
		if r.status != http.StatusCreated {
			t.Fatalf("create file: %d %s", r.status, r.body)
		}
	}
	e.expectEvent(file("", "dup"), "managed_file.created:failure:already_exists")
	if r := e.do(call{method: "POST", path: "/api/v1/managed-files", cookie: alice, body: map[string]any{"path": "/etc/sudoers.d/x", "content": "x"}}); r.status != http.StatusUnprocessableEntity || r.problemCode(t) != "path_not_allowed" {
		t.Fatalf("protected path: %d %s", r.status, r.body)
	}
	if r := e.do(call{method: "POST", path: "/api/v1/managed-units", cookie: alice, body: map[string]any{"unit": "sshd.service"}}); r.status != http.StatusUnprocessableEntity || r.problemCode(t) != "unit_not_allowed" {
		t.Fatalf("reserved unit: %d %s", r.status, r.body)
	}
	unit := e.do(call{method: "POST", path: "/api/v1/managed-units", cookie: alice, body: map[string]any{"unit": "chrony.service", "device_group_id": g2}})
	if unit.status != http.StatusCreated {
		t.Fatalf("create unit: %d %s", unit.status, unit.body)
	}

	eff := e.do(call{method: "GET", path: "/api/v1/devices/" + dev.String() + "/effective-config", cookie: alice})
	var cfg adminapi.EffectiveConfig
	eff.decode(t, &cfg)
	wantContent := "g1"
	if g2 < g1 {
		wantContent = "g2"
	}
	if len(cfg.Files) != 1 || cfg.Files[0].Content != wantContent || len(cfg.Units) != 1 || len(cfg.Conflicts) != 1 ||
		cfg.Conflicts[0].Resource != "file:/etc/motd" {
		t.Fatalf("effective config %+v", cfg)
	}
	var ids []string
	for _, r := range cfg.Resources {
		ids = append(ids, r.Id)
	}
	if strings.Join(ids, ",") != "file:/etc/motd,time,unit:chrony.service" {
		t.Fatalf("resources %v", ids)
	}
	if r := e.do(call{method: "GET", path: "/api/v1/devices/" + dev.String() + "/effective-config", cookie: carol}); r.status != http.StatusNotFound {
		t.Fatalf("globex effective config: %d", r.status)
	}
	changes := e.stateChanges(e.acme)
	for _, want := range []string{"device:" + dev.String(), "org:" + e.acme.String(), "device_group:" + g1, "device_group:" + g2} {
		if !slices.Contains(changes, want) {
			t.Errorf("state change %s missing from %v", want, changes)
		}
	}
}
