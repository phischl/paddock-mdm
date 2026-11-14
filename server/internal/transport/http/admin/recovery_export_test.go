package admin_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

const exportPassphrase = "the requester's long passphrase"

// exportDevice inserts a device of org with an escrowed recovery key and local administrator password.
func (e *env) exportDevice(org uuid.UUID, state, keyCiphertext string) uuid.UUID {
	e.t.Helper()
	id := uuid.Must(uuid.NewV7())
	if _, err := e.super.Exec(context.Background(), `INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, $3, $4)`,
		id, org, "ex-"+id.String()[28:], state); err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.super.Exec(context.Background(), `INSERT INTO escrow_secret (id, organization_id, device_id, kind, generation, status, ciphertext, key_version)
		VALUES ($1, $2, $3, 'luks_recovery_key', 1, 'stored', $4, 1), ($5, $2, $3, 'admin_password', 1, 'active', 'secret-pw', 1)`,
		uuid.New(), org, id, []byte(keyCiphertext), uuid.New()); err != nil {
		e.t.Fatal(err)
	}
	return id
}

func (e *env) pendingDeletion(org uuid.UUID) {
	e.t.Helper()
	if _, err := e.super.Exec(context.Background(), `UPDATE organization SET deletion_requested_at = now(), deletion_requested_by = 'root',
		deletion_reason = 'contract ended', delete_after = now() + interval '30 days' WHERE id = $1`, org); err != nil {
		e.t.Fatal(err)
	}
}

// exportEvent is the audit row of a request: its organization, actor type and params.
func (e *env) exportEvent(r result) (uuid.UUID, string, map[string]any) {
	e.t.Helper()
	var org uuid.UUID
	var actor string
	var params []byte
	if err := e.super.QueryRow(context.Background(), `SELECT organization_id, actor->>'type', params FROM action
		WHERE correlation_id = $1 AND code = 'organization.recovery_exported'`, r.header.Get(httpx.HeaderRequestID)).
		Scan(&org, &actor, &params); err != nil {
		e.t.Fatal(err)
	}
	if bytes.Contains(params, []byte(exportPassphrase)) || bytes.Contains(params, []byte("pw-")) {
		e.t.Fatalf("the audit params carry a secret: %s", params)
	}
	var m map[string]any
	if err := json.Unmarshal(params, &m); err != nil {
		e.t.Fatal(err)
	}
	return org, actor, m
}

func exportBody(passphrase string) map[string]any {
	return map[string]any{"recipient": "passphrase", "passphrase": passphrase}
}

func readExport(t *testing.T, body []byte, keys openpgp.EntityList) []map[string]any {
	t.Helper()
	block, err := armor.Decode(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("armour: %v", err)
	}
	md, err := openpgp.ReadMessage(block.Body, keys, func([]openpgp.Key, bool) ([]byte, error) {
		return []byte(exportPassphrase), nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Fatal(err)
	}
	var lines []map[string]any
	sc := bufio.NewScanner(bytes.NewReader(plain))
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, m)
	}
	return lines
}

// TestRecoveryExportAPI (plan M17 amendment b, tests): the organization administrator's export of a pending
// organization, its refusals, the export limit and exactly one audit event per attempt without any secret.
func TestRecoveryExportAPI(t *testing.T) {
	e := newEnv(t)
	device := e.exportDevice(e.acme, "active", "key-1")
	e.exportDevice(e.acme, "retired", "key-retired")
	if _, err := e.super.Exec(context.Background(), `INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'bare', 'active')`,
		uuid.New(), e.acme); err != nil {
		t.Fatal(err)
	}
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	const path = "/api/v1/recovery-export"

	r := e.do(call{method: "POST", path: path, cookie: e.steppedUp(alice, time.Now()), body: exportBody(exportPassphrase)})
	if r.status != http.StatusConflict || r.problemCode(t) != "invalid_state" {
		t.Fatalf("not pending: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "organization.recovery_exported:failure:invalid_state")
	e.pendingDeletion(e.acme)

	r = e.do(call{method: "POST", path: path, cookie: alice, body: exportBody(exportPassphrase)})
	if r.status != http.StatusForbidden || r.problemCode(t) != "step_up_required" {
		t.Fatalf("without a step-up: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "organization.recovery_exported:denied:step_up_required")
	operator := e.steppedUp(e.session(e.acme, principal.RoleOrgOperator), time.Now())
	r = e.do(call{method: "POST", path: path, cookie: operator, body: exportBody(exportPassphrase)})
	if r.status != http.StatusForbidden || r.problemCode(t) != "forbidden" {
		t.Fatalf("operator: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "organization.recovery_exported:denied:forbidden")
	// Plan M17 amendment g point 2: 19 characters are refused, 20 accepted (below).
	nineteen := strings.Repeat("p", 19)
	r = e.do(call{method: "POST", path: path, cookie: e.steppedUp(alice, time.Now()), body: exportBody(nineteen), skipReqCheck: true})
	if r.status != http.StatusBadRequest || strings.Contains(string(r.body), nineteen) {
		t.Fatalf("short passphrase: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "organization.recovery_exported:failure:invalid_request")

	r = e.do(call{method: "POST", path: path, cookie: e.steppedUp(alice, time.Now()), body: exportBody(exportPassphrase)})
	if r.status != http.StatusOK || r.header.Get("Content-Type") != "application/pgp-encrypted" {
		t.Fatalf("export: %d %s", r.status, r.body)
	}
	_, params, err := mime.ParseMediaType(r.header.Get("Content-Disposition"))
	if err != nil || !strings.HasPrefix(params["filename"], "paddock-recovery-acme-") || !strings.HasSuffix(params["filename"], "Z.asc") {
		t.Fatalf("disposition %q: %v", r.header.Get("Content-Disposition"), err)
	}
	e.expectEvent(r, "organization.recovery_exported:success:")
	org, actor, p := e.exportEvent(r)
	if org != e.acme || actor != string(audit.ActorAdmin) || p["recipient"] != "passphrase" || p["requester_scope"] != "organization" ||
		p["devices"] != float64(1) || p["secrets"] != float64(2) || p["key_fingerprint"] != nil {
		t.Fatalf("event: %s %s %v", org, actor, p)
	}
	lines := readExport(t, r.body, nil)
	if len(lines) != 2 || lines[0]["organization_id"] != e.acme.String() || lines[1]["device_id"] != device.String() {
		t.Fatalf("lines: %v", lines)
	}
	vol := lines[1]["volumes"].([]any)[0].(map[string]any)
	admin := lines[1]["local_admin"].(map[string]any)
	if vol["recovery_key"] != "pw-key-1" || admin["password"] != "pw-secret-pw" || admin["username"] == "" {
		t.Fatalf("device line: %v", lines[1])
	}
	// The values equal the single reveal of the same device.
	reveal := e.do(call{method: "POST", path: "/api/v1/devices/" + device.String() + "/disk/recovery-key",
		cookie: e.steppedUp(alice, time.Now()), body: map[string]any{"confirm_hostname": lines[1]["hostname"]}})
	var revealed struct {
		RecoveryKey string `json:"recovery_key"`
	}
	reveal.decode(t, &revealed)
	if revealed.RecoveryKey != vol["recovery_key"] {
		t.Fatalf("reveal %q, export %q", revealed.RecoveryKey, vol["recovery_key"])
	}

	key, armored := exportKey(t)
	r = e.do(call{method: "POST", path: path, cookie: e.steppedUp(alice, time.Now()),
		body: map[string]any{"recipient": "public_key", "public_key": armored}})
	if r.status != http.StatusOK {
		t.Fatalf("public key: %d %s", r.status, r.body)
	}
	if _, _, p := e.exportEvent(r); p["recipient"] != "public_key" || len(p["key_fingerprint"].(string)) != 40 {
		t.Fatalf("public key event: %v", p)
	}
	if lines := readExport(t, r.body, openpgp.EntityList{key}); len(lines) != 2 {
		t.Fatalf("public key lines: %v", lines)
	}

	// A failure while streaming cuts the download off, is recorded as failure and does not count.
	broken := e.exportDevice(e.acme, "active", "broken")
	rec, event := e.abortedExport(path, e.steppedUp(alice, time.Now()))
	if strings.Contains(rec, "END PGP MESSAGE") || event != "organization.recovery_exported:failure:upstream_unavailable" {
		t.Fatalf("broken export: %q %s", rec, event)
	}
	if _, err := e.super.Exec(context.Background(), `DELETE FROM escrow_secret WHERE device_id = $1`, broken); err != nil {
		t.Fatal(err)
	}

	for i, pass := range []string{strings.Repeat("p", 20), exportPassphrase, exportPassphrase} {
		if r := e.do(call{method: "POST", path: path, cookie: e.steppedUp(alice, time.Now()), body: exportBody(pass)}); r.status != http.StatusOK {
			t.Fatalf("export %d: %d %s", i+3, r.status, r.body)
		}
	}
	r = e.do(call{method: "POST", path: path, cookie: e.steppedUp(alice, time.Now()), body: exportBody(exportPassphrase)})
	if r.status != http.StatusConflict || r.problemCode(t) != "export_limit" {
		t.Fatalf("sixth export: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "organization.recovery_exported:failure:export_limit")

	// A new deletion after a cancel starts the count again.
	if _, err := e.super.Exec(context.Background(), `UPDATE organization SET deletion_requested_at = NULL, deletion_requested_by = NULL,
		deletion_reason = NULL, delete_after = NULL WHERE id = $1`, e.acme); err != nil {
		t.Fatal(err)
	}
	e.pendingDeletion(e.acme)
	if r := e.do(call{method: "POST", path: path, cookie: e.steppedUp(alice, time.Now()), body: exportBody(exportPassphrase)}); r.status != http.StatusOK {
		t.Fatalf("after a new deletion request: %d %s", r.status, r.body)
	}

	// Another organization's administrator exports only its own organization, which has no pending deletion.
	bob := e.steppedUp(e.session(e.globex, principal.RoleOrgAdmin), time.Now())
	r = e.do(call{method: "POST", path: path, cookie: bob, body: exportBody(exportPassphrase)})
	if r.status != http.StatusConflict {
		t.Fatalf("other organization: %d %s", r.status, r.body)
	}
	if org, _, _ := e.exportEvent(r); org != e.globex {
		t.Fatalf("other organization's event in %s", org)
	}
}

// abortedExport sends an export whose stream breaks off and returns what reached the client and the request's event.
func (e *env) abortedExport(path string, cookie *http.Cookie) (string, string) {
	e.t.Helper()
	body, _ := json.Marshal(exportBody(exportPassphrase))
	req := httptest.NewRequest(http.MethodPost, "https://admin.test"+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Paddock-CSRF", "1")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	func() {
		defer func() {
			if v := recover(); v == nil || !errors.Is(v.(error), http.ErrAbortHandler) {
				e.t.Fatalf("the export was not cut off: %v", v)
			}
		}()
		e.handler.ServeHTTP(rec, req)
	}()
	got := e.events(rec.Header().Get(httpx.HeaderRequestID))
	if len(got) != 1 {
		e.t.Fatalf("events: %v", got)
	}
	return rec.Body.String(), got[0]
}

func exportKey(t *testing.T) (*openpgp.Entity, string) {
	t.Helper()
	k, err := openpgp.NewEntity("Requester", "", "requester@example.test", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Serialize(w); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	return k, buf.String()
}

// TestPlatformRecoveryExportAPI (ADR 0052 amendment b decision 8): the platform administrator exports a pending
// organization by its ID; the event lands in that organization's log, a denial included; an unknown organization is
// 404, an organization without a pending deletion 409; an organization administrator may not use the path.
func TestPlatformRecoveryExportAPI(t *testing.T) {
	e := newEnv(t)
	e.exportDevice(e.acme, "active", "key-1")
	e.pendingDeletion(e.acme)
	root := e.platformSession()
	path := func(org uuid.UUID) string {
		return "/api/platform/v1/organizations/" + org.String() + "/recovery-export"
	}

	r := e.do(call{method: "POST", path: path(e.acme), cookie: root, body: exportBody(exportPassphrase)})
	if r.status != http.StatusForbidden || r.problemCode(t) != "step_up_required" {
		t.Fatalf("without a step-up: %d %s", r.status, r.body)
	}
	if org, _, _ := e.exportEvent(r); org != e.acme {
		t.Fatalf("denial recorded in %s", org)
	}
	r = e.do(call{method: "POST", path: path(e.acme), cookie: e.steppedUp(root, time.Now()), body: exportBody(exportPassphrase)})
	if r.status != http.StatusOK {
		t.Fatalf("export: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "organization.recovery_exported:success:")
	org, actor, p := e.exportEvent(r)
	if org != e.acme || actor != string(audit.ActorPlatformAdmin) || p["requester_scope"] != "platform" || p["devices"] != float64(1) {
		t.Fatalf("event: %s %s %v", org, actor, p)
	}
	if lines := readExport(t, r.body, nil); len(lines) != 2 {
		t.Fatalf("lines: %v", lines)
	}

	unknown := uuid.New()
	r = e.do(call{method: "POST", path: path(unknown), cookie: e.steppedUp(root, time.Now()), body: exportBody(exportPassphrase)})
	if r.status != http.StatusNotFound || r.problemCode(t) != "not_found" {
		t.Fatalf("unknown organization: %d %s", r.status, r.body)
	}
	if org, _, _ := e.exportEvent(r); org != audit.PlatformOrganizationID {
		t.Fatalf("unknown organization's event in %s", org)
	}
	r = e.do(call{method: "POST", path: path(e.globex), cookie: e.steppedUp(root, time.Now()), body: exportBody(exportPassphrase)})
	if r.status != http.StatusConflict || r.problemCode(t) != "invalid_state" {
		t.Fatalf("not pending: %d %s", r.status, r.body)
	}
	if org, _, _ := e.exportEvent(r); org != e.globex {
		t.Fatalf("not pending event in %s", org)
	}

	alice := e.steppedUp(e.session(e.acme, principal.RoleOrgAdmin), time.Now())
	r = e.do(call{method: "POST", path: path(e.acme), cookie: alice, body: exportBody(exportPassphrase)})
	if r.status != http.StatusForbidden {
		t.Fatalf("organization administrator on the platform path: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "organization.recovery_exported:denied:forbidden")

	// Plan M17 amendment g point 5: provisioning_failed with delete_after set is pending as well.
	if _, err := e.super.Exec(context.Background(), `UPDATE organization SET status = 'provisioning_failed' WHERE id = $1`, e.globex); err != nil {
		t.Fatal(err)
	}
	e.pendingDeletion(e.globex)
	r = e.do(call{method: "POST", path: path(e.globex), cookie: e.steppedUp(root, time.Now()), body: exportBody(exportPassphrase)})
	if r.status != http.StatusOK {
		t.Fatalf("provisioning_failed with a pending deletion: %d %s", r.status, r.body)
	}

	// Plan M17 amendment g point 6: an organization the worker moved to deleting is refused with 403
	// organization_inactive, recorded as organization.inactive_denied in the platform pseudo-organization only.
	if _, err := e.super.Exec(context.Background(), `UPDATE organization SET status = 'deleting' WHERE id = $1`, e.acme); err != nil {
		t.Fatal(err)
	}
	r = e.do(call{method: "POST", path: path(e.acme), cookie: e.steppedUp(root, time.Now()), body: exportBody(exportPassphrase)})
	if r.status != http.StatusForbidden || r.problemCode(t) != "organization_inactive" || r.header.Get("Content-Type") == "application/pgp-encrypted" {
		t.Fatalf("deleting: %d %s", r.status, r.body)
	}
	var deniedIn uuid.UUID
	var params []byte
	if err := e.super.QueryRow(context.Background(), `SELECT organization_id, params FROM action WHERE correlation_id = $1
		AND code = 'organization.inactive_denied' AND outcome = 'denied'`, r.header.Get(httpx.HeaderRequestID)).Scan(&deniedIn, &params); err != nil ||
		deniedIn != audit.PlatformOrganizationID || !strings.Contains(string(params), "organization.recovery_exported") ||
		!strings.Contains(string(params), "deleting") {
		t.Fatalf("inactive_denied: %s %s %v", deniedIn, params, err)
	}
	if got := e.events(r.header.Get(httpx.HeaderRequestID)); len(got) != 1 {
		t.Fatalf("events of the refused export: %v", got)
	}
}

// setDeleteAfter moves the pending deletion of org to now() plus d on the database's clock.
func (e *env) setDeleteAfter(org uuid.UUID, d time.Duration) {
	e.t.Helper()
	if _, err := e.super.Exec(context.Background(), `UPDATE organization SET delete_after = now() + make_interval(secs => $2)
		WHERE id = $1`, org, d.Seconds()); err != nil {
		e.t.Fatal(err)
	}
}

// TestRecoveryExportCutoff (plan M17 amendment h points 1 and 3): the export closes 20 minutes before delete_after on
// the database's clock, and the API names that time.
func TestRecoveryExportCutoff(t *testing.T) {
	e := newEnv(t)
	e.exportDevice(e.acme, "active", "key-1")
	e.pendingDeletion(e.acme)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	root := e.platformSession()
	for _, tc := range []struct {
		name   string
		cookie func() *http.Cookie
		path   string
	}{
		{"organization", func() *http.Cookie { return e.steppedUp(alice, time.Now()) }, "/api/v1/recovery-export"},
		{"platform", func() *http.Cookie { return e.steppedUp(root, time.Now()) },
			"/api/platform/v1/organizations/" + e.acme.String() + "/recovery-export"},
	} {
		e.setDeleteAfter(e.acme, 19*time.Minute)
		r := e.do(call{method: "POST", path: tc.path, cookie: tc.cookie(), body: exportBody(exportPassphrase)})
		var p httpx.Problem
		r.decode(t, &p)
		if r.status != http.StatusConflict || p.Code != "invalid_state" || !strings.Contains(p.Detail, "20 minutes") {
			t.Fatalf("%s at 19 minutes: %d %s", tc.name, r.status, r.body)
		}
		e.expectEvent(r, "organization.recovery_exported:failure:invalid_state")
		e.setDeleteAfter(e.acme, 21*time.Minute)
		if r := e.do(call{method: "POST", path: tc.path, cookie: tc.cookie(), body: exportBody(exportPassphrase)}); r.status != http.StatusOK {
			t.Fatalf("%s at 21 minutes: %d %s", tc.name, r.status, r.body)
		}
	}

	var me adminapi.Me
	e.do(call{method: "GET", path: "/api/v1/me", cookie: alice}).decode(t, &me)
	var deleteAfter time.Time
	if err := e.super.QueryRow(context.Background(), "SELECT delete_after FROM organization WHERE id = $1", e.acme).Scan(&deleteAfter); err != nil {
		t.Fatal(err)
	}
	if me.OrganizationDeletion == nil || !me.OrganizationDeletion.RecoveryExportUntil.Equal(deleteAfter.Add(-20*time.Minute)) {
		t.Fatalf("me: %+v, delete_after %s", me.OrganizationDeletion, deleteAfter)
	}
}

// TestPlatformExportOutlivesPending (plan M17 amendment h point 2): when the organization becomes deleting while an
// export streams, the platform path writes no action or outbox row into it through the platform pool; the download is
// cut off and the started action stays for the deletion to remove.
func TestPlatformExportOutlivesPending(t *testing.T) {
	e := newEnv(t)
	e.exportDevice(e.acme, "active", "key-1")
	e.pendingDeletion(e.acme)
	e.disk.onBatch = func() {
		if _, err := e.super.Exec(context.Background(), `UPDATE organization SET status = 'deleting' WHERE id = $1`, e.acme); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { e.disk.onBatch = nil })
	root := e.steppedUp(e.platformSession(), time.Now())
	body, _ := json.Marshal(exportBody(exportPassphrase))
	req := httptest.NewRequest(http.MethodPost, "https://admin.test/api/platform/v1/organizations/"+e.acme.String()+"/recovery-export",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Paddock-CSRF", "1")
	req.AddCookie(root)
	rec := httptest.NewRecorder()
	func() {
		defer func() {
			if v := recover(); v == nil || !errors.Is(v.(error), http.ErrAbortHandler) {
				t.Fatalf("the export was not cut off: %v", v)
			}
		}()
		e.handler.ServeHTTP(rec, req)
	}()
	if strings.Contains(rec.Body.String(), "END PGP MESSAGE") {
		t.Fatal("a complete message reached the client")
	}
	var finished, outbox int
	if err := e.super.QueryRow(context.Background(), `SELECT count(*) FILTER (WHERE status = 'finished') FROM action
		WHERE organization_id = $1 AND correlation_id = $2`, e.acme, rec.Header().Get(httpx.HeaderRequestID)).Scan(&finished); err != nil {
		t.Fatal(err)
	}
	if err := e.super.QueryRow(context.Background(), `SELECT count(*) FROM outbox WHERE organization_id = $1 AND created_at > now() - interval '1 minute'`,
		e.acme).Scan(&outbox); err != nil {
		t.Fatal(err)
	}
	if finished != 0 || outbox != 0 {
		t.Fatalf("rows written into the deleting organization: %d finished actions, %d outbox rows", finished, outbox)
	}
}

// TestPlatformExportRacesGate (review 2 finding 6): the worker commits deleting while the export's first transaction
// waits in paddock_org_enter: 403 organization_inactive, no export bytes, exactly one organization.inactive_denied in
// the platform pseudo-organization.
func TestPlatformExportRacesGate(t *testing.T) {
	e := newEnv(t)
	e.exportDevice(e.acme, "active", "key-1")
	e.pendingDeletion(e.acme)
	root := e.steppedUp(e.platformSession(), time.Now())
	ctx := context.Background()
	worker, err := pgx.Connect(ctx, pgtest.SharedPaddock(t).Super)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = worker.Close(ctx) }()
	tx, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", db.OffboardingLockKey(e.acme)); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(exportBody(exportPassphrase))
	req := httptest.NewRequest(http.MethodPost, "https://admin.test/api/platform/v1/organizations/"+e.acme.String()+"/recovery-export",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Paddock-CSRF", "1")
	req.AddCookie(root)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.handler.ServeHTTP(rec, req)
	}()
	waiter, err := pgx.Connect(ctx, pgtest.SharedPaddock(t).Super)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = waiter.Close(ctx) }()
	for waited := 0; ; waited++ {
		var waiting bool
		if err := waiter.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND NOT granted)`).
			Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if waited > 500 {
			t.Fatal("the export never waited in the gate")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := tx.Exec(ctx, "UPDATE organization SET status = 'deleting' WHERE id = $1", e.acme); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	<-done
	var p httpx.Problem
	if rec.Code != http.StatusForbidden || json.Unmarshal(rec.Body.Bytes(), &p) != nil || p.Code != "organization_inactive" ||
		rec.Header().Get("Content-Type") == "application/pgp-encrypted" {
		t.Fatalf("race through the gate: %d %s", rec.Code, rec.Body.String())
	}
	got := e.events(rec.Header().Get(httpx.HeaderRequestID))
	var org uuid.UUID
	if err := e.super.QueryRow(ctx, `SELECT organization_id FROM action WHERE correlation_id = $1`,
		rec.Header().Get(httpx.HeaderRequestID)).Scan(&org); err != nil || len(got) != 1 ||
		got[0] != "organization.inactive_denied:denied:organization_inactive" || org != audit.PlatformOrganizationID {
		t.Fatalf("events %v in %s (%v)", got, org, err)
	}
}
