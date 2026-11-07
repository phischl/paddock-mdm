package admin_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// DeleteAllVersions deletes the objects below prefix, as the versioned escrow bucket deletes every version.
func (d *diskEscrow) DeleteAllVersions(_ context.Context, prefix string) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for k := range d.objects {
		if strings.HasPrefix(k, prefix) {
			delete(d.objects, k)
			n++
		}
	}
	return n, nil
}

// storedDiagnostics seals archive as the agent does and stores it as a verified bundle of the device, with its data key
// wrapped to the escrow-wrap key of the test and no key version (an agent before PDK-749: unwrapped with version 1).
// It returns the bundle's ID and its object key.
func (e *env) storedDiagnostics(org, device uuid.UUID, archive []byte) (uuid.UUID, string) {
	e.t.Helper()
	id := uuid.Must(uuid.NewV7())
	dek := make([]byte, 32)
	_, _ = rand.Read(dek)
	sealed, nonce, err := escrow.SealObject(dek, id.String(), bytes.NewReader(archive))
	if err != nil {
		e.t.Fatal(err)
	}
	ct, err := escrow.Encrypt(&e.disk.key.PublicKey, dek)
	if err != nil {
		e.t.Fatal(err)
	}
	wrapped, _ := base64.StdEncoding.DecodeString(ct)
	key := escrow.DiagnosticsObjectKey(org.String(), device.String(), id.String())
	e.disk.mu.Lock()
	e.disk.objects[key] = sealed
	e.disk.mu.Unlock()
	sum := sha256.Sum256(sealed)
	e.exec(`INSERT INTO device_diagnostics (id, organization_id, device_id, requested_by, reason, state, object_key, size,
		sha256, nonce, wrapped_dek, files, notified_sessions, uploaded_at, stored_at, expires_at)
		VALUES ($1, $2, $3, 'alice', 'VPN fails', 'stored', $4, $5, $6, $7, $8, 41, 1, now(), now(), now() + interval '7 days')`,
		id, org, device, key, len(sealed), hex.EncodeToString(sum[:]), nonce, wrapped)
	// The database is shared: a stored bundle left behind would be due in other packages' retention rounds.
	e.t.Cleanup(func() { _, _ = e.super.Exec(context.Background(), "DELETE FROM device_diagnostics WHERE id = $1", id) })
	return id, key
}

// TestDiagnosticsEndpoints (plan M12 decisions 13 and 14, ADR 0048 decision 4) through the contract: operators request,
// list and read bundles; a download needs a fresh step-up and serves the decrypted archive as application/gzip with
// its file name; the purge is the administrator's; org_auditor gets 403 on every endpoint; an API token requests and
// lists but never downloads.
func TestDiagnosticsEndpoints(t *testing.T) {
	e := newEnv(t)
	device := e.insertDevice(e.acme, "diag-host", "active")
	operator := e.session(e.acme, principal.RoleOrgOperator)
	admin := e.session(e.acme, principal.RoleOrgAdmin)
	auditor := e.session(e.acme, principal.RoleOrgAuditor)
	archive := []byte("\x1f\x8b fixture diagnostics archive")
	stored, key := e.storedDiagnostics(e.acme, device, archive)
	deviceDiagnostics := "/api/v1/devices/" + device.String() + "/diagnostics"
	download := "/api/v1/diagnostics/" + stored.String() + "/download"
	purge := "/api/v1/diagnostics/" + stored.String() + "/purge"

	requested := e.do(call{method: "POST", path: deviceDiagnostics, cookie: operator, body: map[string]any{"reason": "VPN fails since Monday"}})
	if requested.status != http.StatusAccepted {
		t.Fatalf("request: %d %s", requested.status, requested.body)
	}
	e.expectEvent(requested, "device.diagnostics_requested:success:")
	var b adminapi.Diagnostics
	requested.decode(t, &b)
	if b.State != adminapi.DiagnosticsStateRequested || b.Hostname != "diag-host" || b.Reason != "VPN fails since Monday" {
		t.Fatalf("requested %+v", b)
	}
	t.Cleanup(func() {
		_, _ = e.super.Exec(context.Background(), "DELETE FROM device_diagnostics WHERE id = $1", b.Id)
	})

	var page adminapi.DiagnosticsPage
	if r := e.do(call{method: "GET", path: deviceDiagnostics + "?state=stored", cookie: operator}); r.status != http.StatusOK {
		t.Fatalf("device list: %d %s", r.status, r.body)
	} else if r.decode(t, &page); page.Total != 1 || page.Items[0].Id != stored || page.Items[0].DownloadCount != 0 {
		t.Fatalf("device list %+v", page)
	}
	if r := e.do(call{method: "GET", path: "/api/v1/diagnostics?q=diag-ho&sort=hostname", cookie: admin}); r.status != http.StatusOK {
		t.Fatalf("list: %d %s", r.status, r.body)
	} else if r.decode(t, &page); page.Total != 2 {
		t.Fatalf("list %+v", page)
	}
	if r := e.do(call{method: "GET", path: "/api/v1/diagnostics/" + stored.String(), cookie: operator}); r.status != http.StatusOK {
		t.Fatalf("get: %d %s", r.status, r.body)
	}

	for _, c := range []call{
		{method: "POST", path: deviceDiagnostics, body: map[string]any{"reason": "auditor"}},
		{method: "GET", path: deviceDiagnostics},
		{method: "GET", path: "/api/v1/diagnostics"},
		{method: "GET", path: "/api/v1/diagnostics/" + stored.String()},
		{method: "GET", path: download},
		{method: "POST", path: purge},
	} {
		c.cookie = auditor
		if c.path == download {
			c.cookie = e.steppedUp(auditor, time.Now())
		}
		if r := e.do(c); r.status != http.StatusForbidden {
			t.Fatalf("auditor %s %s: %d %s", c.method, c.path, r.status, r.body)
		}
	}

	r := e.do(call{method: "GET", path: download, cookie: operator})
	if r.status != http.StatusForbidden || r.problemCode(t) != "step_up_required" {
		t.Fatalf("download without step-up: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "device.diagnostics_downloaded:denied:step_up_required")

	r = e.do(call{method: "GET", path: download, cookie: e.steppedUp(operator, time.Now())})
	if r.status != http.StatusOK || !bytes.Equal(r.body, archive) || r.header.Get("Content-Type") != "application/gzip" ||
		r.header.Get("Content-Disposition") != `attachment; filename=paddock-diagnostics-diag-host-`+stored.String()+`.tar.gz` {
		t.Fatalf("download: %d %v %q", r.status, r.header, r.body)
	}
	e.expectEvent(r, "device.diagnostics_downloaded:success:")
	if got := e.count("SELECT download_count FROM device_diagnostics WHERE id = $1", stored); got != 1 {
		t.Fatalf("download_count %d", got)
	}

	// HEAD would run the download for a body that is never sent; the contract has no HEAD operation.
	req := httptest.NewRequest(http.MethodHead, "https://admin.test"+download, nil)
	req.AddCookie(e.steppedUp(operator, time.Now()))
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET" || bytes.Contains(rec.Body.Bytes(), archive) {
		t.Fatalf("HEAD download: %d %v", rec.Code, rec.Header())
	}

	token := e.createAPIToken("acme", admin, "ci", adminapi.ApiTokenRoleOrgOperator)
	if r := e.do(call{method: "GET", path: "/api/v1/diagnostics", headers: bearer(token.Secret)}); r.status != http.StatusOK {
		t.Fatalf("token list: %d %s", r.status, r.body)
	}
	if r := e.do(call{method: "GET", path: download, headers: bearer(token.Secret)}); r.status != http.StatusForbidden ||
		r.problemCode(t) != "step_up_required" {
		t.Fatalf("token download: %d %s", r.status, r.body)
	}

	if r := e.do(call{method: "POST", path: purge, cookie: operator}); r.status != http.StatusForbidden {
		t.Fatalf("operator purge: %d %s", r.status, r.body)
	}
	r = e.do(call{method: "POST", path: purge, cookie: admin})
	if r.status != http.StatusOK {
		t.Fatalf("purge: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "device.diagnostics_purged:success:")
	r.decode(t, &b)
	e.disk.mu.Lock()
	_, present := e.disk.objects[key]
	e.disk.mu.Unlock()
	if b.State != adminapi.DiagnosticsStatePurged || present {
		t.Fatalf("purged %s, object present %v", b.State, present)
	}
	r = e.do(call{method: "GET", path: download, cookie: e.steppedUp(admin, time.Now())})
	if r.status != http.StatusConflict || r.problemCode(t) != "invalid_state" {
		t.Fatalf("download after purge: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "device.diagnostics_downloaded:failure:invalid_state")

	globex := e.session(e.globex, principal.RoleOrgAdmin)
	if r := e.do(call{method: "GET", path: "/api/v1/diagnostics/" + stored.String(), cookie: globex}); r.status != http.StatusNotFound {
		t.Fatalf("another organization: %d %s", r.status, r.body)
	}
	if r := e.do(call{method: "POST", path: deviceDiagnostics, cookie: globex, body: map[string]any{"reason": "foreign"}}); r.status != http.StatusNotFound {
		t.Fatalf("another organization's device: %d %s", r.status, r.body)
	}
}

// TestDiagnosticsDownloadRefusesReplacedObject (PDK-747 review finding 5): an object replaced by a blob of the same
// size after the bundle was stored is refused with 409, nothing is served and the download is recorded as a failure.
func TestDiagnosticsDownloadRefusesReplacedObject(t *testing.T) {
	e := newEnv(t)
	device := e.insertDevice(e.acme, "diag-swap", "active")
	archive := []byte("fixture diagnostics archive")
	id, key := e.storedDiagnostics(e.acme, device, archive)
	e.disk.mu.Lock()
	e.disk.objects[key] = bytes.Repeat([]byte{0x42}, len(e.disk.objects[key]))
	e.disk.mu.Unlock()
	r := e.do(call{method: "GET", path: "/api/v1/diagnostics/" + id.String() + "/download",
		cookie: e.steppedUp(e.session(e.acme, principal.RoleOrgAdmin), time.Now())})
	if r.status != http.StatusConflict || r.problemCode(t) != "invalid_state" || bytes.Contains(r.body, archive) {
		t.Fatalf("replaced object: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "device.diagnostics_downloaded:failure:invalid_state")
	if got := e.count("SELECT download_count FROM device_diagnostics WHERE id = $1", id); got != 0 {
		t.Fatalf("download_count %d", got)
	}
}
