package admin_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// sealDay stores a manifest of org for day, as the audit writer's seal does.
func sealDay(t *testing.T, e *env, id uuid.UUID, day time.Time) {
	t.Helper()
	err := e.writer.InWriter(context.Background(), func(ctx context.Context, q *auditstore.Queries) error {
		return q.InsertAuditManifest(ctx, auditstore.InsertAuditManifestParams{
			OrganizationID: id, Day: day, Sha256: make([]byte, 32), Signature: "vault:v1:x", KeyVersion: 1,
			ObjectKey: "org/" + id.String() + "/manifests/" + day.Format(time.DateOnly) + ".json",
		})
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAuditExportsAPI(t *testing.T) {
	e := newEnv(t)
	day := time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -1)
	sealDay(t, e, e.acme, day)
	sealDay(t, e, e.globex, day)
	auditor := e.steppedUp(e.session(e.acme, principal.RoleOrgAuditor), time.Now())
	body := map[string]any{"from_day": day.Format(time.DateOnly), "to_day": day.Format(time.DateOnly), "purpose": "ISO 27001 surveillance audit"}

	created := e.do(call{method: "POST", path: "/api/v1/audit/exports", cookie: auditor, body: body})
	if created.status != http.StatusAccepted {
		t.Fatalf("create: %d %s", created.status, created.body)
	}
	e.expectEvent(created, "audit.export_requested:success:")
	var ex adminapi.AuditExport
	created.decode(t, &ex)
	if ex.Status != adminapi.AuditExportStatusPending || ex.RequestedBy.Ip != nil || !ex.RequestedBy.StepUp ||
		ex.RequestedBy.Display == nil || *ex.RequestedBy.Display != "org_auditor@test" || ex.ReadyAt != nil ||
		len(ex.VerifyProblems) != 0 || strings.Contains(string(created.body), `"ip"`) {
		t.Fatalf("created export: %s", created.body)
	}

	got := e.do(call{method: "GET", path: "/api/v1/audit/exports/" + ex.Id.String(), cookie: e.session(e.acme, principal.RoleOrgAdmin)})
	if got.status != http.StatusOK {
		t.Fatalf("get as admin: %d %s", got.status, got.body)
	}

	// Another organization's auditor gets not_found for acme's export and sees none of acme's exports.
	carol := e.steppedUp(e.session(e.globex, principal.RoleOrgAuditor), time.Now())
	foreign := e.do(call{method: "GET", path: "/api/v1/audit/exports/" + ex.Id.String(), cookie: carol})
	if foreign.status != http.StatusNotFound || foreign.problemCode(t) != "not_found" {
		t.Fatalf("globex get of acme's export: %d %s", foreign.status, foreign.body)
	}
	if r := e.do(call{method: "POST", path: "/api/v1/audit/exports", cookie: carol, body: body}); r.status != http.StatusAccepted {
		t.Fatalf("globex create: %d %s", r.status, r.body)
	}
	var page adminapi.AuditExportPage
	r := e.do(call{method: "GET", path: "/api/v1/audit/exports", cookie: carol})
	r.decode(t, &page)
	if r.status != http.StatusOK || page.Total != 1 || len(page.Items) != 1 || page.Items[0].Id == ex.Id || page.Sort != "-requested_at" {
		t.Fatalf("globex list: %d %s", r.status, r.body)
	}

	for _, c := range []struct {
		query string
		total int
	}{
		{"?status=pending", 1},
		{"?status=ready&status=failed", 0},
		{"?q=surveillance", 1},
		{"?q=org_auditor", 1},
		{"?q=nothing-matches", 0},
		{"?sort=to_day&page_size=10", 1},
	} {
		r := e.do(call{method: "GET", path: "/api/v1/audit/exports" + c.query, cookie: auditor})
		page = adminapi.AuditExportPage{}
		r.decode(t, &page)
		if r.status != http.StatusOK || page.Total != c.total || len(page.Items) != c.total {
			t.Fatalf("list %s: %d %s", c.query, r.status, r.body)
		}
	}
	if r := e.do(call{method: "GET", path: "/api/v1/audit/exports?sort=purpose", cookie: auditor, skipReqCheck: true}); r.status != http.StatusBadRequest {
		t.Fatalf("unknown sort: %d %s", r.status, r.body)
	}
}

func TestAuditExportsRefusals(t *testing.T) {
	e := newEnv(t)
	day := time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -1)
	sealDay(t, e, e.acme, day)
	valid := map[string]any{"from_day": day.Format(time.DateOnly), "to_day": day.Format(time.DateOnly), "purpose": "audit"}
	auditor := e.steppedUp(e.session(e.acme, principal.RoleOrgAuditor), time.Now())
	operator := e.steppedUp(e.session(e.acme, principal.RoleOrgOperator), time.Now())

	for _, c := range []struct {
		name   string
		cookie *http.Cookie
		body   map[string]any
		status int
		event  string
		skip   bool
	}{
		{"no step-up", e.session(e.acme, principal.RoleOrgAuditor), valid, http.StatusForbidden, "audit.export_requested:denied:step_up_required", false},
		{"operator", operator, valid, http.StatusForbidden, "audit.export_requested:denied:forbidden", false},
		{"to_day not sealed", auditor, map[string]any{"from_day": day.Format(time.DateOnly), "to_day": day.AddDate(0, 0, 1).Format(time.DateOnly), "purpose": "audit"},
			http.StatusUnprocessableEntity, "audit.export_requested:failure:day_not_sealed", false},
		{"401 days", auditor, map[string]any{"from_day": day.AddDate(0, 0, -401).Format(time.DateOnly), "to_day": day.Format(time.DateOnly), "purpose": "audit"},
			http.StatusBadRequest, "audit.export_requested:failure:range_too_large", false},
		{"empty purpose", auditor, map[string]any{"from_day": day.Format(time.DateOnly), "to_day": day.Format(time.DateOnly), "purpose": ""},
			http.StatusBadRequest, "audit.export_requested:failure:invalid_request", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := e.do(call{method: "POST", path: "/api/v1/audit/exports", cookie: c.cookie, body: c.body, skipReqCheck: c.skip})
			if r.status != c.status {
				t.Fatalf("status %d %s, want %d", r.status, r.body, c.status)
			}
			e.expectEvent(r, c.event)
		})
	}

	for range 2 {
		if r := e.do(call{method: "POST", path: "/api/v1/audit/exports", cookie: auditor, body: valid}); r.status != http.StatusAccepted {
			t.Fatalf("create: %d %s", r.status, r.body)
		}
	}
	third := e.do(call{method: "POST", path: "/api/v1/audit/exports", cookie: auditor, body: valid})
	if third.status != http.StatusConflict || third.problemCode(t) != "too_many_exports" {
		t.Fatalf("third open export: %d %s", third.status, third.body)
	}
	e.expectEvent(third, "audit.export_requested:failure:too_many_exports")

	if r := e.do(call{method: "GET", path: "/api/v1/audit/exports", cookie: operator}); r.status != http.StatusForbidden {
		t.Fatalf("list as operator: %d %s", r.status, r.body)
	}
}

// storeExport inserts an export of org as the audit writer leaves it, with the chunks, as in the use case tests.
func storeExport(t *testing.T, e *env, org uuid.UUID, status string, chunks ...[]byte) (uuid.UUID, string) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, e.writerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	id := uuid.Must(uuid.NewV7())
	sum := sha256.New()
	var size int64
	for _, c := range chunks {
		sum.Write(c)
		size += int64(len(c))
	}
	day := time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -1)
	if _, err := conn.Exec(ctx, `INSERT INTO audit_export (id, organization_id, status, from_day, to_day, purpose, requested_by,
		correlation_id, ready_at, expires_at, size, package_sha256, event_count, object_count, verify_ok)
		VALUES ($1, $2, $3, $4, $4, 'download test', '{}', 'c', now(), now() + interval '1 hour', $5, $6, 1, 1, true)`,
		id, org, status, day, size, sum.Sum(nil)); err != nil {
		t.Fatal(err)
	}
	for seq, c := range chunks {
		if _, err := conn.Exec(ctx, "INSERT INTO audit_export_chunk (export_id, organization_id, seq, data) VALUES ($1, $2, $3, $4)", id, org, seq, c); err != nil {
			t.Fatal(err)
		}
	}
	return id, hex.EncodeToString(sum.Sum(nil))
}

func TestAuditExportDownload(t *testing.T) {
	e := newEnv(t)
	pkg := []byte("tar-bytes-chunk-one|tar-bytes-chunk-two")
	id, sum := storeExport(t, e, e.acme, "ready", pkg[:20], pkg[20:])
	path := "/api/v1/audit/exports/" + id.String() + "/download"

	// Both roles of decision 35 download without a step-up; the response carries the package metadata.
	for _, role := range []principal.Role{principal.RoleOrgAuditor, principal.RoleOrgAdmin} {
		r := e.do(call{method: "GET", path: path, cookie: e.session(e.acme, role)})
		if r.status != http.StatusOK || !bytes.Equal(r.body, pkg) {
			t.Fatalf("%s: %d %q", role, r.status, r.body)
		}
		got := sha256.Sum256(r.body)
		if r.header.Get("Content-Type") != "application/x-tar" || r.header.Get("Content-Length") != strconv.Itoa(len(pkg)) ||
			r.header.Get("X-Paddock-Package-SHA256") != sum || hex.EncodeToString(got[:]) != sum {
			t.Fatalf("%s headers %v", role, r.header)
		}
		cd := r.header.Get("Content-Disposition")
		if !strings.HasPrefix(cd, `attachment; filename="paddock-audit-export-acme-`) || !strings.HasSuffix(cd, "-"+id.String()[:8]+`.tar"`) {
			t.Fatalf("%s Content-Disposition %q", role, cd)
		}
		e.expectEvent(r, "audit.export_downloaded:success:")
	}

	// Another organization's auditor and an operator get no package; each attempt is one event.
	carol := e.do(call{method: "GET", path: path, cookie: e.session(e.globex, principal.RoleOrgAuditor)})
	if carol.status != http.StatusNotFound || carol.problemCode(t) != "not_found" || bytes.Contains(carol.body, pkg) {
		t.Fatalf("globex download: %d %s", carol.status, carol.body)
	}
	e.expectEvent(carol, "audit.export_downloaded:failure:not_found")
	op := e.do(call{method: "GET", path: path, cookie: e.session(e.acme, principal.RoleOrgOperator)})
	if op.status != http.StatusForbidden {
		t.Fatalf("operator download: %d %s", op.status, op.body)
	}
	e.expectEvent(op, "audit.export_downloaded:denied:forbidden")

	// HEAD would run the download for a body that is never sent; it is refused before the use case, as one event. The
	// contract has no HEAD operation, so the request bypasses e.do's contract check.
	req := httptest.NewRequest(http.MethodHead, "https://admin.test"+path, nil)
	req.AddCookie(e.session(e.acme, principal.RoleOrgAuditor))
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	head := result{status: rec.Code, header: rec.Header(), body: rec.Body.Bytes()}
	if head.status != http.StatusMethodNotAllowed || head.header.Get("Allow") != "GET" || bytes.Contains(head.body, pkg) {
		t.Fatalf("HEAD download: %d %v %s", head.status, head.header, head.body)
	}
	e.expectEvent(head, "audit.export_downloaded:failure:invalid_request")

	for _, status := range []string{"pending", "failed", "expired"} {
		notReady, _ := storeExport(t, e, e.acme, status, pkg)
		r := e.do(call{method: "GET", path: "/api/v1/audit/exports/" + notReady.String() + "/download", cookie: e.session(e.acme, principal.RoleOrgAuditor)})
		if r.status != http.StatusConflict || r.problemCode(t) != "export_not_ready" || bytes.Contains(r.body, pkg) {
			t.Fatalf("%s download: %d %s", status, r.status, r.body)
		}
		e.expectEvent(r, "audit.export_downloaded:failure:export_not_ready")
	}
}
