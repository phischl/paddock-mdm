package admin_test

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/auditevidence"
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

func TestAuditEvidenceKeys(t *testing.T) {
	e := newEnv(t)
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i + 1)
	}
	const version = 7001
	err := e.writer.InWriter(context.Background(), func(ctx context.Context, q *auditstore.Queries) error {
		return q.EnsureAuditSigningKey(ctx, auditstore.EnsureAuditSigningKeyParams{KeyVersion: version, PublicKey: pub})
	})
	if err != nil {
		t.Fatal(err)
	}
	want := auditevidence.Fingerprint(pub)

	// The key is not organization data: auditors and admins of every organization read the same list.
	for _, c := range []struct {
		org  uuid.UUID
		role principal.Role
	}{{e.acme, principal.RoleOrgAuditor}, {e.acme, principal.RoleOrgAdmin}, {e.globex, principal.RoleOrgAuditor}} {
		r := e.do(call{method: "GET", path: "/api/v1/audit/keys", cookie: e.session(c.org, c.role)})
		var got adminapi.AuditEvidenceKeys
		r.decode(t, &got)
		if r.status != http.StatusOK {
			t.Fatalf("%s: %d %s", c.role, r.status, r.body)
		}
		var found bool
		for i, k := range got.Keys {
			if i > 0 && got.Keys[i-1].KeyVersion >= k.KeyVersion {
				t.Fatalf("keys not in version order: %s", r.body)
			}
			if k.KeyVersion == version {
				found = k.Fingerprint == want && bytes.Equal(k.PublicKey, pub) && !k.FirstSeenAt.IsZero()
			}
		}
		if !found {
			t.Fatalf("%s: key v%d with fingerprint %s missing: %s", c.role, version, want, r.body)
		}
	}

	for _, role := range []principal.Role{principal.RoleOrgOperator} {
		if r := e.do(call{method: "GET", path: "/api/v1/audit/keys", cookie: e.session(e.acme, role)}); r.status != http.StatusForbidden {
			t.Fatalf("%s: %d %s, want 403", role, r.status, r.body)
		}
	}
	if r := e.do(call{method: "GET", path: "/api/v1/audit/keys", skipReqCheck: true}); r.status != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d %s, want 401", r.status, r.body)
	}
}
