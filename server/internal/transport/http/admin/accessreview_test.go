package admin_test

import (
	"context"
	"encoding/csv"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// reviewEvent is one row of the audit index the report reads.
type reviewEvent struct {
	org     uuid.UUID
	code    string
	outcome string
	actor   string
	target  string
	params  string
	at      time.Time
}

func (e *env) seedReviewEvents(events ...reviewEvent) {
	e.t.Helper()
	now := time.Now().UTC()
	err := e.writer.InWriter(context.Background(), func(ctx context.Context, q *auditstore.Queries) error {
		for _, ev := range events {
			if err := q.EnsureAuditPartition(ctx, ev.at); err != nil {
				return err
			}
			if ev.outcome == "" {
				ev.outcome = "success"
			}
			if ev.actor == "" {
				ev.actor = `{"type":"admin","display":"alice","step_up":false}`
			}
			if ev.target == "" {
				ev.target = `{"type":"device","id":"d","display":"ws-1"}`
			}
			if ev.params == "" {
				ev.params = `{}`
			}
			_, err := q.InsertAuditEvent(ctx, auditstore.InsertAuditEventParams{
				EventID: uuid.Must(uuid.NewV7()), OrganizationID: ev.org, OccurredAt: ev.at, RecordedAt: now, Code: ev.code,
				Outcome: ev.outcome, Source: "portal", Actor: []byte(ev.actor), Target: []byte(ev.target), Params: []byte(ev.params),
				CorrelationID: "c", ObjectKey: "k",
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) exec(sql string, args ...any) {
	e.t.Helper()
	if _, err := e.super.Exec(context.Background(), sql, args...); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) count(sql string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.super.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

// TestAccessReview (plan M12 decisions 24 to 26): the report lists the organization's role members, role changes, API
// tokens, reveals, step-ups and destructive actions and nothing of another organization; operators are refused; the
// period is bounded; the view is recorded once per actor and UTC day while audit_search_recorded is on; every export
// is recorded; the CSV carries every row, neutralizes formulas and names its file safely.
func TestAccessReview(t *testing.T) {
	e := newEnv(t)
	org, other := e.org("review"), e.org("foreign")
	admin := e.session(org, principal.RoleOrgAdmin)
	auditor := e.session(org, principal.RoleOrgAuditor)
	operator := e.session(org, principal.RoleOrgOperator)
	now := time.Now().UTC()
	hour := now.Add(-time.Hour)

	e.session(other, principal.RoleOrgAdmin)
	e.exec(`INSERT INTO organization_role_member (organization_id, role, authentik_pk, username, first_seen_at) VALUES
		($1, 'org_admin', '1', 'amy', $3), ($1, 'org_auditor', '2', '=HYPERLINK("http://evil")', $3),
		($2, 'org_admin', '9', 'foreign-member', $3)`, org, other, hour)
	e.exec(`INSERT INTO organization_role_snapshot (organization_id, role, taken_at) VALUES ($1, 'org_admin', $2)`, org, hour)
	e.exec(`UPDATE organization_login_settings SET break_glass_accounts = ARRAY['root-breakglass'] WHERE organization_id = $1`, org)
	var creator uuid.UUID
	if err := e.super.QueryRow(context.Background(), "SELECT id FROM admin_account WHERE organization_id = $1 AND role = 'org_admin'", org).Scan(&creator); err != nil {
		t.Fatal(err)
	}
	secret := func() []byte { return []byte(uuid.NewString()) }
	e.exec(`INSERT INTO api_token (id, organization_id, name, role, secret_sha256, prefix, created_by, created_at, expires_at, revoked_at, revoked_by) VALUES
		($1, $2, 'ci-live', 'org_operator', $6, 'pdk_aaaaaaaa', $3, $4, $5, NULL, NULL),
		($7, $2, 'ci-revoked', 'org_auditor', $8, 'pdk_bbbbbbbb', $3, $4, $5, $4, $3)`,
		uuid.New(), org, creator, now.Add(-48*time.Hour), now.Add(24*time.Hour), secret(), uuid.New(), secret())
	e.exec(`INSERT INTO api_token (id, organization_id, name, role, secret_sha256, prefix, created_by, created_at, expires_at) VALUES
		($1, $2, 'foreign-token', 'org_admin', $5, 'pdk_cccccccc', (SELECT id FROM admin_account WHERE organization_id = $2 LIMIT 1), $3, $4)`,
		uuid.New(), other, now.Add(-48*time.Hour), now.Add(24*time.Hour), secret())

	e.seedReviewEvents(
		reviewEvent{org: org, at: hour, code: "local_admin.revealed", params: `{"hostname":"ws-1","generations":[1],"secret":"x"}`},
		reviewEvent{org: org, at: hour, code: "local_admin.revealed", outcome: "denied"},
		reviewEvent{org: org, at: hour, code: "admin.role_granted", actor: `{"type":"system","display":"worker"}`, params: `{"role":"org_admin","username":"amy","baseline":false}`},
		reviewEvent{org: org, at: hour, code: "admin.role_granted", actor: `{"type":"system","display":"worker"}`, params: `{"role":"org_admin","username":"base","baseline":true}`},
		reviewEvent{org: org, at: hour, code: "device.retired", params: `{"hostname":"ws-9"}`},
		reviewEvent{org: org, at: hour, code: "admin.sessions_revoked", target: `{"type":"admin_account","id":"a","display":"bob"}`, params: `{"reason":"role_changed"}`},
		reviewEvent{org: org, at: hour, code: "api_token.use_denied", outcome: "denied"},
		reviewEvent{org: org, at: hour, code: "api_token.use_denied", outcome: "denied"},
		reviewEvent{org: org, at: hour, code: "device_group.created", actor: `{"type":"admin","display":"alice","step_up":true}`},
		reviewEvent{org: org, at: hour, code: "device_group.deleted", outcome: "denied", params: `{"error_code":"step_up_required"}`},
		reviewEvent{org: org, at: now.AddDate(0, -4, 0), code: "local_admin.revealed"},
		reviewEvent{org: other, at: hour, code: "local_admin.revealed", params: `{"hostname":"foreign-host"}`},
	)

	var report adminapi.AccessReviewReport
	for _, c := range []struct {
		name   string
		cookie *http.Cookie
	}{{"admin", admin}, {"auditor", auditor}} {
		r := e.do(call{method: http.MethodGet, path: "/api/v1/access-review", cookie: c.cookie})
		if r.status != http.StatusOK {
			t.Fatalf("%s: %d %s", c.name, r.status, r.body)
		}
		r.decode(t, &report)
	}
	if report.RowCap != 1000 || report.Period.To.Sub(report.Period.From) != 90*24*time.Hour {
		t.Fatalf("row cap %d, period %v", report.RowCap, report.Period)
	}
	if strings.Contains(string(e.do(call{method: http.MethodGet, path: "/api/v1/access-review", cookie: admin}).body), "foreign") {
		t.Fatal("the report names data of another organization")
	}
	byRole := map[string]adminapi.AccessReviewRoleMembers{}
	for _, r := range report.Roles {
		byRole[r.Role] = r
	}
	if len(report.Roles) != 3 || byRole["org_admin"].Total != 1 || byRole["org_admin"].SnapshotTakenAt == nil ||
		byRole["org_operator"].Total != 0 || byRole["org_operator"].SnapshotTakenAt != nil {
		t.Fatalf("roles: %+v", report.Roles)
	}
	if report.RoleChanges.Total != 1 || report.RoleChanges.Items[0].Username != "amy" {
		t.Fatalf("role changes (baseline excluded): %+v", report.RoleChanges)
	}
	if report.ApiTokens.Total != 2 || report.ApiTokens.Items[0].Name != "ci-revoked" && report.ApiTokens.Items[1].Name != "ci-revoked" ||
		report.TokenDenials != 2 {
		t.Fatalf("tokens %+v, denials %d", report.ApiTokens, report.TokenDenials)
	}
	if report.Reveals.Total != 1 || report.Reveals.Items[0].DeviceHostname != "ws-1" || len(report.Reveals.Items[0].Params) != 1 {
		t.Fatalf("reveals (successes of the period, identifying params only): %+v", report.Reveals)
	}
	if report.StepUp.Succeeded != 1 || report.StepUp.Failed != 1 || report.SessionsRevoked.Total != 1 ||
		report.SessionsRevoked.Items[0].Username != "bob" || report.Destructive.Total != 1 ||
		len(report.BreakGlassAccounts) != 1 || report.Accounts.Total != 3 {
		t.Fatalf("report: %+v", report)
	}

	denied := e.do(call{method: http.MethodGet, path: "/api/v1/access-review", cookie: operator})
	if denied.status != http.StatusForbidden {
		t.Fatalf("operator: %d %s", denied.status, denied.body)
	}
	e.expectEvent(denied, "access_review.viewed:denied:forbidden")
	long := "?from=" + url.QueryEscape(now.Add(-401*24*time.Hour).Format(time.RFC3339)) + "&to=" + url.QueryEscape(now.Format(time.RFC3339))
	if r := e.do(call{method: http.MethodGet, path: "/api/v1/access-review" + long, cookie: admin}); r.status != http.StatusBadRequest || r.problemCode(t) != "invalid_request" {
		t.Fatalf("401 days: %d %s", r.status, r.body)
	}

	viewed := func() int {
		return e.count("SELECT count(*) FROM action WHERE organization_id = $1 AND code = 'access_review.viewed' AND outcome = 'success'", org)
	}
	if n := viewed(); n != 0 {
		t.Fatalf("%d views recorded with the switch off", n)
	}
	e.exec("UPDATE organization_privacy_settings SET audit_search_recorded = true WHERE organization_id = $1", org)
	for range 3 {
		e.do(call{method: http.MethodGet, path: "/api/v1/access-review", cookie: admin})
	}
	if n := viewed(); n != 1 {
		t.Fatalf("%d views recorded for one actor and day, want 1", n)
	}
	e.do(call{method: http.MethodGet, path: "/api/v1/access-review", cookie: auditor})
	if n := viewed(); n != 2 {
		t.Fatalf("%d views recorded for two actors, want 2", n)
	}

	csvRes := e.do(call{method: http.MethodGet, path: "/api/v1/access-review/export?format=csv", cookie: auditor})
	if csvRes.status != http.StatusOK || csvRes.header.Get("Content-Type") != "text/csv" {
		t.Fatalf("csv export: %d %s %s", csvRes.status, csvRes.header.Get("Content-Type"), csvRes.body)
	}
	e.expectEvent(csvRes, "access_review.exported:success:")
	disposition := csvRes.header.Get("Content-Disposition")
	if !regexp.MustCompile(`^attachment; filename="paddock-access-review-review-[0-9a-f]+-\d{4}-\d{2}-\d{2}-\d{4}-\d{2}-\d{2}\.csv"$`).MatchString(disposition) {
		t.Fatalf("Content-Disposition %q", disposition)
	}
	rows, err := csv.NewReader(strings.NewReader(string(csvRes.body))).ReadAll()
	if err != nil {
		t.Fatalf("csv: %v", err)
	}
	if rows[0][0] != "section" {
		t.Fatalf("header %v", rows[0])
	}
	sections := map[string]int{}
	for _, row := range rows[1:] {
		sections[row[0]]++
		for _, cell := range row {
			if cell != "" && strings.ContainsRune("=+-@\t\r", rune(cell[0])) {
				t.Fatalf("cell %q starts with a formula character", cell)
			}
		}
	}
	want := map[string]int{"report": 1, "role_members": 3, "role_changes": 1, "accounts": 3, "api_tokens": 2, "token_denials": 1,
		"step_up_succeeded": 1, "step_up_failed": 1, "reveals": 1, "sessions_revoked": 1, "break_glass_accounts": 1, "destructive": 1}
	for s, n := range want {
		if sections[s] != n {
			t.Errorf("csv section %s has %d rows, want %d (%v)", s, sections[s], n, sections)
		}
	}
	if !strings.Contains(string(csvRes.body), `'=HYPERLINK`) {
		t.Errorf("the formula member is not neutralized:\n%s", csvRes.body)
	}

	jsonRes := e.do(call{method: http.MethodGet, path: "/api/v1/access-review/export?format=json", cookie: admin})
	e.expectEvent(jsonRes, "access_review.exported:success:")
	var exported adminapi.AccessReviewReport
	jsonRes.decode(t, &exported)
	if exported.Accounts.Total != report.Accounts.Total || len(exported.Roles) != 3 || exported.Reveals.Total != 1 {
		t.Fatalf("json export differs from the view: %+v", exported)
	}
	if !strings.HasSuffix(jsonRes.header.Get("Content-Disposition"), `.json"`) {
		t.Fatalf("Content-Disposition %q", jsonRes.header.Get("Content-Disposition"))
	}

	refused := e.do(call{method: http.MethodGet, path: "/api/v1/access-review/export?format=csv", cookie: operator})
	if refused.status != http.StatusForbidden {
		t.Fatalf("operator export: %d", refused.status)
	}
	e.expectEvent(refused, "access_review.exported:denied:forbidden")
	tooLong := e.do(call{method: http.MethodGet, path: "/api/v1/access-review/export?format=csv&" + strings.TrimPrefix(long, "?"), cookie: admin})
	if tooLong.status != http.StatusBadRequest {
		t.Fatalf("export of 401 days: %d", tooLong.status)
	}
	e.expectEvent(tooLong, "access_review.exported:failure:invalid_request")
	badFormat := e.do(call{method: http.MethodGet, path: "/api/v1/access-review/export?format=xml", cookie: admin, skipReqCheck: true})
	if badFormat.status != http.StatusBadRequest {
		t.Fatalf("export as xml: %d %s", badFormat.status, badFormat.body)
	}
	e.expectEvent(badFormat, "access_review.exported:failure:invalid_request")
	if n := e.count("SELECT count(*) FROM action WHERE organization_id = $1 AND code = 'access_review.exported'", org); n != 5 {
		t.Fatalf("%d exports recorded, want 5 (two successes, three refusals)", n)
	}
}

// TestPlatformAccessReview: a platform administrator reads the platform members and administrators; every view and
// export is recorded, whatever the organizations' settings; an organization session is refused and recorded as denied.
func TestPlatformAccessReview(t *testing.T) {
	e := newEnv(t)
	root := e.platformSession()
	org := e.org("plat")
	e.exec(`INSERT INTO platform_role_member (role, authentik_pk, username, first_seen_at) VALUES ('platform_admin', $1, $2, now())`,
		"pk-"+uuid.NewString(), "root-"+uuid.NewString()[:8])
	e.seedReviewEvents(reviewEvent{org: uuid.Nil, at: time.Now().UTC().Add(-time.Hour), code: "platform.sessions_ended",
		actor: `{"type":"platform_admin","display":"root@test"}`})

	var report adminapi.PlatformAccessReviewReport
	r := e.do(call{method: http.MethodGet, path: "/api/platform/v1/access-review", cookie: root})
	if r.status != http.StatusOK {
		t.Fatalf("platform view: %d %s", r.status, r.body)
	}
	r.decode(t, &report)
	e.expectEvent(r, "platform.access_review_viewed:success:")
	if len(report.Roles) != 2 || report.Roles[0].Total < 1 || report.Administrators.Total < 1 || report.Events.Total < 1 || report.OrganizationsCreated.Total < 1 {
		t.Fatalf("platform report: %+v", report)
	}
	e.expectEvent(e.do(call{method: http.MethodGet, path: "/api/platform/v1/access-review", cookie: root}), "platform.access_review_viewed:success:")

	for _, format := range []string{"csv", "json"} {
		x := e.do(call{method: http.MethodGet, path: "/api/platform/v1/access-review/export?format=" + format, cookie: root})
		if x.status != http.StatusOK || !strings.Contains(x.header.Get("Content-Disposition"), "paddock-access-review-platform-") {
			t.Fatalf("platform %s export: %d %q", format, x.status, x.header.Get("Content-Disposition"))
		}
		e.expectEvent(x, "platform.access_review_exported:success:")
	}

	for _, role := range []principal.Role{principal.RoleOrgAdmin, principal.RoleOrgAuditor} {
		denied := e.do(call{method: http.MethodGet, path: "/api/platform/v1/access-review", cookie: e.session(org, role)})
		if denied.status != http.StatusForbidden {
			t.Fatalf("%s session: %d %s", role, denied.status, denied.body)
		}
		e.expectEvent(denied, "platform.access_review_viewed:denied:forbidden")
	}
	denied := e.do(call{method: http.MethodGet, path: "/api/platform/v1/access-review/export?format=csv", cookie: e.session(org, principal.RoleOrgAdmin)})
	if denied.status != http.StatusForbidden {
		t.Fatalf("organization export: %d", denied.status)
	}
	e.expectEvent(denied, "platform.access_review_exported:denied:forbidden")
}
