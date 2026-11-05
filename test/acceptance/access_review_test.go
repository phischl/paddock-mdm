package acceptance

import (
	"encoding/csv"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// accessReview is the part of the report the gates read.
type accessReview struct {
	Roles []struct {
		Role            string     `json:"role"`
		SnapshotTakenAt *time.Time `json:"snapshot_taken_at"`
		Total           int        `json:"total"`
	} `json:"roles"`
	APITokens struct {
		Total int `json:"total"`
		Items []struct {
			Name      string     `json:"name"`
			RevokedAt *time.Time `json:"revoked_at"`
		} `json:"items"`
	} `json:"api_tokens"`
	Reveals struct {
		Total int `json:"total"`
		Items []struct {
			Code string `json:"code"`
		} `json:"items"`
	} `json:"reveals"`
	RoleChanges struct {
		Total int `json:"total"`
		Items []struct {
			Code     string `json:"code"`
			Role     string `json:"role"`
			Username string `json:"username"`
		} `json:"items"`
	} `json:"role_changes"`
}

func getAccessReview(t *testing.T, p *env.Portal, path string) (accessReview, env.Response) {
	t.Helper()
	res := call(t, p, http.MethodGet, path, nil)
	var r accessReview
	if res.Status == http.StatusOK {
		if err := res.JSON(&r); err != nil {
			t.Fatal(err)
		}
	}
	return r, res
}

func (r accessReview) granted(username string) bool {
	for _, c := range r.RoleChanges.Items {
		if c.Code == "admin.role_granted" && c.Username == username {
			return true
		}
	}
	return false
}

func (r accessReview) adminMembers() int {
	for _, role := range r.Roles {
		if role.Role == "org_admin" {
			return role.Total
		}
	}
	return 0
}

// TestAccessReview is gate A1 of plan M12: an organization administrator and an auditor read the report with the
// seeded role members (from the worker's snapshot), a created and a revoked API token and a local_admin.revealed
// event; an operator is refused (403); a period over 400 days is 400 invalid_request; the CSV export has the section
// column and a row for every item of the JSON, and every export is recorded as access_review.exported (pending stack
// run).
func TestAccessReview(t *testing.T) {
	slug, org := gateOrganization(t)
	admin := steppedUpTempUser(t, "ar-admin", env.RoleGroup(slug, "admins"))
	auditor := tempPortal(t, "ar-auditor", env.RoleGroup(slug, "auditors"))
	idx := auditIndex(t)

	created := createAPIToken(t, admin.Portal, admin.username, "org_operator")
	revoked := createAPIToken(t, admin.Portal, admin.username, "org_auditor")
	admin.stepUp(t)
	expectStatus(t, call(t, admin.Portal, http.MethodPost, "/api/v1/api-tokens/"+revoked.Token.ID+"/revoke", nil), http.StatusOK, "")

	d, _ := escrowedDevice(t, admin.Portal)
	admin.stepUp(t)
	expectStatus(t, call(t, admin.Portal, http.MethodPost, "/api/v1/devices/"+d.DeviceID+"/local-admin/reveal",
		map[string]any{"confirm_hostname": getDevice(t, admin.Portal, d.DeviceID).Hostname}), http.StatusOK, "")

	// The first comparison of a role records its members as baseline, which the report hides; the operator joins only
	// after the operators role has its snapshot, so the grant is a real change.
	eventually(t, "the worker's snapshot of the operators role", 10*time.Minute, func() bool {
		r, res := getAccessReview(t, admin.Portal, "/api/v1/access-review")
		if res.Status != http.StatusOK {
			return false
		}
		for _, role := range r.Roles {
			if role.Role == "org_operator" && role.SnapshotTakenAt != nil {
				return true
			}
		}
		return false
	})
	operatorName, operatorPassword := tempUser(t, "ar-operator", env.RoleGroup(slug, "operators"))
	operator, err := loginAs(t, operatorName, operatorPassword)
	if err != nil {
		t.Fatal(err)
	}

	var report accessReview
	eventually(t, "the worker's admin snapshot, the operator's role grant and the reveal in the report", 10*time.Minute, func() bool {
		var res env.Response
		report, res = getAccessReview(t, admin.Portal, "/api/v1/access-review")
		return res.Status == http.StatusOK && report.adminMembers() > 0 && report.Reveals.Total > 0 &&
			report.granted(operatorName)
	})
	if report.APITokens.Total < 2 || report.Reveals.Items[0].Code != "local_admin.revealed" {
		t.Fatalf("report: %+v", report)
	}
	names := map[string]*time.Time{}
	for _, it := range report.APITokens.Items {
		names[it.Name] = it.RevokedAt
	}
	if at, ok := names[created.Token.Name]; !ok || at != nil {
		t.Fatalf("the live token %q is missing or revoked: %v", created.Token.Name, names)
	}
	if at, ok := names[revoked.Token.Name]; !ok || at == nil {
		t.Fatalf("the revoked token %q is missing or live: %v", revoked.Token.Name, names)
	}
	if r, res := getAccessReview(t, auditor, "/api/v1/access-review"); res.Status != http.StatusOK || r.adminMembers() == 0 {
		t.Fatalf("auditor: %d %s", res.Status, res.Body)
	}
	expectStatus(t, call(t, operator, http.MethodGet, "/api/v1/access-review", nil), http.StatusForbidden, "forbidden")
	expectStatus(t, call(t, admin.Portal, http.MethodGet, "/api/v1/access-review?from="+url.QueryEscape(time.Now().Add(-401*24*time.Hour).UTC().Format(time.RFC3339)), nil),
		http.StatusBadRequest, "invalid_request")

	adminID := whoami(t, admin.Portal).ID
	viewedWhere := "code = 'access_review.viewed' AND outcome = 'success' AND actor->>'id' = $1"
	time.Sleep(10 * time.Second)
	if found, err := idx.Events(testContext(t, time.Minute), org, viewedWhere, adminID); err != nil || len(found) != 0 {
		t.Fatalf("access_review.viewed with audit_search_recorded off: %+v (%v)", found, err)
	}
	settings := currentPrivacySettings(t, admin.Portal)
	previous := settings["audit_search_recorded"]
	settings["audit_search_recorded"] = true
	expectStatus(t, call(t, admin.Portal, http.MethodPut, "/api/v1/settings/privacy", settings), http.StatusOK, "")
	t.Cleanup(func() {
		restore := currentPrivacySettings(t, admin.Portal)
		restore["audit_search_recorded"] = previous
		expectStatus(t, call(t, admin.Portal, http.MethodPut, "/api/v1/settings/privacy", restore), http.StatusOK, "")
	})
	for range 3 {
		expectStatus(t, call(t, admin.Portal, http.MethodGet, "/api/v1/access-review", nil), http.StatusOK, "")
	}
	expectOneIndexEvent(t, idx, org, viewedWhere, adminID, "access_review.viewed", "success", 30*time.Second)

	res := call(t, auditor, http.MethodGet, "/api/v1/access-review/export?format=csv", nil)
	expectStatus(t, res, http.StatusOK, "")
	rows, err := csv.NewReader(strings.NewReader(string(res.Body))).ReadAll()
	if err != nil || len(rows) < 2 || rows[0][0] != "section" {
		t.Fatalf("csv: %v %v", err, rows)
	}
	items := 0
	for _, row := range rows[1:] {
		if row[0] == "api_tokens" {
			items++
		}
	}
	if items != min(report.APITokens.Total, 1000) {
		t.Fatalf("csv has %d token rows, the report %d", items, report.APITokens.Total)
	}
	expectOneIndexEvent(t, idx, org, "correlation_id = $1", res.RequestID, "access_review.exported", "success", 30*time.Second)
}

// TestPlatformAccessReview is gate A2 of plan M12: a platform administrator reads the platform members and
// administrators and the view is recorded; an organization session is refused (403) (pending stack run).
func TestPlatformAccessReview(t *testing.T) {
	root := login(t, env.PlatformAdmin)
	res := call(t, root, http.MethodGet, "/api/platform/v1/access-review", nil)
	expectStatus(t, res, http.StatusOK, "")
	var report struct {
		Roles          []struct{ Role string } `json:"roles"`
		Administrators struct {
			Total int `json:"total"`
		} `json:"administrators"`
	}
	if err := res.JSON(&report); err != nil {
		t.Fatal(err)
	}
	if len(report.Roles) != 2 || report.Administrators.Total < 1 {
		t.Fatalf("platform report: %s", res.Body)
	}
	expectStatus(t, call(t, root, http.MethodGet, "/api/platform/v1/access-review/export?format=csv", nil), http.StatusOK, "")
	expectStatus(t, call(t, login(t, env.Alice), http.MethodGet, "/api/platform/v1/access-review", nil), http.StatusForbidden, "forbidden")
}
