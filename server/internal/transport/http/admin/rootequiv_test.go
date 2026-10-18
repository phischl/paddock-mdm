package admin_test

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// TestPreviewRootEquivalence: the read-only preview names the effective class, the root-equivalent commands and the
// witnesses with the rules of the save, for every reading role, and records nothing (plan M8x decisions 40 and 42).
func TestPreviewRootEquivalence(t *testing.T) {
	e := newEnv(t)
	auditor := e.session(e.acme, principal.RoleOrgAuditor)
	preview := func(c *http.Cookie, class string, commands ...string) (int, adminapi.RootEquivalence) {
		t.Helper()
		q := url.Values{"class": {class}, "command": commands}
		r := e.do(call{method: "GET", path: "/api/v1/permission-profiles/root-equivalence?" + q.Encode(), cookie: c})
		var out adminapi.RootEquivalence
		if r.status == http.StatusOK {
			r.decode(t, &out)
		}
		return r.status, out
	}

	status, got := preview(auditor, "restricted", "/usr/bin/apt update")
	if status != http.StatusOK || got.EffectiveClass != adminapi.Full ||
		!slices.Equal(got.Witnesses, []string{"cmd:/usr/bin/apt update"}) ||
		!slices.Equal(got.RootEquivalentCommands, []string{"/usr/bin/apt update"}) {
		t.Fatalf("apt update: %d %+v", status, got)
	}
	_, got = preview(auditor, "restricted", "/usr/bin/tee /opt/x", "/opt/x")
	if got.EffectiveClass != adminapi.Full || !slices.Equal(got.Witnesses, []string{"pair:/usr/bin/tee /opt/x|/opt/x"}) {
		t.Fatalf("tee pair: %+v", got)
	}
	_, got = preview(auditor, "restricted", "/usr/bin/systemctl restart nginx.service")
	if got.EffectiveClass != adminapi.Restricted || len(got.Witnesses) != 0 || got.Witnesses == nil ||
		len(got.RootEquivalentCommands) != 0 {
		t.Fatalf("systemctl restart: %+v", got)
	}
	_, got = preview(e.session(e.acme, principal.RoleOrgOperator), "full")
	if got.EffectiveClass != adminapi.Full || !slices.Equal(got.Witnesses, []string{"ALL"}) {
		t.Fatalf("full: %+v", got)
	}
	// Duplicates and surrounding blanks are normalized as on save.
	_, got = preview(auditor, "restricted", " /usr/bin/apt update ", "/usr/bin/apt update")
	if !slices.Equal(got.RootEquivalentCommands, []string{"/usr/bin/apt update"}) {
		t.Fatalf("normalized: %+v", got)
	}

	if status, _ := preview(e.platformSession(), "full"); status != http.StatusForbidden {
		t.Fatalf("platform admin: %d, want 403", status)
	}
	if status, _ := preview(nil, "full"); status != http.StatusUnauthorized {
		t.Fatalf("no session: %d, want 401", status)
	}
	if r := e.do(call{method: "GET", path: "/api/v1/permission-profiles/root-equivalence?class=root", cookie: auditor,
		skipReqCheck: true}); r.status != http.StatusBadRequest {
		t.Fatalf("invalid class: %d", r.status)
	}
	if r := e.do(call{method: "GET", path: "/api/v1/permission-profiles/root-equivalence?class=restricted&command=" +
		url.QueryEscape("/usr/bin/"+strings.Repeat("x", 1100)), cookie: auditor, skipReqCheck: true}); r.status != http.StatusBadRequest {
		t.Fatalf("command over 1024 characters: %d", r.status)
	}
	var n int
	if err := e.super.QueryRow(context.Background(), "SELECT count(*) FROM action WHERE code LIKE 'permission_profile.%' AND organization_id = $1",
		e.acme).Scan(&n); err != nil || n != 0 {
		t.Fatalf("the preview recorded %d audit events, %v", n, err)
	}
}
