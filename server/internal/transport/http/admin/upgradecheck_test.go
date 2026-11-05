package admin_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin"
)

// TestUpgradeCheckAuthorizesBeforeValidating (PDK-788): a missing target_version is answered after the platform check,
// so an organization principal gets 403 and a platform administrator 400. The unknown version ends the report before
// it reads any data, which is why the use case needs no database here.
func TestUpgradeCheckAuthorizesBeforeValidating(t *testing.T) {
	e := newEnvWith(t, func(d *admin.Deps) { d.UpgradeCheck = app.NewUpgradeCheck(nil, nil, nil, nil, 0) })
	const path = "/api/platform/v1/upgrade-check"
	orgAdmin := e.session(e.org("upgrade-check"), principal.RoleOrgAdmin)

	for _, query := range []string{"", "?target_version=0.0.0-unknown"} {
		r := e.do(call{method: "GET", path: path + query, cookie: orgAdmin})
		if r.status != http.StatusForbidden || r.problemCode(t) != "forbidden" {
			t.Errorf("organization administrator %q: %d %s", query, r.status, r.body)
		}
		r = e.do(call{method: "GET", path: path + query, cookie: e.platformSession()})
		if r.status != http.StatusBadRequest || r.problemCode(t) != "invalid_request" {
			t.Errorf("platform administrator %q: %d %s", query, r.status, r.body)
		}
		if want := map[string]string{"": "target_version is required", "?target_version=0.0.0-unknown": "no known Paddock release"}[query]; !strings.Contains(string(r.body), want) {
			t.Errorf("platform administrator %q: detail does not contain %q: %s", query, want, r.body)
		}
	}
}
