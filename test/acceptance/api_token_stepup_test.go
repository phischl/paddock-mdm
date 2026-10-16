package acceptance

import (
	"net/http"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// TestTokenCannotGrantRoot is gate S5 and S7 of plan M8s (ADR 0034 decision 3): an operator API token is refused with
// the token detail for a root-equivalent profile and a file on a sensitive path, and keeps working for an ordinary
// profile and an ordinary file.
func TestTokenCannotGrantRoot(t *testing.T) {
	alice := login(t, env.Alice)
	token := tokenPortal(t, createAPIToken(t, alice, env.Alice, "org_operator").Secret)
	refused := func(t *testing.T, res env.Response, code string) {
		t.Helper()
		expectRefusal(t, alice, res, http.StatusForbidden, "step_up_required", code)
		if d := problemDetail(t, res); !strings.Contains(d, "API tokens") {
			t.Fatalf("detail %q does not name API tokens", d)
		}
	}

	t.Run("S5 profiles", func(t *testing.T) {
		refused(t, call(t, token, http.MethodPost, "/api/v1/permission-profiles", rootProfile()), "permission_profile.created")
		res := call(t, token, http.MethodPost, "/api/v1/permission-profiles", map[string]any{
			"name": uniqueName("s5 nginx"), "class": "restricted", "commands": []string{"/usr/bin/systemctl restart nginx.service"},
		})
		expectStatus(t, res, http.StatusCreated, "")
		createdID(t, alice, "/api/v1/permission-profiles", res)
		if ev := expectOneEvent(t, alice, res.RequestID, "permission_profile.created", "success"); ev.Params["effective_class"] != "restricted" {
			t.Fatalf("event %+v", ev)
		}
	})

	t.Run("S7 managed files", func(t *testing.T) {
		sfx := uniqueSuffix()
		refused(t, call(t, token, http.MethodPost, "/api/v1/managed-files", map[string]any{
			"path": "/etc/profile.d/s7-" + sfx + ".sh", "content": "export S7=1\n",
		}), "managed_file.created")
		res := call(t, token, http.MethodPost, "/api/v1/managed-files", map[string]any{
			"path": "/opt/myapp-" + sfx + "/conf/a.ini", "mode": "0644", "content": "a=1\n",
		})
		expectStatus(t, res, http.StatusCreated, "")
		createdID(t, alice, "/api/v1/managed-files", res)
		if ev := expectOneEvent(t, alice, res.RequestID, "managed_file.created", "success"); ev.Params["tier"] != "ordinary" {
			t.Fatalf("event %+v", ev)
		}
	})
}
