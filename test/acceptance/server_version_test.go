package acceptance

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// TestMeServerVersion (PDK-430): GET /api/v1/me names the build version of the running paddock-api, the version its
// binary prints, for an organization and a platform administrator; without a session the endpoint answers 401 and
// names no version.
func TestMeServerVersion(t *testing.T) {
	out, err := stack.Compose(testContext(t, time.Minute), nil, "exec", "-T", "paddock-api", "/paddock-server", "version")
	if err != nil {
		t.Fatalf("paddock-server version in paddock-api: %v: %s", err, out)
	}
	want := strings.TrimSpace(out)
	if want == "" {
		t.Fatal("paddock-server version printed nothing")
	}

	for _, user := range []string{env.Alice, env.PlatformAdmin} {
		res := call(t, login(t, user), http.MethodGet, "/api/v1/me", nil)
		expectStatus(t, res, http.StatusOK, "")
		var m struct {
			ServerVersion string `json:"server_version"`
		}
		if err := res.JSON(&m); err != nil {
			t.Fatal(err)
		}
		if m.ServerVersion != want {
			t.Fatalf("%s: server_version %q, want %q", user, m.ServerVersion, want)
		}
	}

	res := call(t, anonymousPortal(t), http.MethodGet, "/api/v1/me", nil)
	expectStatus(t, res, http.StatusUnauthorized, "unauthenticated")
	if strings.Contains(string(res.Body), want) {
		t.Fatalf("anonymous /api/v1/me names the version: %s", res.Body)
	}
}
