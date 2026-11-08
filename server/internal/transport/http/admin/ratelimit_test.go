package admin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/platform/ratelimit"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin"
)

type memoryWindows struct {
	mu     sync.Mutex
	counts map[string]int64
}

func (m *memoryWindows) Hit(_ context.Context, cur, prev string, _ time.Duration) (int64, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counts[cur]++
	return m.counts[cur], m.counts[prev], nil
}

// TestRateLimitWiring: in the complete handler the auth class limits /api/auth/* per address before any session is
// looked at, the principal classes limit after authentication per principal, and an unauthenticated request is
// answered 401 without counting (plan M12h decision 8). The 429 responses are documented once for every operation in
// the contract's description, so the requests go to the handler directly.
func TestRateLimitWiring(t *testing.T) {
	e := newEnvWith(t, func(d *admin.Deps) {
		d.RateLimiter = ratelimit.New(&memoryWindows{counts: map[string]int64{}}, nil,
			map[ratelimit.Class]int{ratelimit.Auth: 2, ratelimit.AdminRead: 3, ratelimit.AdminWrite: 1})
	})
	send := func(path string, cookie *http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "https://admin.test"+path, nil)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		e.handler.ServeHTTP(w, req)
		return w
	}
	limited := func(what string, w *httptest.ResponseRecorder) {
		t.Helper()
		if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), `"code":"rate_limited"`) ||
			w.Header().Get("Retry-After") == "" {
			t.Fatalf("%s: %d %v %s, want 429 rate_limited with Retry-After", what, w.Code, w.Header(), w.Body)
		}
	}
	for range 2 {
		if w := send("/api/auth/login?return_to=%2F", nil); w.Code == http.StatusTooManyRequests {
			t.Fatalf("sign-in within the limit: %d %s", w.Code, w.Body)
		}
	}
	limited("third sign-in", send("/api/auth/login?return_to=%2F", nil))

	for range 5 {
		if w := send("/api/v1/me", nil); w.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated read: %d", w.Code)
		}
	}
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	bob := e.session(e.acme, principal.RoleOrgAdmin)
	for range 3 {
		if w := send("/api/v1/me", alice); w.Code != http.StatusOK {
			t.Fatalf("alice's read: %d %s", w.Code, w.Body)
		}
	}
	limited("alice's fourth read", send("/api/v1/me", alice))
	if w := send("/api/v1/me", bob); w.Code != http.StatusOK {
		t.Fatalf("bob is limited by alice's reads: %d %s", w.Code, w.Body)
	}
}
