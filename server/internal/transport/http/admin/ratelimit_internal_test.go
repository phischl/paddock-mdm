package admin

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/platform/ratelimit"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// countStore counts in memory; err makes every hit fail.
type countStore struct {
	counts map[string]int64
	err    error
}

func (s *countStore) Hit(_ context.Context, cur, prev string, _ time.Duration) (int64, int64, error) {
	if s.err != nil {
		return 0, 0, s.err
	}
	s.counts[cur]++
	return s.counts[cur], s.counts[prev], nil
}

func limitedServer(store ratelimit.Store, limits map[ratelimit.Class]int, exempt ...netip.Prefix) *server {
	return &server{d: Deps{RateLimiter: ratelimit.New(store, func() time.Time { return time.Unix(1_800_000_030, 0) }, limits),
		RateLimitExempt: exempt}}
}

var okHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })

func serve(h http.Handler, method, path string, p *principal.Principal) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://admin.test"+path, nil)
	if p != nil {
		r = r.WithContext(principal.With(r.Context(), *p))
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestPrincipalClass(t *testing.T) {
	for _, c := range []struct {
		method, path string
		want         ratelimit.Class
	}{
		{http.MethodGet, "/api/v1/devices", ratelimit.AdminRead},
		{http.MethodHead, "/api/v1/devices", ratelimit.AdminRead},
		{http.MethodPost, "/api/v1/device-groups", ratelimit.AdminWrite},
		{http.MethodDelete, "/api/v1/device-groups/x", ratelimit.AdminWrite},
		{http.MethodPut, "/api/v1/config", ratelimit.AdminWrite},
		{http.MethodPut, "/api/platform/v1/agent-releases/1.2.3/artifacts/amd64", ratelimit.PlatformUpload},
		{http.MethodPut, "/api/platform/v1/agent-releases/1.2.3/packages/paddock-agent/amd64", ratelimit.PlatformUpload},
		{http.MethodPut, "/api/platform/v1/agent-releases/1.2.3/artifacts", ratelimit.AdminWrite},
		{http.MethodPut, "/api/platform/v1/agent-releases/1.2.3/notes/amd64", ratelimit.AdminWrite},
		{http.MethodGet, "/api/platform/v1/agent-releases/1.2.3/artifacts/amd64", ratelimit.AdminRead},
	} {
		r := httptest.NewRequest(c.method, "https://admin.test"+c.path, nil)
		if got := principalClass(r); got != c.want {
			t.Errorf("%s %s: %s, want %s", c.method, c.path, got, c.want)
		}
	}
}

func TestPrincipalKey(t *testing.T) {
	account, token := uuid.New(), uuid.New()
	viaToken := principalKey(principal.Principal{Kind: principal.KindAdmin, ID: account, APITokenID: token})
	if viaToken != "token:"+token.String() {
		t.Fatalf("token key %q", viaToken)
	}
	s1 := principalKey(principal.Principal{Kind: principal.KindAdmin, ID: account, SessionID: "secret-session-1"})
	s2 := principalKey(principal.Principal{Kind: principal.KindAdmin, ID: account, SessionID: "secret-session-2"})
	if s1 == s2 || s1 == viaToken || len(s1) != len("session:")+32 {
		t.Fatalf("session keys %q %q", s1, s2)
	}
	for _, k := range []string{s1, s2} {
		if strings.Contains(k, "secret-session") {
			t.Fatalf("session ID in key %q", k)
		}
	}
	if got := principalKey(principal.Principal{Kind: principal.KindPlatformAdmin, ID: account}); got != "platform_admin:"+account.String() {
		t.Fatalf("account key %q", got)
	}
}

func TestLimitAuthOnlyOnAuthPaths(t *testing.T) {
	s := limitedServer(&countStore{counts: map[string]int64{}}, map[ratelimit.Class]int{ratelimit.Auth: 2})
	h := s.limitAuth(okHandler)
	for range 2 {
		if w := serve(h, http.MethodGet, "/api/auth/login", nil); w.Code != http.StatusNoContent {
			t.Fatalf("within the limit: %d", w.Code)
		}
	}
	w := serve(h, http.MethodPost, "/api/auth/mcp/session", nil)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != "30" {
		t.Fatalf("third sign-in request: %d Retry-After %q, want 429 30", w.Code, w.Header().Get("Retry-After"))
	}
	for _, path := range []string{"/", "/assets/app.js", "/api/v1/me", "/healthz", "/readyz", "/metrics"} {
		if w := serve(h, http.MethodGet, path, nil); w.Code != http.StatusNoContent {
			t.Fatalf("%s limited by the auth class: %d", path, w.Code)
		}
	}
}

func TestLimitPrincipalPerPrincipalAndClass(t *testing.T) {
	s := limitedServer(&countStore{counts: map[string]int64{}},
		map[ratelimit.Class]int{ratelimit.AdminRead: 2, ratelimit.AdminWrite: 1, ratelimit.PlatformUpload: 1})
	h := s.limitPrincipal(okHandler)
	alice := &principal.Principal{Kind: principal.KindAdmin, ID: uuid.New(), SessionID: "a"}
	bob := &principal.Principal{Kind: principal.KindAdmin, ID: uuid.New(), APITokenID: uuid.New()}
	for range 2 {
		if w := serve(h, http.MethodGet, "/api/v1/me", alice); w.Code != http.StatusNoContent {
			t.Fatalf("alice read: %d", w.Code)
		}
	}
	if w := serve(h, http.MethodGet, "/api/v1/me", alice); w.Code != http.StatusTooManyRequests {
		t.Fatalf("alice's third read: %d", w.Code)
	}
	if w := serve(h, http.MethodGet, "/api/v1/me", bob); w.Code != http.StatusNoContent {
		t.Fatalf("bob's read after alice is limited: %d", w.Code)
	}
	if w := serve(h, http.MethodPost, "/api/v1/device-groups", alice); w.Code != http.StatusNoContent {
		t.Fatalf("alice's write after her reads are limited: %d", w.Code)
	}
	if w := serve(h, http.MethodPost, "/api/v1/device-groups", alice); w.Code != http.StatusTooManyRequests {
		t.Fatalf("alice's second write: %d", w.Code)
	}
	upload := "/api/platform/v1/agent-releases/1.2.3/artifacts/amd64"
	if w := serve(h, http.MethodPut, upload, bob); w.Code != http.StatusNoContent {
		t.Fatalf("first upload: %d", w.Code)
	}
	if w := serve(h, http.MethodPut, upload, bob); w.Code != http.StatusTooManyRequests {
		t.Fatalf("second upload: %d", w.Code)
	}
	if w := serve(h, http.MethodGet, "/api/v1/me", nil); w.Code != http.StatusNoContent {
		t.Fatalf("a request without principal reaches the session's 401 unlimited: %d", w.Code)
	}
}

func TestRateLimitFailsOpen(t *testing.T) {
	s := limitedServer(&countStore{err: errors.New("valkey down")}, map[ratelimit.Class]int{ratelimit.Auth: 1, ratelimit.AdminRead: 1})
	alice := &principal.Principal{Kind: principal.KindAdmin, ID: uuid.New()}
	for range 3 {
		if w := serve(s.limitAuth(okHandler), http.MethodGet, "/api/auth/login", nil); w.Code != http.StatusNoContent {
			t.Fatalf("sign-in with the store down: %d", w.Code)
		}
		if w := serve(s.limitPrincipal(okHandler), http.MethodGet, "/api/v1/me", alice); w.Code != http.StatusNoContent {
			t.Fatalf("read with the store down: %d", w.Code)
		}
	}
}

func TestRateLimitExempt(t *testing.T) {
	store := &countStore{counts: map[string]int64{}}
	// httptest requests come from 192.0.2.1.
	s := limitedServer(store, map[ratelimit.Class]int{ratelimit.Auth: 1}, netip.MustParsePrefix("192.0.2.0/24"))
	for range 3 {
		if w := serve(s.limitAuth(okHandler), http.MethodGet, "/api/auth/login", nil); w.Code != http.StatusNoContent {
			t.Fatalf("exempt client limited: %d", w.Code)
		}
	}
	if len(store.counts) != 0 {
		t.Fatalf("exempt client counted: %v", store.counts)
	}
}

func TestNoLimiterLimitsNothing(t *testing.T) {
	s := &server{}
	for range 50 {
		if w := serve(s.limitAuth(okHandler), http.MethodGet, "/api/auth/login", nil); w.Code != http.StatusNoContent {
			t.Fatalf("limited without a limiter: %d", w.Code)
		}
	}
}
