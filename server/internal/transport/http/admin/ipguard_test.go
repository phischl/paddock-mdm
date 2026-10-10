package admin_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin"
)

func prefixes(s ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range s {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}

// guardHandler wraps a 200 handler with the guard and the request ID middleware, as NewHandler does.
func guardHandler(g *admin.IPGuard) http.Handler {
	return httpx.RequestIDMiddleware(g.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
}

func guardGet(h http.Handler, path, remote string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "https://admin.test"+path, nil)
	r.RemoteAddr = remote
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// TestIPGuard: allowed and denied requests (problem details under /api/, plain text elsewhere), readiness, the
// bypass and a failing reload that keeps the last set (plan M7a decision 17).
func TestIPGuard(t *testing.T) {
	ctx := context.Background()
	list := prefixes("198.51.100.0/24", "2001:db8::/32")
	var loadErr error
	g := admin.NewIPGuard(func(context.Context) ([]netip.Prefix, error) { return list, loadErr }, nil, nil, false)
	h := guardHandler(g)
	if g.Ready() {
		t.Fatal("ready before the first load")
	}
	if rec := guardGet(h, "/api/v1/me", "192.0.2.1:1"); rec.Code != http.StatusOK {
		t.Fatalf("before the first load every address is allowed: %d", rec.Code)
	}
	if err := g.Reload(ctx); err != nil || !g.Ready() {
		t.Fatalf("reload: %v ready %v", err, g.Ready())
	}

	rec := guardGet(h, "/api/v1/me", "192.0.2.1:1")
	if rec.Code != http.StatusForbidden || rec.Header().Get("Content-Type") != "application/problem+json" ||
		!strings.Contains(rec.Body.String(), `"code":"ip_not_allowed"`) || rec.Header().Get(httpx.HeaderRequestID) == "" {
		t.Fatalf("denied api request: %d %s %v", rec.Code, rec.Body.String(), rec.Header())
	}
	if strings.Contains(rec.Body.String(), "198.51.100") || strings.Contains(rec.Body.String(), "allow list") {
		t.Fatalf("the denial reveals the list: %s", rec.Body.String())
	}
	rec = guardGet(h, "/", "192.0.2.1:1")
	if rec.Code != http.StatusForbidden || rec.Header().Get("Content-Type") != "text/plain; charset=utf-8" ||
		rec.Body.String() != "403 Forbidden\n" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("denied page request: %d %q %v", rec.Code, rec.Body.String(), rec.Header())
	}
	for _, remote := range []string{"198.51.100.7:1", "[2001:db8::9]:1", "[::ffff:198.51.100.7]:1"} {
		if rec := guardGet(h, "/api/v1/me", remote); rec.Code != http.StatusOK {
			t.Fatalf("%s: %d", remote, rec.Code)
		}
	}
	if rec := guardGet(h, "/api/v1/me", "garbage"); rec.Code != http.StatusForbidden {
		t.Fatalf("an unparsable peer is denied while the list is on: %d", rec.Code)
	}

	// A failed reload keeps the last set.
	loadErr = errors.New("database down")
	if err := g.Reload(ctx); err == nil {
		t.Fatal("reload with a failing load")
	}
	if rec := guardGet(h, "/", "192.0.2.1:1"); rec.Code != http.StatusForbidden {
		t.Fatalf("after a failed reload: %d", rec.Code)
	}
	loadErr = nil
	list = nil
	if err := g.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if rec := guardGet(h, "/", "192.0.2.1:1"); rec.Code != http.StatusOK {
		t.Fatalf("an empty list allows everyone: %d", rec.Code)
	}

	bypass := admin.NewIPGuard(func(context.Context) ([]netip.Prefix, error) { return prefixes("198.51.100.0/24"), nil }, nil, nil, true)
	if !bypass.Ready() {
		t.Fatal("the bypass is ready without a load")
	}
	if err := bypass.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if rec := guardGet(guardHandler(bypass), "/api/v1/me", "192.0.2.1:1"); rec.Code != http.StatusOK {
		t.Fatalf("bypass: %d", rec.Code)
	}
}
