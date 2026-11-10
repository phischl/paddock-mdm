package admin

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/ratelimit"
)

// fakeLocator accepts paddock:secret for the organization acme and knows one object.
type fakeLocator struct{ calls int }

func (f *fakeLocator) Locate(_ context.Context, slug, user, password, path string) (string, error) {
	f.calls++
	switch {
	case slug != "acme" || user != "paddock" || password != "secret":
		return "", app.ErrRepositoryUnauthorized
	case path == "dists/paddock/InRelease":
		return "https://bundles.test/paddock-bundles/apt/x/dists/paddock/InRelease?X-Amz-Signature=s", nil
	case path == "boom":
		return "", errors.New("store down")
	}
	return "", app.ErrRepositoryNotFound
}

// TestBundlesHostRepository (plan M13c decision 14): on the bundles host the api answers apt with 401 and a Basic
// challenge without the credential, 302 to the presigned URL with it, 404 for an unknown path or anything outside
// /apt/<slug>/, 405 for a write, 429 beyond bundles_apt per client address (six requests counted here); other hosts
// reach the admin handler.
func TestBundlesHostRepository(t *testing.T) {
	loc := &fakeLocator{}
	s := limitedServer(&countStore{counts: map[string]int64{}}, map[ratelimit.Class]int{ratelimit.BundlesAPT: 6})
	s.d.BundlesHost, s.d.Repositories = "bundles.test:8443", loc
	h := s.bundlesHost(okHandler)
	do := func(method, target, user, password string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, target, nil)
		if user != "" {
			r.SetBasicAuth(user, password)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, c := range []struct {
		name, method, target, user, password string
		code                                 int
	}{
		{"without credential", http.MethodGet, "https://bundles.test:8443/apt/acme/dists/paddock/InRelease", "", "", http.StatusUnauthorized},
		{"wrong secret", http.MethodGet, "https://bundles.test:8443/apt/acme/dists/paddock/InRelease", "paddock", "nope", http.StatusUnauthorized},
		{"with credential", http.MethodGet, "https://bundles.test:8443/apt/acme/dists/paddock/InRelease", "paddock", "secret", http.StatusFound},
		{"head", http.MethodHead, "https://BUNDLES.test:8443/apt/acme/dists/paddock/InRelease", "paddock", "secret", http.StatusFound},
		{"unknown path", http.MethodGet, "https://bundles.test:8443/apt/acme/dists/paddock/Release", "paddock", "secret", http.StatusNotFound},
		{"store error", http.MethodGet, "https://bundles.test:8443/apt/acme/boom", "paddock", "secret", http.StatusServiceUnavailable},
		{"write", http.MethodPut, "https://bundles.test:8443/apt/acme/dists/paddock/InRelease", "paddock", "secret", http.StatusMethodNotAllowed},
		{"no slug path", http.MethodGet, "https://bundles.test:8443/apt/acme", "paddock", "secret", http.StatusNotFound},
		{"portal on the bundles host", http.MethodGet, "https://bundles.test:8443/api/v1/devices", "", "", http.StatusNotFound},
		{"admin host", http.MethodGet, "https://admin.test/apt/acme/dists/paddock/InRelease", "", "", http.StatusNoContent},
	} {
		w := do(c.method, c.target, c.user, c.password)
		if w.Code != c.code {
			t.Errorf("%s: %d, want %d", c.name, w.Code, c.code)
		}
		if c.code == http.StatusUnauthorized && w.Header().Get("WWW-Authenticate") != `Basic realm="paddock"` {
			t.Errorf("%s: WWW-Authenticate %q", c.name, w.Header().Get("WWW-Authenticate"))
		}
		if c.code == http.StatusFound && w.Header().Get("Location") != "https://bundles.test/paddock-bundles/apt/x/dists/paddock/InRelease?X-Amz-Signature=s" {
			t.Errorf("%s: Location %q", c.name, w.Header().Get("Location"))
		}
	}
	calls := loc.calls
	if w := do(http.MethodGet, "https://bundles.test:8443/apt/acme/dists/paddock/InRelease", "paddock", "secret"); w.Code != http.StatusTooManyRequests ||
		w.Header().Get("Retry-After") == "" || loc.calls != calls {
		t.Fatalf("beyond the limit: %d, Retry-After %q, locator called %v", w.Code, w.Header().Get("Retry-After"), loc.calls != calls)
	}
}
