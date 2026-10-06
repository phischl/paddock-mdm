package admin_test

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin"
)

const (
	testIndex  = `<!doctype html><html><head><meta name="csp-nonce" content="__CSP_NONCE__"><title>Paddock</title></head></html>`
	defaultCSP = "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)

var (
	cspWithNonce = regexp.MustCompile(`^default-src 'self'; style-src 'self' 'nonce-([A-Za-z0-9+/]{22}==)'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'$`)
	metaNonce    = regexp.MustCompile(`<meta name="csp-nonce" content="([^"]*)">`)
)

func staticHandler(t *testing.T) http.Handler {
	t.Helper()
	static, err := admin.NewStaticHandler(fstest.MapFS{
		"index.html":       {Data: []byte(testIndex)},
		"assets/app-1.js":  {Data: []byte("console.log(1)")},
		"assets/app-1.css": {Data: []byte("body{}")},
	})
	if err != nil {
		t.Fatal(err)
	}
	return admin.NewHandler(admin.Deps{Static: static, Keys: &admin.Keyring{}, OIDC: admin.NewOIDC(admin.OIDCConfig{})})
}

func get(h http.Handler, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://admin.test"+path, nil))
	return rec
}

// TestIndexNonce: every index.html response carries a fresh nonce, identical in the CSP header and the meta tag.
func TestIndexNonce(t *testing.T) {
	h := staticHandler(t)
	seen := map[string]string{}
	for _, path := range []string{"/", "/", "/device-groups", "/device-groups", "/index.html"} {
		rec := get(h, path)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", path, rec.Code)
		}
		header := cspWithNonce.FindStringSubmatch(rec.Header().Get("Content-Security-Policy"))
		if header == nil {
			t.Fatalf("%s: CSP %q", path, rec.Header().Get("Content-Security-Policy"))
		}
		body := rec.Body.String()
		meta := metaNonce.FindStringSubmatch(body)
		if meta == nil || meta[1] != header[1] {
			t.Fatalf("%s: meta nonce %v, header nonce %s", path, meta, header[1])
		}
		if strings.Contains(body, "__CSP_NONCE__") {
			t.Fatalf("%s: placeholder left in the body", path)
		}
		if strings.Contains(rec.Header().Get("Content-Security-Policy"), "unsafe-inline") {
			t.Fatalf("%s: CSP allows unsafe-inline", path)
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
			t.Fatalf("%s: Cache-Control %q", path, cc)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
			t.Fatalf("%s: Content-Type %q", path, ct)
		}
		if prev, ok := seen[header[1]]; ok {
			t.Fatalf("%s reused the nonce of %s", path, prev)
		}
		seen[header[1]] = path
	}
}

// TestAssetsUnchanged: static assets keep the default CSP and immutable caching and are served byte for byte.
func TestAssetsUnchanged(t *testing.T) {
	h := staticHandler(t)
	for path, want := range map[string]string{"/assets/app-1.js": "console.log(1)", "/assets/app-1.css": "body{}"} {
		rec := get(h, path)
		if rec.Code != http.StatusOK || rec.Body.String() != want {
			t.Fatalf("%s: %d %q", path, rec.Code, rec.Body.String())
		}
		if csp := rec.Header().Get("Content-Security-Policy"); csp != defaultCSP {
			t.Fatalf("%s: CSP %q", path, csp)
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
			t.Fatalf("%s: Cache-Control %q", path, cc)
		}
	}
}

func TestStaticHandlerRejectsTemplate(t *testing.T) {
	for name, index := range map[string]string{
		"no placeholder":   `<!doctype html><meta name="csp-nonce" content=""><title>Paddock</title>`,
		"two placeholders": `<!doctype html><meta name="csp-nonce" content="__CSP_NONCE__"><style nonce="__CSP_NONCE__"></style>`,
	} {
		if _, err := admin.NewStaticHandler(fstest.MapFS{"index.html": {Data: []byte(index)}}); err == nil {
			t.Errorf("%s: template accepted", name)
		}
	}
}

func TestStaticHandlerWithoutPortalBuild(t *testing.T) {
	static, err := admin.NewStaticHandler(fstest.MapFS{".gitkeep": {Data: nil}})
	if err != nil {
		t.Fatal(err)
	}
	rec := get(admin.NewHandler(admin.Deps{Static: static, Keys: &admin.Keyring{}, OIDC: admin.NewOIDC(admin.OIDCConfig{})}), "/")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", rec.Code)
	}
}
