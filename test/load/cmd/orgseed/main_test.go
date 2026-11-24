package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type fakeAPI struct {
	mu      sync.Mutex
	slugs   map[string]bool
	cookies []string
	csrf    []string
	limited int
	status  int
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cookies = append(f.cookies, r.Header.Get("Cookie"))
	f.csrf = append(f.csrf, r.Header.Get("X-Paddock-CSRF"))
	if r.Method != http.MethodPost || r.URL.Path != createPath {
		http.NotFound(w, r)
		return
	}
	if f.status != 0 {
		w.WriteHeader(f.status)
		return
	}
	if f.limited > 0 {
		f.limited--
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	var b struct{ Slug, Name string }
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.Slug == "" || b.Name == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if f.slugs[b.Slug] {
		w.WriteHeader(http.StatusConflict)
		return
	}
	f.slugs[b.Slug] = true
	w.WriteHeader(http.StatusCreated)
}

func opts(srv *httptest.Server, count int) options {
	return options{server: srv.URL, cookie: "sealed", count: count, prefix: "load", concurrency: 3}
}

func TestSeedCreatesOrganizations(t *testing.T) {
	api := &fakeAPI{slugs: map[string]bool{}}
	srv := httptest.NewServer(api)
	defer srv.Close()
	var out bytes.Buffer
	if err := seed(context.Background(), srv.Client(), opts(srv, 12), &out); err != nil {
		t.Fatal(err)
	}
	if len(api.slugs) != 12 || !api.slugs["load-001"] || !api.slugs["load-012"] {
		t.Fatalf("slugs = %v", api.slugs)
	}
	for i := range api.cookies {
		if api.cookies[i] != "paddock_session=sealed" || api.csrf[i] != "1" {
			t.Fatalf("request %d: cookie %q csrf %q", i, api.cookies[i], api.csrf[i])
		}
	}
	if !strings.Contains(out.String(), "12 created, 0 existed") {
		t.Fatalf("output = %q", out.String())
	}
}

func TestSeedIsRepeatable(t *testing.T) {
	api := &fakeAPI{slugs: map[string]bool{"load-001": true, "load-002": true}}
	srv := httptest.NewServer(api)
	defer srv.Close()
	var out bytes.Buffer
	if err := seed(context.Background(), srv.Client(), opts(srv, 5), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "3 created, 2 existed") {
		t.Fatalf("output = %q", out.String())
	}
}

func TestSeedRetriesRateLimit(t *testing.T) {
	api := &fakeAPI{slugs: map[string]bool{}, limited: 2}
	srv := httptest.NewServer(api)
	defer srv.Close()
	o := opts(srv, 3)
	o.concurrency = 1
	if err := seed(context.Background(), srv.Client(), o, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if len(api.slugs) != 3 {
		t.Fatalf("slugs = %v", api.slugs)
	}
}

func TestSeedFailsOnRefusal(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusBadGateway} {
		api := &fakeAPI{slugs: map[string]bool{}, status: status}
		srv := httptest.NewServer(api)
		err := seed(context.Background(), srv.Client(), opts(srv, 4), &bytes.Buffer{})
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), "HTTP "+strconv.Itoa(status)) {
			t.Fatalf("status %d: err = %v", status, err)
		}
	}
}

func TestSlugOf(t *testing.T) {
	if s, err := slugOf("load", 7); err != nil || s != "load-007" {
		t.Fatalf("slugOf = %q, %v", s, err)
	}
	if s, err := slugOf("load", 1234); err != nil || s != "load-1234" {
		t.Fatalf("slugOf = %q, %v", s, err)
	}
	for _, p := range []string{"Load", "load_x", "", strings.Repeat("a", 30)} {
		if _, err := slugOf(p, 1); err == nil {
			t.Fatalf("prefix %q accepted", p)
		}
	}
}

func TestRunValidatesArguments(t *testing.T) {
	dir := t.TempDir()
	cookie := filepath.Join(dir, "cookie")
	if err := os.WriteFile(cookie, []byte("sealed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]string{
		"no server":     {"--cookie-file", cookie},
		"no cookie":     {"--server", "http://x:8080"},
		"zero count":    {"--server", "http://x:8080", "--cookie-file", cookie, "--count", "0"},
		"bad scheme":    {"--server", "ftp://x", "--cookie-file", cookie},
		"missing file":  {"--server", "http://x:8080", "--cookie-file", filepath.Join(dir, "none")},
		"empty cookie":  {"--server", "http://x:8080", "--cookie-file", empty},
		"invalid slugs": {"--server", "http://x:8080", "--cookie-file", cookie, "--slug-prefix", "Bad_Prefix"},
	}
	for name, args := range cases {
		if err := run(context.Background(), args, &bytes.Buffer{}); err == nil {
			t.Fatalf("%s: no error", name)
		}
	}
}
