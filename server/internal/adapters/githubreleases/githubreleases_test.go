package githubreleases

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

const releasesJSON = `[
 {"tag_name": "v0.2.0-alpha.1", "draft": false, "prerelease": true, "published_at": "2026-10-20T10:00:00Z",
  "assets": [{"name": "paddockd_0.2.0-alpha.1_linux_amd64", "size": 3, "browser_download_url": "%[1]s/download/a"}]},
 {"tag_name": "v9.9.9", "draft": true, "published_at": "2026-10-21T10:00:00Z", "assets": []},
 {"tag_name": "v9.9.9-e2e", "draft": false, "published_at": "2026-10-21T10:00:00Z", "assets": []},
 {"tag_name": "0.3.0", "draft": false, "published_at": "2026-10-21T10:00:00Z", "assets": []},
 {"tag_name": "v0.1.0", "draft": false, "published_at": "2026-10-01T10:00:00Z", "assets": []}
]`

func TestListReleases(t *testing.T) {
	var got *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		_, _ = fmt.Fprintf(w, releasesJSON, "http://"+r.Host)
	}))
	defer srv.Close()

	rels, err := New(srv.URL, "phischl/paddock-mdm", "", true).ListReleases(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rels) != 2 || rels[0].Version != "0.2.0-alpha.1" || rels[1].Version != "0.1.0" {
		t.Fatalf("releases = %+v, want 0.2.0-alpha.1 and 0.1.0 (drafts and other tags dropped)", rels)
	}
	if a := rels[0].Assets; len(a) != 1 || a[0].Name != "paddockd_0.2.0-alpha.1_linux_amd64" || a[0].Size != 3 ||
		a[0].URL != srv.URL+"/download/a" || !rels[0].PublishedAt.Equal(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("release = %+v", rels[0])
	}
	if got.URL.Path != "/repos/phischl/paddock-mdm/releases" || got.URL.Query().Get("per_page") != "100" {
		t.Fatalf("request = %s", got.URL)
	}
	if got.Header.Get("Accept") != "application/vnd.github+json" || got.Header.Get("X-GitHub-Api-Version") != APIVersion ||
		got.Header.Get("User-Agent") != UserAgent {
		t.Fatalf("headers = %v", got.Header)
	}
	if _, ok := got.Header["Authorization"]; ok {
		t.Fatal("Authorization sent without a token")
	}

	if _, err := New(srv.URL, "phischl/paddock-mdm", "ghp_x", true).ListReleases(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got.Header.Get("Authorization") != "Bearer ghp_x" {
		t.Fatalf("Authorization = %q", got.Header.Get("Authorization"))
	}
}

func TestListReleasesBounds(t *testing.T) {
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("[" + strings.Repeat(" ", MaxListBytes) + "]"))
	}))
	defer big.Close()
	if _, err := New(big.URL, "o/r", "", true).ListReleases(context.Background()); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("list above 1 MiB: %v", err)
	}

	block := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	defer slow.Close()
	defer close(block)
	c := New(slow.URL, "o/r", "", true)
	c.listTimeout = 100 * time.Millisecond
	if _, err := c.ListReleases(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("silent server: %v", err)
	}
}

func TestPlainHTTPOnlyWhenAllowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("[]")) }))
	defer srv.Close()
	if _, err := New(srv.URL, "o/r", "", false).ListReleases(context.Background()); !errors.Is(err, ErrHostNotAllowed) {
		t.Fatalf("http without allowPlainHTTP: %v", err)
	}
	if _, err := New(srv.URL, "o/r", "", false).Download(context.Background(), Asset{Name: "a", URL: srv.URL + "/a"}, 10); !errors.Is(err, ErrHostNotAllowed) {
		t.Fatalf("http download without allowPlainHTTP: %v", err)
	}
}

func TestRateLimit(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusTooManyRequests} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("X-Ratelimit-Remaining", "0")
			w.Header().Set("X-Ratelimit-Reset", "1792922400")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"message":"API rate limit exceeded"}`))
		}))
		_, err := New(srv.URL, "o/r", "", true).ListReleases(context.Background())
		srv.Close()
		var rl *RateLimitError
		if !errors.As(err, &rl) || !errors.Is(err, ErrRateLimited) || !rl.ResetAt.Equal(time.Unix(1792922400, 0)) {
			t.Fatalf("%d: %v", status, err)
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer srv.Close()
	if _, err := New(srv.URL, "o/r", "", true).ListReleases(context.Background()); err == nil || errors.Is(err, ErrRateLimited) {
		t.Fatalf("403 without the rate limit header: %v", err)
	}
}

func TestDownload(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("elsewhere")) }))
	defer other.Close()
	var accept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/file":
			accept = r.Header.Get("Accept")
			_, _ = w.Write([]byte("0123456789"))
		case r.URL.Path == "/away":
			http.Redirect(w, r, other.URL+"/file", http.StatusFound)
		case strings.HasPrefix(r.URL.Path, "/hop/"):
			n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/hop/"))
			if n == 0 {
				http.Redirect(w, r, "/file", http.StatusFound)
				return
			}
			http.Redirect(w, r, fmt.Sprintf("/hop/%d", n-1), http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := New(srv.URL, "o/r", "", true)
	ctx := context.Background()

	b, err := c.Download(ctx, Asset{Name: "f", Size: 10, URL: srv.URL + "/file"}, 10)
	if err != nil || string(b) != "0123456789" || accept != "application/octet-stream" {
		t.Fatalf("download = %q, %v, Accept %q", b, err, accept)
	}
	accept = ""
	if _, err := c.Download(ctx, Asset{Name: "f", Size: 11, URL: srv.URL + "/file"}, 10); !errors.Is(err, ErrTooLarge) || accept != "" {
		t.Fatalf("listed size above the limit: %v (downloaded: %v)", err, accept != "")
	}
	if _, err := c.Download(ctx, Asset{Name: "f", Size: 1, URL: srv.URL + "/file"}, 9); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("body above the limit: %v", err)
	}
	if _, err := c.Download(ctx, Asset{Name: "f", URL: other.URL + "/file"}, 10); !errors.Is(err, ErrHostNotAllowed) {
		t.Fatalf("asset on another host: %v", err)
	}
	if _, err := c.Download(ctx, Asset{Name: "f", URL: srv.URL + "/away"}, 10); !errors.Is(err, ErrHostNotAllowed) {
		t.Fatalf("redirect to another host: %v", err)
	}
	// /hop/n answers n+1 redirects in total.
	if b, err := c.Download(ctx, Asset{Name: "f", URL: srv.URL + "/hop/4"}, 10); err != nil || string(b) != "0123456789" {
		t.Fatalf("5 redirects on the base host: %q, %v", b, err)
	}
	if _, err := c.Download(ctx, Asset{Name: "f", URL: srv.URL + "/hop/5"}, 10); err == nil {
		t.Fatal("the 6th redirect was followed")
	}
	if _, err := c.Download(ctx, Asset{Name: "f", URL: srv.URL + "/missing"}, 10); err == nil {
		t.Fatal("404 accepted")
	}
}

func TestHostRule(t *testing.T) {
	c := New("https://api.github.com", "o/r", "", false)
	for raw, ok := range map[string]bool{
		"https://api.github.com/x":                       true,
		"https://github.com/o/r/releases/download/v1/a":  true,
		"https://objects.githubusercontent.com/x":        true,
		"https://release-assets.githubusercontent.com/x": true,
		"https://githubusercontent.com.evil.example/x":   false,
		"https://evilgithubusercontent.com/x":            false,
		"http://github.com/o/r/releases/download/v1/a":   false,
		"https://api.github.com:8443/x":                  false,
		"https://example.com/github.com":                 false,
	} {
		u, _ := http.NewRequest(http.MethodGet, raw, nil)
		if err := c.checkURL(u.URL); (err == nil) != ok {
			t.Errorf("%s: %v, want allowed %v", raw, err, ok)
		}
	}
}
