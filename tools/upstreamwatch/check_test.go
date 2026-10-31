package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

const newRuntimeDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fakeUpstream serves the Docker Hub API, an OCI registry with anonymous token exchange and Link pagination, a
// manifest digest and the Himmelblau index from the fixtures.
func fakeUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/repositories/library/caddy/tags", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" {
			_, _ = w.Write(fixture(t, "hub-page2.json"))
			return
		}
		if r.URL.Query().Get("page_size") != "100" || r.URL.Query().Get("ordering") != "last_updated" {
			t.Errorf("hub query = %s", r.URL.RawQuery)
		}
		next := srv.URL + "/v2/repositories/library/caddy/tags?page=2"
		_, _ = w.Write(bytes.Replace(fixture(t, "hub-page1.json"), []byte("NEXT"), []byte(next), 1))
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("scope") == "" || r.URL.Query().Get("service") != "registry" {
			t.Errorf("token query = %s", r.URL.RawQuery)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "anon"})
	})
	challenge := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") == "Bearer anon" {
			return false
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="`+srv.URL+`/token",service="registry",scope="repository:x:pull"`)
		w.WriteHeader(http.StatusUnauthorized)
		return true
	}
	mux.HandleFunc("/v2/goauthentik/server/tags/list", func(w http.ResponseWriter, r *http.Request) {
		if challenge(w, r) {
			return
		}
		if r.URL.Query().Get("last") != "" {
			_, _ = w.Write(fixture(t, "oci-tags-page2.json"))
			return
		}
		w.Header().Set("Link", `</v2/goauthentik/server/tags/list?last=2026.8.4-rc1&n=1000>; rel="next"`)
		_, _ = w.Write(fixture(t, "oci-tags-page1.json"))
	})
	mux.HandleFunc("/v2/distroless/static-debian12/manifests/nonroot", func(w http.ResponseWriter, r *http.Request) {
		if challenge(w, r) {
			return
		}
		if r.Method != http.MethodHead || !strings.Contains(r.Header.Get("Accept"), "image.index") {
			t.Errorf("manifest request %s accept %q", r.Method, r.Header.Get("Accept"))
		}
		w.Header().Set("Docker-Content-Digest", newRuntimeDigest)
	})
	mux.HandleFunc("/stable/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(fixture(t, "himmelblau-index.html"))
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func upstreamAt(base string, c *http.Client) *Upstream {
	return &Upstream{
		Registries:      &Registries{HTTP: c, HubBase: base, RegistryURL: func(string) string { return base }},
		HTTP:            c,
		HimmelblauIndex: base + "/stable/",
		LatestRelease: func(_ context.Context, repo string) (string, error) {
			if repo != "fleetdm/nvd" {
				return "", os.ErrNotExist
			}
			b, err := os.ReadFile("testdata/release.json")
			if err != nil {
				return "", err
			}
			return ParseLatestRelease(b)
		},
	}
}

func TestCheckAgainstFixtures(t *testing.T) {
	srv := fakeUpstream(t)
	var out, errOut bytes.Buffer
	code := run(context.Background(), []string{"check", "--versions", "testdata/versions.env", "--compiler", "testdata/compiler.go.txt"},
		&out, &errOut, upstreamAt(srv.URL, srv.Client()), nil)
	if code != 0 {
		t.Fatalf("exit %d, stderr %s", code, errOut.String())
	}
	want := strings.Join([]string{
		"caddy 2.11.6 2.11.7 patch",
		"rabbitmq 4.3.6-management - unknown",
		"authentik 2026.8.3 2026.10.1 minor",
		"runtime nonroot@sha256:afa5c872c891 nonroot@sha256:111111111111 digest",
		"fleet_nvd 202610120101 202610180059 patch",
		"himmelblau 4.0.4 4.0.6 patch",
	}, "\n") + "\n"
	if out.String() != want {
		t.Fatalf("output\n%s\nwant\n%s", out.String(), want)
	}
	if !strings.Contains(errOut.String(), "rabbitmq") {
		t.Fatalf("stderr does not name the failed lookup: %s", errOut.String())
	}
}

func TestCheckJSON(t *testing.T) {
	srv := fakeUpstream(t)
	var out, errOut bytes.Buffer
	code := run(context.Background(), []string{"check", "--json", "--versions", "testdata/versions.env", "--compiler", "testdata/compiler.go.txt"},
		&out, &errOut, upstreamAt(srv.URL, srv.Client()), nil)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	var rows []map[string]string
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil || len(rows) != 6 {
		t.Fatalf("json %v: %s", err, out.String())
	}
	if rows[0]["release_notes"] != "https://github.com/caddyserver/caddy/releases/tag/2.11.7" {
		t.Fatalf("release notes = %q", rows[0]["release_notes"])
	}
}

// A network error makes every pin unknown and the run still exits 0.
func TestCheckNetworkErrorIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	base := srv.URL
	c := srv.Client()
	srv.Close()
	var out, errOut bytes.Buffer
	code := run(context.Background(), []string{"check", "--versions", "testdata/versions.env", "--compiler", "testdata/compiler.go.txt"},
		&out, &errOut, upstreamAt(base, c), nil)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if strings.HasPrefix(line, "fleet_nvd") {
			continue
		}
		if !strings.HasSuffix(line, " - unknown") {
			t.Errorf("line %q is not unknown", line)
		}
	}
}

func TestRunRefusesMissingInputs(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"check", "--versions", "testdata/missing.env"}, &out, &errOut, nil, nil); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if code := run(context.Background(), []string{"issues", "--versions", "testdata/versions.env", "--compiler", "testdata/compiler.go.txt"}, &out, &errOut, nil, nil); code != 2 {
		t.Fatalf("issues without --repo: exit %d, want 2", code)
	}
	if code := run(context.Background(), nil, &out, &errOut, nil, nil); code != 2 {
		t.Fatalf("no command: exit %d, want 2", code)
	}
}

func TestHubNameFilter(t *testing.T) {
	cases := map[string]string{"2.11.6": "", "4.3.6-management": "-management", "24.21.0-trixie-slim": "-trixie-slim", "v4.92.3": "", "qemu-v10.2.3-68": "qemu-v"}
	for in, want := range cases {
		if got := hubNameFilter(in); got != want {
			t.Errorf("hubNameFilter(%q) = %q, want %q", in, got, want)
		}
	}
}

// A pin with a line compares only with that line; when the line has no tag the error names it.
func TestCheckFollowsTheLine(t *testing.T) {
	tags := `{"next":null,"results":[{"name":"26.10.0"},{"name":"9.7.4"},{"name":"8.4.13"},{"name":"8.4.12"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(tags)) }))
	defer srv.Close()
	u := upstreamAt(srv.URL, srv.Client())
	img, err := ParseImage("mysql:8.4.11@sha256:aa")
	if err != nil {
		t.Fatal(err)
	}
	pin := Pin{Info: PinInfo{Name: "fleet_mysql", Line: "8.4."}, Kind: KindImage, Image: img, Pinned: "8.4.11"}

	if r := u.check(context.Background(), pin); r.Latest != "8.4.13" || r.Class != ClassPatch || r.Err != nil {
		t.Errorf("with line: %+v", r)
	}
	pin.Info.Line = ""
	if r := u.check(context.Background(), pin); r.Latest != "26.10.0" || r.Class != ClassMajor {
		t.Errorf("without line: %+v", r)
	}
	pin.Info.Line = "8.5."
	r := u.check(context.Background(), pin)
	if r.Class != ClassUnknown || r.Err == nil || !strings.Contains(r.Err.Error(), `no tag of the shape ^\d+\.\d+\.\d+$ in line 8.5.`) {
		t.Errorf("empty line: %+v", r)
	}
}
