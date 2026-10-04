package authentik_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/server/internal/adapters/authentik"
	"github.com/paddock-mdm/paddock/server/internal/domain/organization"
	"github.com/paddock-mdm/paddock/server/internal/problem"
)

// fakeAuthentik replays the recorded responses of the pinned Authentik version (testdata/) over an in-memory store.
type fakeAuthentik struct {
	t      *testing.T
	mu     sync.Mutex
	groups map[string]string // name → pk
	gets   int
	posts  int
	// failNext makes the next n requests answer with the given status.
	failNext   int
	failStatus int
}

func newFake(t *testing.T) (*fakeAuthentik, *httptest.Server) {
	f := &fakeAuthentik{t: t, groups: map[string]string{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeAuthentik) fixture(name string) map[string]any {
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		f.t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		f.t.Fatal(err)
	}
	return m
}

func (f *fakeAuthentik) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer test-token" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if f.failNext > 0 {
		f.failNext--
		w.WriteHeader(f.failStatus)
		_, _ = w.Write([]byte(`{"detail":"injected"}`))
		return
	}
	if r.URL.Path != "/api/v3/core/groups/" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		f.gets++
		name := r.URL.Query().Get("name")
		pk, ok := f.groups[name]
		if !ok {
			_ = json.NewEncoder(w).Encode(f.fixture("groups_list_empty.json"))
			return
		}
		page := f.fixture("groups_list_found.json")
		g := page["results"].([]any)[0].(map[string]any)
		g["pk"], g["name"] = pk, name
		_ = json.NewEncoder(w).Encode(page)
	case http.MethodPost:
		f.posts++
		var body struct {
			Name    string   `json:"name"`
			Parents []string `json:"parents"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if _, exists := f.groups[body.Name]; exists {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(f.fixture("groups_create_duplicate.json"))
			return
		}
		pk := uuid.NewString()
		f.groups[body.Name] = pk
		g := f.fixture("groups_create.json")
		if len(body.Parents) > 0 {
			g = f.fixture("groups_create_child.json")
		}
		g["pk"], g["name"], g["parents"] = pk, body.Name, body.Parents
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(g)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func client(srv *httptest.Server) *authentik.Client {
	return authentik.New(srv.URL, "test-token").WithBackoff(time.Millisecond)
}

func TestEnsureOrganizationIsIdempotent(t *testing.T) {
	f, srv := newFake(t)
	c := client(srv)
	first, err := c.EnsureOrganization(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	if f.posts != 4 {
		t.Fatalf("first call created %d groups, want 4", f.posts)
	}
	for _, name := range []string{
		organization.RootGroup("acme"),
		organization.RoleGroup("acme", organization.GroupAdmins),
		organization.RoleGroup("acme", organization.GroupOperators),
		organization.RoleGroup("acme", organization.GroupAuditors),
	} {
		if _, ok := f.groups[name]; !ok {
			t.Errorf("group %s missing", name)
		}
	}
	second, err := c.EnsureOrganization(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	if f.posts != 4 {
		t.Fatalf("second call created groups (%d POSTs in total)", f.posts)
	}
	if first != second || first.AdminsGroupPK != f.groups[organization.RoleGroup("acme", organization.GroupAdmins)] {
		t.Fatalf("refs differ: %+v vs %+v", first, second)
	}
}

func TestRetryOn5xx(t *testing.T) {
	f, srv := newFake(t)
	f.failNext, f.failStatus = 2, http.StatusBadGateway
	if _, err := client(srv).EnsureOrganization(context.Background(), "globex"); err != nil {
		t.Fatalf("EnsureOrganization after two 502s: %v", err)
	}
	if len(f.groups) != 4 {
		t.Fatalf("%d groups, want 4", len(f.groups))
	}
}

func TestGiveUpAfterThreeRetries(t *testing.T) {
	f, srv := newFake(t)
	f.failNext, f.failStatus = 100, http.StatusServiceUnavailable
	_, err := client(srv).EnsureOrganization(context.Background(), "globex")
	if !errors.Is(err, problem.UpstreamUnavailable) {
		t.Fatalf("error = %v, want upstream_unavailable", err)
	}
	if used := 100 - f.failNext; used != 4 {
		t.Fatalf("%d attempts, want 1 + 3 retries", used)
	}
}

func TestNoRetryOn4xx(t *testing.T) {
	f, srv := newFake(t)
	f.failNext, f.failStatus = 1, http.StatusForbidden
	_, err := client(srv).EnsureOrganization(context.Background(), "initech")
	if !errors.Is(err, problem.UpstreamUnavailable) || !strings.Contains(err.Error(), "403") {
		t.Fatalf("error = %v, want upstream_unavailable wrapping HTTP 403", err)
	}
	if f.gets+f.posts != 0 || f.failNext != 0 {
		t.Fatalf("a 4xx was retried (%d further requests)", f.gets+f.posts)
	}
}

func TestNetworkErrorIsRetriedThenUpstream(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close() // connection refused
	_, err := authentik.New(srv.URL, "test-token").WithBackoff(time.Millisecond).EnsureOrganization(context.Background(), "acme")
	if !errors.Is(err, problem.UpstreamUnavailable) {
		t.Fatalf("error = %v, want upstream_unavailable", err)
	}
}
