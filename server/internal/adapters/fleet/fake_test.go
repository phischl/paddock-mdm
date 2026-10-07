package fleet_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeFleet emulates the part of Fleet's API the adapter uses. The configuration starts as the recorded configuration
// of a freshly set-up Fleet (testdata/get_config.json) and PATCHes merge into it the way Fleet does: objects merge,
// null clears a field, and inside detail_query_overrides null is a value (the query is switched off).
type fakeFleet struct {
	t  *testing.T
	mu sync.Mutex

	config   map[string]any
	queries  map[int]map[string]any
	packs    map[int]string
	nextID   int
	requests []string // "METHOD path" of every request
	// failNext makes the next n requests answer 503.
	failNext int
}

const fakeToken = "fake-token"

func newFake(t *testing.T) (*fakeFleet, *httptest.Server) {
	t.Helper()
	data, err := os.ReadFile("testdata/get_config.json")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeFleet{t: t, queries: map[int]map[string]any{}, packs: map[int]string{}, nextID: 1}
	if err := json.Unmarshal(data, &f.config); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeFleet) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	if r.Header.Get("Authorization") != "Bearer "+fakeToken {
		http.Error(w, `{"message":"Authentication required"}`, http.StatusUnauthorized)
		return
	}
	if f.failNext > 0 {
		f.failNext--
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	body, _ := io.ReadAll(r.Body)
	path := r.URL.Path
	switch {
	case r.Method == http.MethodGet && path == "/api/latest/fleet/config":
		f.write(w, f.config)
	case r.Method == http.MethodPatch && path == "/api/latest/fleet/config":
		var patch map[string]any
		if err := json.Unmarshal(body, &patch); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		merge(f.config, patch, false)
		f.write(w, f.config)
	case r.Method == http.MethodGet && path == "/api/latest/fleet/queries":
		list := []map[string]any{}
		for _, q := range f.queries {
			list = append(list, q)
		}
		f.write(w, map[string]any{"queries": list})
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/latest/fleet/queries/id/"):
		id, _ := strconv.Atoi(strings.TrimPrefix(path, "/api/latest/fleet/queries/id/"))
		delete(f.queries, id)
		f.write(w, map[string]any{})
	case r.Method == http.MethodGet && path == "/api/latest/fleet/packs":
		list := []map[string]any{}
		for id, name := range f.packs {
			list = append(list, map[string]any{"id": id, "name": name})
		}
		f.write(w, map[string]any{"packs": list})
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/latest/fleet/packs/id/"):
		id, _ := strconv.Atoi(strings.TrimPrefix(path, "/api/latest/fleet/packs/id/"))
		delete(f.packs, id)
		f.write(w, map[string]any{})
	default:
		http.Error(w, "404 page not found", http.StatusNotFound)
	}
}

func (f *fakeFleet) write(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		f.t.Error(err)
	}
}

// merge applies patch to dst; overrides is true inside detail_query_overrides, whose null values are kept.
func merge(dst, patch map[string]any, overrides bool) {
	for k, v := range patch {
		switch v := v.(type) {
		case nil:
			if overrides {
				dst[k] = nil
			} else {
				delete(dst, k)
			}
		case map[string]any:
			sub, ok := dst[k].(map[string]any)
			if !ok {
				sub = map[string]any{}
				dst[k] = sub
			}
			merge(sub, v, k == "detail_query_overrides")
		default:
			dst[k] = v
		}
	}
}

// addQuery stores a saved query with an interval (0: not scheduled).
func (f *fakeFleet) addQuery(name string, interval int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries[f.nextID] = map[string]any{"id": f.nextID, "name": name, "interval": interval, "query": "SELECT 1;"}
	f.nextID++
}

func (f *fakeFleet) addPack(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.packs[f.nextID] = name
	f.nextID++
}

// section returns a copy of a top-level configuration object.
func (f *fakeFleet) section(name string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, _ := json.Marshal(f.config[name])
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	return out
}
