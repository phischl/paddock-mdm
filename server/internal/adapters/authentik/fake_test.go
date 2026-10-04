package authentik_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

// fakeAuthentik emulates the part of the Authentik API the adapter uses over an in-memory store. Every response body
// is a recorded fixture of the pinned Authentik version (testdata/) with the store's values filled in, so the adapter
// decodes exactly the shapes the real API returns.
type fakeAuthentik struct {
	t  *testing.T
	mu sync.Mutex

	groups   map[string]*fakeGroup // pk → group
	users    map[int]*fakeUser
	objects  map[string]map[string]map[string]any // collection → pk → object (flows, mappings, providers, …)
	tokens   map[string][]int                     // "refresh_tokens"/"access_tokens" → owning user pks
	sessions map[int]int                          // user pk → number of sessions
	nextPK   int
	// deactivations counts PATCHes with is_active false.
	deactivations int

	requests []string // "METHOD path" of every request
	// failNext makes the next n requests answer with failStatus.
	failNext   int
	failStatus int
}

type fakeGroup struct {
	pk, name string
	parents  []string
}

type fakeUser struct {
	pk                    int
	username, name, email string
	attributes            map[string]any
	groups                []string
	inactive              bool
}

func newFake(t *testing.T) (*fakeAuthentik, *httptest.Server) {
	f := &fakeAuthentik{
		t: t, groups: map[string]*fakeGroup{}, users: map[int]*fakeUser{}, nextPK: 1,
		objects: map[string]map[string]map[string]any{}, tokens: map[string][]int{}, sessions: map[int]int{},
	}
	// Objects of Authentik's defaults and of the Paddock blueprints.
	for _, slug := range []string{"paddock-device-authentication", "paddock-device-authorization", "default-provider-invalidation-flow"} {
		f.put("flows", map[string]any{"pk": uuid.NewString(), "slug": slug, "name": slug})
	}
	f.put("certificatekeypairs", map[string]any{"pk": uuid.NewString(), "name": "authentik Self-signed Certificate"})
	for _, scope := range []string{"openid", "email", "profile", "offline_access"} {
		f.put("scopemappings", map[string]any{"pk": uuid.NewString(), "name": "authentik default OAuth Mapping: " + scope,
			"managed": "goauthentik.io/providers/oauth2/scope-" + scope, "scope_name": scope})
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeAuthentik) put(collection string, obj map[string]any) {
	if f.objects[collection] == nil {
		f.objects[collection] = map[string]map[string]any{}
	}
	f.objects[collection][key(obj["pk"])] = obj
}

func key(pk any) string {
	if n, ok := pk.(int); ok {
		return strconv.Itoa(n)
	}
	s, _ := pk.(string)
	return s
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

// page renders items into the recorded envelope of a list response.
func (f *fakeAuthentik) page(items []map[string]any) map[string]any {
	p := f.fixture("get_providers_oauth2.json")
	if items == nil {
		items = []map[string]any{}
	}
	p["results"] = items
	p["pagination"].(map[string]any)["count"] = len(items)
	return p
}

func (f *fakeAuthentik) groupJSON(g *fakeGroup) map[string]any {
	j := f.fixture("post_core_groups.json")
	j["pk"], j["name"], j["parents"] = g.pk, g.name, g.parents
	return j
}

func (f *fakeAuthentik) userJSON(u *fakeUser) map[string]any {
	j := f.fixture("post_core_users.json")
	j["pk"], j["username"], j["name"], j["email"], j["attributes"], j["groups"] = u.pk, u.username, u.name, u.email, u.attributes, u.groups
	j["groups_obj"] = nil
	return j
}

var (
	reGroup       = regexp.MustCompile(`^/api/v3/core/groups/([^/]+)/(add_user/|remove_user/)?$`)
	reUser        = regexp.MustCompile(`^/api/v3/core/users/([0-9]+)/(recovery/)?$`)
	reApplication = regexp.MustCompile(`^/api/v3/core/applications/([^/]+)/$`)
	reObject      = regexp.MustCompile(`^/api/v3/(providers/oauth2|propertymappings/provider/scope|policies/expression)/([^/]+)/$`)
)

// collections maps list paths to the store collection and the recorded create response.
var collections = map[string]struct{ name, fixture string }{
	"/api/v3/flows/instances/":                 {"flows", ""},
	"/api/v3/crypto/certificatekeypairs/":      {"certificatekeypairs", ""},
	"/api/v3/propertymappings/provider/scope/": {"scopemappings", "post_propertymappings_provider_scope.json"},
	"/api/v3/providers/oauth2/":                {"providers", "post_providers_oauth2.json"},
	"/api/v3/policies/expression/":             {"policies", "post_policies_expression.json"},
	"/api/v3/policies/bindings/":               {"bindings", "post_policies_bindings.json"},
	"/api/v3/core/applications/":               {"applications", "post_core_applications.json"},
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
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	var body map[string]any
	if r.Body != nil && r.ContentLength != 0 {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	status, out := f.route(r, body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if out != nil {
		_ = json.NewEncoder(w).Encode(out)
	}
}

func (f *fakeAuthentik) route(r *http.Request, body map[string]any) (int, any) {
	p, q := r.URL.Path, r.URL.Query()
	switch {
	case p == "/api/v3/core/groups/" && r.Method == http.MethodGet:
		var items []map[string]any
		for _, g := range f.sortedGroups() {
			if name := q.Get("name"); name == "" || g.name == name {
				items = append(items, f.groupJSON(g))
			}
		}
		return http.StatusOK, f.page(items)
	case p == "/api/v3/core/groups/" && r.Method == http.MethodPost:
		name, _ := body["name"].(string)
		for _, g := range f.groups {
			if g.name == name {
				return http.StatusBadRequest, map[string]any{"name": []string{"group with this name already exists."}}
			}
		}
		g := &fakeGroup{pk: uuid.NewString(), name: name, parents: []string{}}
		if parents, ok := body["parents"].([]any); ok {
			for _, x := range parents {
				g.parents = append(g.parents, x.(string))
			}
		}
		f.groups[g.pk] = g
		return http.StatusCreated, f.groupJSON(g)
	case reGroup.MatchString(p):
		m := reGroup.FindStringSubmatch(p)
		g, ok := f.groups[m[1]]
		if !ok {
			return http.StatusNotFound, f.fixture("delete_core_groups_id_404.json")
		}
		switch {
		case r.Method == http.MethodDelete:
			delete(f.groups, g.pk)
			return http.StatusNoContent, nil
		case m[2] == "add_user/" || m[2] == "remove_user/":
			u, ok := f.users[int(body["pk"].(float64))]
			if !ok {
				return http.StatusBadRequest, map[string]any{"pk": []string{"invalid"}}
			}
			u.groups = slices.DeleteFunc(u.groups, func(x string) bool { return x == g.pk })
			if m[2] == "add_user/" {
				u.groups = append(u.groups, g.pk)
			}
			return http.StatusNoContent, nil
		}
	case p == "/api/v3/core/users/" && r.Method == http.MethodGet:
		return f.listUsers(q)
	case p == "/api/v3/core/users/" && r.Method == http.MethodPost:
		username, _ := body["username"].(string)
		for _, u := range f.users {
			if u.username == username {
				return http.StatusBadRequest, f.fixture("post_core_users_400.json")
			}
		}
		u := &fakeUser{pk: f.nextPK, username: username, attributes: map[string]any{}, groups: []string{}}
		f.nextPK++
		u.name, _ = body["name"].(string)
		u.email, _ = body["email"].(string)
		if attrs, ok := body["attributes"].(map[string]any); ok {
			u.attributes = attrs
		}
		if groups, ok := body["groups"].([]any); ok {
			for _, g := range groups {
				u.groups = append(u.groups, g.(string))
			}
		}
		f.users[u.pk] = u
		return http.StatusCreated, f.userJSON(u)
	case reUser.MatchString(p):
		m := reUser.FindStringSubmatch(p)
		pk, _ := strconv.Atoi(m[1])
		u, ok := f.users[pk]
		if !ok {
			return http.StatusNotFound, f.fixture("delete_core_users_id_404.json")
		}
		switch {
		case m[2] == "recovery/":
			link := f.fixture("post_core_users_id_recovery.json")
			link["link"] = "https://auth.example.org/if/flow/paddock-recovery/?flow_token=t" + m[1] + "&d=" + key(body["token_duration"])
			return http.StatusOK, link
		case r.Method == http.MethodPatch:
			if active, ok := body["is_active"].(bool); ok {
				u.inactive = !active
				if !active { // Authentik's deactivation cleanup: every token and session of the user
					f.deactivations++
					for kind, owners := range f.tokens {
						for i, owner := range owners {
							if owner == u.pk {
								f.tokens[kind][i] = 0
							}
						}
					}
					delete(f.sessions, u.pk)
				}
				return http.StatusOK, f.userJSON(u)
			}
			u.name, _ = body["name"].(string)
			u.email, _ = body["email"].(string)
			return http.StatusOK, f.userJSON(u)
		case r.Method == http.MethodDelete:
			delete(f.users, pk)
			return http.StatusNoContent, nil
		}
	case reApplication.MatchString(p):
		app, ok := f.objects["applications"][reApplication.FindStringSubmatch(p)[1]]
		if !ok {
			return http.StatusNotFound, f.fixture("get_core_applications_paddock-device-fixture-org_404.json")
		}
		if r.Method == http.MethodPatch {
			for k, v := range body {
				app[k] = v
			}
		}
		return http.StatusOK, app
	case reObject.MatchString(p):
		m := reObject.FindStringSubmatch(p)
		coll := collections["/api/v3/"+m[1]+"/"].name
		obj, ok := f.objects[coll][m[2]]
		if !ok {
			return http.StatusNotFound, f.fixture("delete_core_groups_id_404.json")
		}
		if r.Method == http.MethodPut || r.Method == http.MethodPatch {
			for k, v := range body {
				obj[k] = v
			}
		}
		return http.StatusOK, obj
	default:
		if c, ok := collections[p]; ok {
			return f.collection(r.Method, c.name, c.fixture, q, body)
		}
	}
	return http.StatusNotFound, f.fixture("delete_core_groups_id_404.json")
}

// collection lists (filtered by every query parameter that names a field) or creates objects.
func (f *fakeAuthentik) collection(method, name, fixture string, q map[string][]string, body map[string]any) (int, any) {
	if method == http.MethodPost {
		obj := f.fixture(fixture)
		for k, v := range body {
			obj[k] = v
		}
		if name == "providers" {
			obj["pk"] = f.nextPK
			f.nextPK++
		} else {
			obj["pk"] = uuid.NewString()
		}
		if name == "applications" { // looked up by slug
			if f.objects["applications"] == nil {
				f.objects["applications"] = map[string]map[string]any{}
			}
			f.objects["applications"][body["slug"].(string)] = obj
			return http.StatusCreated, obj
		}
		f.put(name, obj)
		return http.StatusCreated, obj
	}
	var items []map[string]any
	for _, obj := range f.objects[name] {
		match := true
		for k, v := range q {
			if k == "page" || k == "page_size" || k == "ordering" {
				continue
			}
			if got := obj[k]; got == nil || key(got) != v[0] && strconv.Itoa(intOf(got)) != v[0] {
				match = false
			}
		}
		if match {
			items = append(items, obj)
		}
	}
	return http.StatusOK, f.page(items)
}

func intOf(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	}
	return -1
}

func (f *fakeAuthentik) listUsers(q map[string][]string) (int, any) {
	var match []*fakeUser
	for _, u := range f.users {
		if name := first(q["groups_by_name"]); name != "" && !slices.ContainsFunc(u.groups, func(pk string) bool { return f.groups[pk] != nil && f.groups[pk].name == name }) {
			continue
		}
		if pk := first(q["groups_by_pk"]); pk != "" && !slices.Contains(u.groups, pk) {
			continue
		}
		match = append(match, u)
	}
	slices.SortFunc(match, func(a, b *fakeUser) int { return a.pk - b.pk })
	size, _ := strconv.Atoi(first(q["page_size"]))
	page, _ := strconv.Atoi(first(q["page"]))
	from := min((page-1)*size, len(match))
	to := min(from+size, len(match))
	var items []map[string]any
	for _, u := range match[from:to] {
		items = append(items, f.userJSON(u))
	}
	out := f.page(items)
	if to < len(match) {
		out["pagination"].(map[string]any)["next"] = page + 1
	}
	return http.StatusOK, out
}

func (f *fakeAuthentik) sortedGroups() []*fakeGroup {
	var out []*fakeGroup
	for _, g := range f.groups {
		out = append(out, g)
	}
	slices.SortFunc(out, func(a, b *fakeGroup) int { return strings.Compare(a.name, b.name) })
	return out
}

func (f *fakeAuthentik) groupByName(name string) *fakeGroup {
	for _, g := range f.groups {
		if g.name == name {
			return g
		}
	}
	return nil
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}
