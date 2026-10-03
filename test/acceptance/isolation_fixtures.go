package acceptance

import (
	"net/http"
	"strings"
	"testing"

	"github.com/paddock-mdm/paddock/test/acceptance/internal/env"
)

// isolationWorld holds the sessions and the globex resources of the isolation gate.
type isolationWorld struct {
	alice, carol *env.Portal
	globexIDs    []string // every ID of globex the acme session must never see
	globexGroups []string
}

// isolationKind is what the gate expects from an operation called by an acme admin.
type isolationKind int

const (
	// isoItem: the operation addresses one globex resource by ID → 404 not_found without globex IDs.
	isoItem isolationKind = iota
	// isoList: the operation lists resources → 200 without globex IDs.
	isoList
	// isoOwn: the operation acts on the caller's own data → 2xx without globex IDs.
	isoOwn
)

type isolationFixture struct {
	kind isolationKind
	// request returns the concrete path and body for alice; item fixtures create the globex resource first.
	request func(t *testing.T, w *isolationWorld) (path string, body any)
}

// globexGroup creates a device group in globex as carol and returns its ID.
func globexGroup(t *testing.T, w *isolationWorld) string {
	t.Helper()
	res := call(t, w.carol, http.MethodPost, "/api/v1/device-groups", map[string]string{"name": uniqueName("globex isolation")})
	expectStatus(t, res, http.StatusCreated, "")
	var g struct {
		ID string `json:"id"`
	}
	if err := res.JSON(&g); err != nil {
		t.Fatal(err)
	}
	w.globexIDs = append(w.globexIDs, g.ID)
	w.globexGroups = append(w.globexGroups, g.ID)
	return g.ID
}

// isolationFixtures maps every operation of api/openapi/admin.yaml below /api/v1/ ("METHOD path"). The gate
// fails when the contract has an operation without an entry here.
var isolationFixtures = map[string]isolationFixture{
	"GET /api/v1/me": {kind: isoOwn, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/me", nil
	}},
	"PATCH /api/v1/me": {kind: isoOwn, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/me", map[string]string{"locale": "en"}
	}},
	"GET /api/v1/device-groups": {kind: isoList, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/device-groups?page_size=100", nil
	}},
	"POST /api/v1/device-groups": {kind: isoOwn, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/device-groups", map[string]string{"name": uniqueName("acme isolation")}
	}},
	"GET /api/v1/device-groups/{id}": {kind: isoItem, request: func(t *testing.T, w *isolationWorld) (string, any) {
		return "/api/v1/device-groups/" + globexGroup(t, w), nil
	}},
	"PATCH /api/v1/device-groups/{id}": {kind: isoItem, request: func(t *testing.T, w *isolationWorld) (string, any) {
		return "/api/v1/device-groups/" + globexGroup(t, w), map[string]string{"name": "taken over by acme"}
	}},
	"DELETE /api/v1/device-groups/{id}": {kind: isoItem, request: func(t *testing.T, w *isolationWorld) (string, any) {
		return "/api/v1/device-groups/" + globexGroup(t, w), nil
	}},
	"GET /api/v1/audit-events": {kind: isoList, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/audit-events?page_size=100", nil
	}},
}

func fixtureKey(method, path string) string { return strings.ToUpper(method) + " " + path }
