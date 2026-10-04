package acceptance

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/paddock-mdm/paddock/test/acceptance/internal/env"
)

// isolationWorld holds the sessions and the globex resources of the isolation gate.
type isolationWorld struct {
	// top is the gate's test: globex resources live until it ends, also those its subtests create.
	top          *testing.T
	alice, carol *env.Portal
	globexIDs    []string // every ID of globex the acme session must never see
	globexGroups []string
	// Globex device control plane resources (seedGlobexDevices).
	globexToken, globexDevice, globexFile, globexUnit, globexDeviceGroup string
}

// seedGlobexDevices creates, as carol, a device group with an enrolled device (through the device API), an
// enrollment token, a managed file and a managed unit of that group — all named "globex-iso…" so the list searches
// find them.
func seedGlobexDevices(t *testing.T, w *isolationWorld) {
	t.Helper()
	w.globexDeviceGroup = namedGroup(t, w.carol, "globex isolation devices")
	tok := createToken(t, w.carol, tokenOptions{name: uniqueName("globex isolation token"), autoApprove: true})
	w.globexToken = tok.Token.ID
	dev, s := enroll(t, tok.EnrollmentConfig, "globex-iso-"+uniqueSuffix())
	if s.Status != "active" {
		t.Fatalf("globex device enrollment %+v", s)
	}
	w.globexDevice = dev.DeviceID
	res := call(t, w.carol, http.MethodPut, "/api/v1/devices/"+dev.DeviceID+"/groups", map[string]any{"device_group_ids": []string{w.globexDeviceGroup}})
	expectStatus(t, res, http.StatusOK, "")
	res = call(t, w.carol, http.MethodPost, "/api/v1/managed-files", map[string]any{
		"path": "/etc/globex-iso-" + uniqueSuffix() + ".conf", "content": "globex", "device_group_id": w.globexDeviceGroup,
	})
	expectStatus(t, res, http.StatusCreated, "")
	w.globexFile = createdID(t, w.carol, "/api/v1/managed-files", res)
	res = call(t, w.carol, http.MethodPost, "/api/v1/managed-units", map[string]any{
		"unit": testUnitPrefix + "globex-iso-" + uniqueSuffix() + ".service", "device_group_id": w.globexDeviceGroup,
	})
	expectStatus(t, res, http.StatusCreated, "")
	w.globexUnit = createdID(t, w.carol, "/api/v1/managed-units", res)
	w.globexIDs = append(w.globexIDs, w.globexDeviceGroup, w.globexToken, w.globexDevice, w.globexFile, w.globexUnit)
	w.globexGroups = append(w.globexGroups, w.globexDeviceGroup)
}

// itemFixture is an item operation on one globex resource.
func itemFixture(path func(w *isolationWorld) string, body any) isolationFixture {
	return isolationFixture{kind: isoItem, request: func(_ *testing.T, w *isolationWorld) (string, any) { return path(w), body }}
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
	id := createdID(w.top, w.carol, "/api/v1/device-groups", res)
	w.globexIDs = append(w.globexIDs, id)
	w.globexGroups = append(w.globexGroups, id)
	return id
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

	"GET /api/v1/enrollment-tokens": {kind: isoList, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/enrollment-tokens?page_size=100", nil
	}},
	"POST /api/v1/enrollment-tokens": {kind: isoOwn, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/enrollment-tokens", map[string]any{"name": uniqueName("acme isolation"), "max_uses": 1,
			"auto_approve": false, "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	}},
	"GET /api/v1/enrollment-tokens/{id}":         itemFixture(func(w *isolationWorld) string { return "/api/v1/enrollment-tokens/" + w.globexToken }, nil),
	"POST /api/v1/enrollment-tokens/{id}/revoke": itemFixture(func(w *isolationWorld) string { return "/api/v1/enrollment-tokens/" + w.globexToken + "/revoke" }, nil),

	"GET /api/v1/devices": {kind: isoList, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/devices?page_size=100", nil
	}},
	"GET /api/v1/devices/{id}":                     itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice }, nil),
	"POST /api/v1/devices/{id}/approve":            itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/approve" }, nil),
	"POST /api/v1/devices/{id}/reject":             itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/reject" }, nil),
	"POST /api/v1/devices/{id}/release-quarantine": itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/release-quarantine" }, nil),
	"POST /api/v1/devices/{id}/retire":             itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/retire" }, nil),
	"PUT /api/v1/devices/{id}/groups": itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/groups" },
		map[string]any{"device_group_ids": []string{}}),
	"GET /api/v1/devices/{id}/effective-config": itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/effective-config" }, nil),
	"GET /api/v1/device-groups/{id}/devices":    itemFixture(func(w *isolationWorld) string { return "/api/v1/device-groups/" + w.globexDeviceGroup + "/devices" }, nil),

	"GET /api/v1/managed-files": {kind: isoList, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/managed-files?page_size=100", nil
	}},
	"POST /api/v1/managed-files": {kind: isoOwn, request: func(t *testing.T, w *isolationWorld) (string, any) {
		return "/api/v1/managed-files", map[string]any{"path": "/etc/acme-iso-" + uniqueSuffix() + ".conf", "content": "acme",
			"device_group_id": namedGroup(t, w.alice, "acme isolation scope")}
	}},
	"GET /api/v1/managed-files/{id}":    itemFixture(func(w *isolationWorld) string { return "/api/v1/managed-files/" + w.globexFile }, nil),
	"PATCH /api/v1/managed-files/{id}":  itemFixture(func(w *isolationWorld) string { return "/api/v1/managed-files/" + w.globexFile }, map[string]any{"content": "taken over by acme"}),
	"DELETE /api/v1/managed-files/{id}": itemFixture(func(w *isolationWorld) string { return "/api/v1/managed-files/" + w.globexFile }, nil),

	"GET /api/v1/managed-units": {kind: isoList, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/managed-units?page_size=100", nil
	}},
	"POST /api/v1/managed-units": {kind: isoOwn, request: func(t *testing.T, w *isolationWorld) (string, any) {
		return "/api/v1/managed-units", map[string]any{"unit": testUnitPrefix + "acme-iso-" + uniqueSuffix() + ".service",
			"device_group_id": namedGroup(t, w.alice, "acme isolation scope")}
	}},
	"GET /api/v1/managed-units/{id}":    itemFixture(func(w *isolationWorld) string { return "/api/v1/managed-units/" + w.globexUnit }, nil),
	"PATCH /api/v1/managed-units/{id}":  itemFixture(func(w *isolationWorld) string { return "/api/v1/managed-units/" + w.globexUnit }, map[string]any{"enabled": false}),
	"DELETE /api/v1/managed-units/{id}": itemFixture(func(w *isolationWorld) string { return "/api/v1/managed-units/" + w.globexUnit }, nil),
}

// listParents resolves the parent ID of collection GETs below an item (path with {id}): the globex parent whose
// data carol finds and alice must get 404 for.
var listParents = map[string]func(w *isolationWorld) string{
	"/api/v1/device-groups/{id}/devices": func(w *isolationWorld) string { return w.globexDeviceGroup },
}

func fixtureKey(method, path string) string { return strings.ToUpper(method) + " " + path }

// listIsolationQueries holds, for every collection GET below /api/v1/, searches and filters that find globex data
// when carol runs them; alice running them must never see it (plan M0.2 step 2, AC5). The gate fails when the
// contract has a collection GET without an entry here.
var listIsolationQueries = map[string][]url.Values{
	"/api/v1/device-groups": {
		{"q": {"globex isolation"}},
		{"q": {"isolation"}, "sort": {"-created_at"}, "page_size": {"100"}},
	},
	"/api/v1/audit-events": {
		{"q": {"globex isolation"}},
		{"q": {"carol"}},
		{"code": {"device_group.created"}, "page_size": {"100"}},
		{"outcome": {"success"}, "actor_type": {"admin"}, "page_size": {"100"}},
		// Not "device_group": acme's own failed attempts on globex IDs (the item checks above) are acme events that
		// carry the ID alice sent.
		{"q": {"created"}, "sort": {"-code"}, "page_size": {"100"}},
	},
	"/api/v1/enrollment-tokens": {
		{"q": {"globex isolation"}},
		{"sort": {"-expires_at"}, "page_size": {"100"}},
	},
	"/api/v1/devices": {
		{"q": {"globex-iso"}},
		{"state": {"active"}, "sort": {"-last_contact_at"}, "page_size": {"100"}},
	},
	"/api/v1/managed-files":              {{"q": {"globex-iso"}}},
	"/api/v1/managed-units":              {{"q": {"globex-iso"}}},
	"/api/v1/device-groups/{id}/devices": {{"q": {"globex-iso"}}, {"state": {"active"}}},
}
