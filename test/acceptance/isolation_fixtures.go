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
	// Globex identity resources (seedGlobexIdentity).
	globexUser, globexUserGroup, globexProfile, globexAssignment string
	// globexUpstream is the Authentik pk of an upstream group whose only member is a globex user (seedGlobexUpstream).
	globexUpstream string
}

// seedGlobexIdentity creates, as carol, a local user in a user group, a permission profile and its assignment to the
// group — all named "globex-iso…" so the list searches find them. They are deleted when the gate ends.
func seedGlobexIdentity(t *testing.T, w *isolationWorld) {
	t.Helper()
	res := call(t, w.carol, http.MethodPost, "/api/v1/users", map[string]string{
		"username": "globex-iso-" + uniqueSuffix() + "@globex.test", "display_name": "globex-iso user",
	})
	expectStatus(t, res, http.StatusCreated, "")
	var created struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := res.JSON(&created); err != nil {
		t.Fatal(err)
	}
	w.globexUser = created.User.ID
	deleteOnCleanup(w.top, w.carol, "/api/v1/users/"+w.globexUser)
	res = call(t, w.carol, http.MethodPost, "/api/v1/user-groups", map[string]string{"slug": "globex-iso-" + uniqueSuffix(), "name": "globex-iso group"})
	expectStatus(t, res, http.StatusCreated, "")
	w.globexUserGroup = createdID(w.top, w.carol, "/api/v1/user-groups", res)
	res = call(t, w.carol, http.MethodPost, "/api/v1/user-groups/"+w.globexUserGroup+"/members", map[string]string{"user_id": w.globexUser})
	expectStatus(t, res, http.StatusNoContent, "")
	res = call(t, w.carol, http.MethodPost, "/api/v1/permission-profiles", map[string]any{
		"name": "globex-iso profile " + uniqueSuffix(), "class": "restricted", "commands": []string{"/usr/bin/systemctl restart globex.service"},
	})
	expectStatus(t, res, http.StatusCreated, "")
	w.globexProfile = createdID(w.top, w.carol, "/api/v1/permission-profiles", res)
	res = call(t, w.carol, http.MethodPost, "/api/v1/profile-assignments", map[string]any{
		"profile_id": w.globexProfile, "subject_type": "group", "subject_id": w.globexUserGroup,
	})
	expectStatus(t, res, http.StatusCreated, "")
	w.globexAssignment = createdID(w.top, w.carol, "/api/v1/profile-assignments", res)
	w.globexIDs = append(w.globexIDs, w.globexUser, w.globexUserGroup, w.globexProfile, w.globexAssignment)
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
	res = call(t, w.carol, http.MethodPost, "/api/v1/devices/"+dev.DeviceID+"/local-admin/rotate", nil)
	expectStatus(t, res, http.StatusAccepted, "")
	w.globexIDs = append(w.globexIDs, w.globexDeviceGroup, w.globexToken, w.globexDevice, w.globexFile, w.globexUnit,
		responseID(t, res).String())
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

	"GET /api/v1/users": {kind: isoList, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/users?page_size=100", nil
	}},
	"POST /api/v1/users": {kind: isoOwn, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/users", map[string]string{"username": "acme-iso-" + uniqueSuffix() + "@acme.test", "display_name": "acme-iso"}
	}},
	"GET /api/v1/users/{id}":                   itemFixture(func(w *isolationWorld) string { return "/api/v1/users/" + w.globexUser }, nil),
	"PATCH /api/v1/users/{id}":                 itemFixture(func(w *isolationWorld) string { return "/api/v1/users/" + w.globexUser }, map[string]string{"display_name": "taken over by acme"}),
	"DELETE /api/v1/users/{id}":                itemFixture(func(w *isolationWorld) string { return "/api/v1/users/" + w.globexUser }, nil),
	"POST /api/v1/users/{id}/lock":             itemFixture(func(w *isolationWorld) string { return "/api/v1/users/" + w.globexUser + "/lock" }, nil),
	"POST /api/v1/users/{id}/unlock":           itemFixture(func(w *isolationWorld) string { return "/api/v1/users/" + w.globexUser + "/unlock" }, nil),
	"GET /api/v1/users/{id}/effective-profile": itemFixture(func(w *isolationWorld) string { return "/api/v1/users/" + w.globexUser + "/effective-profile" }, nil),

	"GET /api/v1/user-groups": {kind: isoList, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/user-groups?page_size=100", nil
	}},
	"POST /api/v1/user-groups": {kind: isoOwn, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/user-groups", map[string]string{"slug": "acme-iso-" + uniqueSuffix(), "name": "acme-iso"}
	}},
	"GET /api/v1/user-groups/{id}":          itemFixture(func(w *isolationWorld) string { return "/api/v1/user-groups/" + w.globexUserGroup }, nil),
	"PATCH /api/v1/user-groups/{id}":        itemFixture(func(w *isolationWorld) string { return "/api/v1/user-groups/" + w.globexUserGroup }, map[string]string{"name": "taken over by acme"}),
	"DELETE /api/v1/user-groups/{id}":       itemFixture(func(w *isolationWorld) string { return "/api/v1/user-groups/" + w.globexUserGroup }, nil),
	"GET /api/v1/user-groups/{id}/members":  itemFixture(func(w *isolationWorld) string { return "/api/v1/user-groups/" + w.globexUserGroup + "/members" }, nil),
	"POST /api/v1/user-groups/{id}/members": itemFixture(func(w *isolationWorld) string { return "/api/v1/user-groups/" + w.globexUserGroup + "/members" }, map[string]string{"user_id": "00000000-0000-4000-8000-000000000000"}),
	"DELETE /api/v1/user-groups/{id}/members/{user_id}": itemFixture(func(w *isolationWorld) string {
		return "/api/v1/user-groups/" + w.globexUserGroup + "/members/" + w.globexUser
	}, nil),
	"GET /api/v1/upstream-groups": {kind: isoList, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/upstream-groups?page_size=100", nil
	}},

	"GET /api/v1/settings/login": {kind: isoOwn, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/settings/login", nil
	}},
	"PUT /api/v1/settings/login": {kind: isoOwn, request: func(t *testing.T, w *isolationWorld) (string, any) {
		return "/api/v1/settings/login", currentLoginSettings(t, w.alice)
	}},

	"PUT /api/v1/devices/{id}/login-assignment": itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/login-assignment" },
		map[string]any{"users": []string{}, "groups": []string{}}),
	"POST /api/v1/devices/{id}/suspend-logins": itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/suspend-logins" }, nil),
	"POST /api/v1/devices/{id}/resume-logins":  itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/resume-logins" }, nil),
	"GET /api/v1/devices/{id}/effective-sudo":  itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/effective-sudo" }, nil),
	"GET /api/v1/devices/{id}/commands":        itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/commands" }, nil),
	"POST /api/v1/devices/{id}/local-admin/rotate": itemFixture(func(w *isolationWorld) string {
		return "/api/v1/devices/" + w.globexDevice + "/local-admin/rotate"
	}, nil),

	"GET /api/v1/permission-profiles": {kind: isoList, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/permission-profiles?page_size=100", nil
	}},
	"POST /api/v1/permission-profiles": {kind: isoOwn, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/permission-profiles", map[string]any{"name": "acme-iso " + uniqueSuffix(), "class": "none"}
	}},
	"GET /api/v1/permission-profiles/{id}":    itemFixture(func(w *isolationWorld) string { return "/api/v1/permission-profiles/" + w.globexProfile }, nil),
	"PATCH /api/v1/permission-profiles/{id}":  itemFixture(func(w *isolationWorld) string { return "/api/v1/permission-profiles/" + w.globexProfile }, map[string]any{"class": "full"}),
	"DELETE /api/v1/permission-profiles/{id}": itemFixture(func(w *isolationWorld) string { return "/api/v1/permission-profiles/" + w.globexProfile }, nil),

	"GET /api/v1/profile-assignments": {kind: isoList, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/profile-assignments?page_size=100", nil
	}},
	"POST /api/v1/profile-assignments": {kind: isoOwn, request: func(t *testing.T, w *isolationWorld) (string, any) {
		res := call(t, w.alice, http.MethodPost, "/api/v1/permission-profiles", map[string]any{"name": "acme-iso " + uniqueSuffix(), "class": "none"})
		expectStatus(t, res, http.StatusCreated, "")
		return "/api/v1/profile-assignments", map[string]any{"profile_id": createdID(t, w.alice, "/api/v1/permission-profiles", res), "subject_type": "global"}
	}},
	"GET /api/v1/profile-assignments/{id}":    itemFixture(func(w *isolationWorld) string { return "/api/v1/profile-assignments/" + w.globexAssignment }, nil),
	"PATCH /api/v1/profile-assignments/{id}":  itemFixture(func(w *isolationWorld) string { return "/api/v1/profile-assignments/" + w.globexAssignment }, map[string]any{"device_group_id": nil}),
	"DELETE /api/v1/profile-assignments/{id}": itemFixture(func(w *isolationWorld) string { return "/api/v1/profile-assignments/" + w.globexAssignment }, nil),
}

// listParents resolves the parent ID of collection GETs below an item (path with {id}): the globex parent whose
// data carol finds and alice must get 404 for.
var listParents = map[string]func(w *isolationWorld) string{
	"/api/v1/device-groups/{id}/devices": func(w *isolationWorld) string { return w.globexDeviceGroup },
	"/api/v1/user-groups/{id}/members":   func(w *isolationWorld) string { return w.globexUserGroup },
	"/api/v1/devices/{id}/commands":      func(w *isolationWorld) string { return w.globexDevice },
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
	"/api/v1/users":                      {{"q": {"globex-iso"}}, {"source": {"local"}, "sort": {"-created_at"}, "page_size": {"100"}}},
	"/api/v1/user-groups":                {{"q": {"globex-iso"}}},
	"/api/v1/user-groups/{id}/members":   {{"q": {"globex-iso"}}, {"source": {"local"}}},
	"/api/v1/permission-profiles":        {{"q": {"globex-iso"}}, {"class": {"restricted"}, "page_size": {"100"}}},
	"/api/v1/profile-assignments":        {{"q": {"globex-iso"}}, {"subject_type": {"group"}, "page_size": {"100"}}},
	// Upstream groups with a member of the organization only (plan M3b decision 1): the globex-only group of
	// seedGlobexUpstream is carol's, never alice's.
	"/api/v1/upstream-groups":       {{"q": {"globex-iso"}}, {"page_size": {"100"}}},
	"/api/v1/devices/{id}/commands": {{"q": {"rotate"}}, {"type": {"rotate_admin_password"}, "status": {"pending", "delivered"}}},
}

// currentLoginSettings returns acme's login settings as an update body (unchanged values).
func currentLoginSettings(t *testing.T, p *env.Portal) map[string]any {
	t.Helper()
	res := call(t, p, http.MethodGet, "/api/v1/settings/login", nil)
	expectStatus(t, res, http.StatusOK, "")
	var s map[string]any
	if err := res.JSON(&s); err != nil {
		t.Fatal(err)
	}
	delete(s, "updated_at")
	return s
}
