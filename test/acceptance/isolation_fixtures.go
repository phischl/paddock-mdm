package acceptance

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/test/acceptance/devicesim"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// isolationWorld holds the sessions and the globex resources of the isolation gate.
type isolationWorld struct {
	// top is the gate's test: globex resources live until it ends, also those its subtests create.
	top          *testing.T
	alice, carol *env.Portal
	globexIDs    []string // every ID of globex the acme session must never see
	// ownActors are the actor ids of the acme administrators and API tokens this gate sends globex IDs with; their
	// failed or denied attempts are acme's own records of those requests (withoutOwnFailedAttempts).
	ownActors    []string
	globexGroups []string
	// Globex device control plane resources (seedGlobexDevices).
	globexToken, globexDevice, globexFile, globexUnit, globexDeviceGroup string
	// globexSim is the simulated agent of globexDevice.
	globexSim *devicesim.Device
	// globexLogin is the user name of the session start globexSim reported (seedGlobexLogin).
	globexLogin string
	// globexEnrollment is the enrollment configuration of globexToken.
	globexEnrollment protocol.EnrollmentConfig
	// Globex identity resources (seedGlobexIdentity).
	globexUser, globexUserGroup, globexProfile, globexAssignment string
	// globexUpstream is the Authentik pk of an upstream group whose only member is a globex user (seedGlobexUpstream).
	globexUpstream string
	// globexRevocation is a Destroy request of globexDevice that waits for its approval (seedGlobexDevices).
	globexRevocation string
	// globexCVE is a vulnerability found on globexDevice only (seedGlobexDevices).
	globexCVE string
	// globexHold is a package hold of globexDeviceGroup (seedGlobexDevices).
	globexHold string
	// globexAPIToken is an API token of globex (seedGlobexDevices).
	globexAPIToken string
	// globexDestination is a notification destination of globex (seedGlobexNotification).
	globexDestination string
	// globexChangeSet is a change set of globex (seedGlobexChangeSet).
	globexChangeSet string
	// globexFinding is the open tamper finding of globexDevice (seedGlobexFinding).
	globexFinding string
	// globexExport is an evidence export of globex (seedGlobexExport).
	globexExport string
}

// seedGlobexFinding reports an unexpected sudoers file of globexDevice as event 1 (seedGlobexLogin continues with 2) and
// waits until carol sees the finding the worker opens from it.
func seedGlobexFinding(t *testing.T, w *isolationWorld) {
	t.Helper()
	sendSudoersEvent(t, w.globexSim, 1, "globex-iso-evil-"+uniqueSuffix())
	f := tamperFindingOf(t, w.carol, w.globexDevice, 1)
	w.globexFinding = f.ID
	w.globexIDs = append(w.globexIDs, f.ID)
}

// seedGlobexChangeSet applies, as carol, a document with only globex's update settings and a changed daily time, so
// that globex has a change set; the original settings are applied again when the gate ends. Sections other than the
// settings stay absent, so nothing of globex is deleted.
func seedGlobexChangeSet(t *testing.T, w *isolationWorld) {
	t.Helper()
	original := currentUpdateSettings(t, w.carol)
	changed := map[string]any{}
	for k, v := range original {
		changed[k] = v
	}
	changed["security_daily_at"] = "04:44"
	if original["security_daily_at"] == "04:44" {
		changed["security_daily_at"] = "04:45"
	}
	doc := func(updates map[string]any) map[string]any {
		return map[string]any{"api_version": "paddock/v1", "kind": "OrganizationConfig", "settings": map[string]any{"updates": updates}}
	}
	res := call(t, w.carol, http.MethodPut, "/api/v1/config", doc(changed))
	expectStatus(t, res, http.StatusOK, "")
	var out struct {
		ChangeSetID string `json:"change_set_id"`
	}
	if err := res.JSON(&out); err != nil || out.ChangeSetID == "" {
		t.Fatalf("globex apply: %v %s", err, res.Body)
	}
	w.globexChangeSet = out.ChangeSetID
	w.globexIDs = append(w.globexIDs, out.ChangeSetID)
	w.top.Cleanup(func() { _ = call(w.top, w.carol, http.MethodPut, "/api/v1/config", doc(original)) })
}

// seedGlobexNotification creates a notification destination of globex that pseudonymizes user names, so its
// pseudonym lookup has a key.
func seedGlobexNotification(t *testing.T, w *isolationWorld) {
	t.Helper()
	renew := func(t *testing.T) { stepUp(t, w.carol, env.Carol, true) }
	body := webhookBody(destinationName("globex-iso"), notificationURL)
	body["pseudonymize_users"] = true
	renew(t)
	res := call(t, w.carol, http.MethodPost, "/api/v1/notification-destinations", body)
	expectStatus(t, res, http.StatusCreated, "")
	w.globexDestination = responseID(t, res).String()
	w.globexIDs = append(w.globexIDs, w.globexDestination)
	deleteDestinationOnCleanup(w.top, w.carol, renew, "/api/v1/notification-destinations/"+w.globexDestination)
}

// settingsOnlyConfig is a document with acme's current update settings only: applying it changes and deletes nothing.
func settingsOnlyConfig(t *testing.T, p *env.Portal) map[string]any {
	t.Helper()
	return map[string]any{"api_version": "paddock/v1", "kind": "OrganizationConfig",
		"settings": map[string]any{"updates": currentUpdateSettings(t, p)}}
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

// seedGlobexOwnersAndLogins makes, as carol, globexUser the owner of globexDevice and switches login history on
// (restored when the gate ends), so the user's devices have globex data to find; the session start itself is seeded
// right before the logins list is checked (seedGlobexLogin).
func seedGlobexOwnersAndLogins(t *testing.T, w *isolationWorld) {
	t.Helper()
	res := call(t, w.carol, http.MethodPut, "/api/v1/devices/"+w.globexDevice+"/owners", map[string]any{"user_ids": []string{w.globexUser}})
	expectStatus(t, res, http.StatusOK, "")
	original := currentLoginSettings(t, w.carol)
	w.top.Cleanup(func() { _ = call(w.top, w.carol, http.MethodPut, "/api/v1/settings/login", original) })
	expectStatus(t, putLoginHistory(t, w.carol, true, 365), http.StatusOK, "")
}

// seedGlobexLogin records one session start of globexDevice and waits until carol sees it. It runs right before the
// logins list is checked: the development stack counts the retention days in seconds, so a row seeded with the
// other fixtures could be purged before the gate reaches the route.
func seedGlobexLogin(t *testing.T, w *isolationWorld) {
	t.Helper()
	w.globexLogin = "globex-iso-" + uniqueSuffix() + "@globex.test"
	sendSessionLogins(t, w.globexSim, 2, w.globexLogin, time.Now().UTC().Truncate(time.Millisecond))
	query := "/api/v1/devices/" + w.globexDevice + "/logins?" + url.Values{"username": {strings.ToLower(w.globexLogin)}}.Encode()
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(time.Second) {
		var page struct {
			Total int `json:"total"`
		}
		res := call(t, w.carol, http.MethodGet, query, nil)
		expectStatus(t, res, http.StatusOK, "")
		if err := res.JSON(&page); err == nil && page.Total > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the seeded globex login is not listed for carol within 30 s: %s", res.Body)
		}
	}
}

// seedGlobexDevices creates, as carol, a device group with an enrolled device (through the device API), an
// enrollment token, a managed file and a managed unit of that group — all named "globex-iso…" so the list searches
// find them.
func seedGlobexDevices(t *testing.T, w *isolationWorld) {
	t.Helper()
	w.globexDeviceGroup = namedGroup(t, w.carol, "globex isolation devices")
	tok := createToken(t, w.carol, tokenOptions{name: uniqueName("globex isolation token"), autoApprove: true})
	w.globexToken, w.globexEnrollment = tok.Token.ID, tok.EnrollmentConfig
	dev, s := enroll(t, tok.EnrollmentConfig, "globex-iso-"+uniqueSuffix())
	if s.Status != "active" {
		t.Fatalf("globex device enrollment %+v", s)
	}
	w.globexDevice, w.globexSim = dev.DeviceID, dev
	// One check-in without any update run makes it a device with overdue security updates (security_updates filter).
	if _, _, err := dev.Checkin(testContext(t, time.Minute)); err != nil {
		t.Fatal(err)
	}
	res := call(t, w.carol, http.MethodPut, "/api/v1/devices/"+dev.DeviceID+"/groups", map[string]any{"device_group_ids": []string{w.globexDeviceGroup}})
	expectStatus(t, res, http.StatusOK, "")
	res = call(t, w.carol, http.MethodPost, "/api/v1/managed-files", map[string]any{
		"path": "/etc/paddock-gates/globex-iso-" + uniqueSuffix() + ".conf", "content": "globex", "device_group_id": w.globexDeviceGroup,
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
	res = call(t, w.carol, http.MethodPost, "/api/v1/package-holds", map[string]any{
		"package": "globex-iso-" + uniqueSuffix(), "device_group_id": w.globexDeviceGroup, "reason": "globex-iso",
	})
	expectStatus(t, res, http.StatusCreated, "")
	w.globexHold = createdID(t, w.carol, "/api/v1/package-holds", res)
	w.globexIDs = append(w.globexIDs, w.globexHold)
	// Its inventory, as the worker stores it from Fleet.
	w.globexCVE = uniqueCVE()
	pkg := "globex-iso-pkg-" + uniqueSuffix()
	storeInventory(t, dev.DeviceID, [][2]string{{pkg, "1.0"}}, [][4]string{{w.globexCVE, pkg, "1.0", "7.5"}})
	w.globexIDs = append(w.globexIDs, w.globexCVE)
	// A Destroy waits for its second approval forever: nothing is ever issued.
	stepUp(t, w.carol, env.Carol, true)
	hostname := getDevice(t, w.carol, dev.DeviceID).Hostname
	res = call(t, w.carol, http.MethodPost, "/api/v1/devices/"+dev.DeviceID+"/destroy", map[string]any{"confirm_hostname": hostname})
	expectStatus(t, res, http.StatusCreated, "")
	w.globexRevocation = responseID(t, res).String()
	w.globexIDs = append(w.globexIDs, w.globexRevocation)
	w.globexGroups = append(w.globexGroups, w.globexDeviceGroup)
	// An API token (plan M6c), still within carol's step-up.
	res = postAPIToken(t, w.carol, apiTokenName("globex-iso token"), "org_auditor", 2*time.Hour)
	expectStatus(t, res, http.StatusCreated, "")
	removeCreated(w.top, w.carol, "/api/v1/api-tokens", res)
	var apiTok apiTokenCreated
	if err := res.JSON(&apiTok); err != nil {
		t.Fatal(err)
	}
	w.globexAPIToken = apiTok.Token.ID
	w.globexIDs = append(w.globexIDs, w.globexAPIToken)
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
	// ownAttempts marks the audit-event list: the failed or denied attempts of the gate's own actors are left out of the
	// leak check (withoutOwnFailedAttempts), because the item checks record them with the globex ID the gate sent.
	ownAttempts bool
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
	"GET /api/v1/overview": {kind: isoOwn, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/overview", nil
	}},
	"GET /api/v1/security-review": {kind: isoOwn, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/security-review", nil
	}},
	"GET /api/v1/attention/devices": {kind: isoList, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/attention/devices?page_size=100", nil
	}},
	"GET /api/v1/audit-events": {kind: isoList, ownAttempts: true, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/audit-events?page_size=100", nil
	}},
	// Evidence integrity (plan M8b decision 30): a globex manifest's object key holds the globex organization ID.
	"GET /api/v1/audit/integrity": {kind: isoOwn, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/audit/integrity", nil
	}},
	"GET /api/v1/audit/verification-runs": {kind: isoList, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/audit/verification-runs?page_size=100", nil
	}},
	"GET /api/v1/audit/manifests": {kind: isoList, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/audit/manifests?page_size=100", nil
	}},
	// Evidence exports (plan M10 decision 30): alice requests one of acme's sealed days, the item is globex's export.
	"GET /api/v1/audit/exports": {kind: isoList, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/audit/exports?page_size=100", nil
	}},
	"POST /api/v1/audit/exports": {kind: isoOwn, request: func(t *testing.T, w *isolationWorld) (string, any) {
		day := acmeSealedDay(t, w)
		finishOpenExports(t, orgOf(t, w.alice))
		return "/api/v1/audit/exports", map[string]string{"from_day": day, "to_day": day, "purpose": "acme isolation gate"}
	}},
	// Signing keys (plan M10 decision 36) are the audit chain's public keys, shared by every organization.
	"GET /api/v1/audit/keys": {kind: isoOwn, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/audit/keys", nil
	}},
	"GET /api/v1/audit/exports/{id}": {kind: isoItem, request: func(t *testing.T, w *isolationWorld) (string, any) {
		seedGlobexExport(t, w)
		return "/api/v1/audit/exports/" + w.globexExport, nil
	}},
	"GET /api/v1/audit/exports/{id}/download": {kind: isoItem, request: func(t *testing.T, w *isolationWorld) (string, any) {
		seedGlobexExport(t, w)
		return "/api/v1/audit/exports/" + w.globexExport + "/download", nil
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

	"GET /api/v1/api-tokens": {kind: isoList, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/api-tokens?page_size=100", nil
	}},
	// alice has a step-up (TestOrganizationIsolation), so the creation succeeds in acme.
	"POST /api/v1/api-tokens": {kind: isoOwn, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/api-tokens", map[string]any{"name": apiTokenName("acme isolation"), "role": "org_auditor",
			"expires_at": time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)}
	}},
	"GET /api/v1/api-tokens/{id}":         itemFixture(func(w *isolationWorld) string { return "/api/v1/api-tokens/" + w.globexAPIToken }, nil),
	"POST /api/v1/api-tokens/{id}/revoke": itemFixture(func(w *isolationWorld) string { return "/api/v1/api-tokens/" + w.globexAPIToken + "/revoke" }, nil),

	"GET /api/v1/notification-destinations": {kind: isoList, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/notification-destinations?page_size=100", nil
	}},
	"POST /api/v1/notification-destinations": {kind: isoOwn, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/notification-destinations", webhookBody(destinationName("acme-iso"), notificationURL)
	}},
	"GET /api/v1/notification-destinations/{id}":    itemFixture(func(w *isolationWorld) string { return "/api/v1/notification-destinations/" + w.globexDestination }, nil),
	"PUT /api/v1/notification-destinations/{id}":    itemFixture(func(w *isolationWorld) string { return "/api/v1/notification-destinations/" + w.globexDestination }, map[string]any{"name": "acme-iso", "enabled": true, "filter_mode": "all"}),
	"DELETE /api/v1/notification-destinations/{id}": itemFixture(func(w *isolationWorld) string { return "/api/v1/notification-destinations/" + w.globexDestination }, nil),
	"POST /api/v1/notification-destinations/{id}/rotate-secret": itemFixture(func(w *isolationWorld) string {
		return "/api/v1/notification-destinations/" + w.globexDestination + "/rotate-secret"
	}, nil),
	"POST /api/v1/notification-destinations/{id}/test": itemFixture(func(w *isolationWorld) string {
		return "/api/v1/notification-destinations/" + w.globexDestination + "/test"
	}, nil),
	"POST /api/v1/notification-destinations/{id}/resolve-pseudonym": itemFixture(func(w *isolationWorld) string {
		return "/api/v1/notification-destinations/" + w.globexDestination + "/resolve-pseudonym"
	},
		map[string]any{"pseudonym": "u_0123456789abcdef01234567"}),
	"GET /api/v1/notification-destinations/{id}/resolve-pseudonym/{lookup_id}": itemFixture(func(w *isolationWorld) string {
		return "/api/v1/notification-destinations/" + w.globexDestination + "/resolve-pseudonym/" + uuid.NewString()
	}, nil),
	"GET /api/v1/findings": {kind: isoList, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/findings?page_size=100", nil
	}},
	"GET /api/v1/findings/{id}": itemFixture(func(w *isolationWorld) string { return "/api/v1/findings/" + w.globexFinding }, nil),
	"POST /api/v1/findings/{id}/acknowledge": itemFixture(func(w *isolationWorld) string {
		return "/api/v1/findings/" + w.globexFinding + "/acknowledge"
	}, nil),
	"POST /api/v1/findings/{id}/assign": itemFixture(func(w *isolationWorld) string {
		return "/api/v1/findings/" + w.globexFinding + "/assign"
	}, map[string]any{"assignee_id": nil}),
	"POST /api/v1/findings/{id}/close": itemFixture(func(w *isolationWorld) string {
		return "/api/v1/findings/" + w.globexFinding + "/close"
	}, map[string]any{"resolution": "resolved", "reason": "acme-iso"}),
	"POST /api/v1/findings/{id}/reopen": itemFixture(func(w *isolationWorld) string {
		return "/api/v1/findings/" + w.globexFinding + "/reopen"
	}, map[string]any{"reason": "acme-iso"}),
	"GET /api/v1/accounts": {kind: isoList, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/accounts?page_size=100", nil
	}},
	"GET /api/v1/settings/watched-units": {kind: isoOwn, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/settings/watched-units", nil
	}},
	"PUT /api/v1/settings/watched-units": {kind: isoOwn, request: func(t *testing.T, w *isolationWorld) (string, any) {
		res := call(t, w.alice, http.MethodGet, "/api/v1/settings/watched-units", nil)
		expectStatus(t, res, http.StatusOK, "")
		var cur struct {
			Units []string `json:"units"`
		}
		if err := res.JSON(&cur); err != nil {
			t.Fatal(err)
		}
		if cur.Units == nil {
			cur.Units = []string{}
		}
		return "/api/v1/settings/watched-units", map[string]any{"units": cur.Units}
	}},
	"GET /api/v1/audit-events/feed": {kind: isoOwn, ownAttempts: true, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/audit-events/feed?limit=1000", nil
	}},
	"GET /api/v1/notification-capabilities": {kind: isoOwn, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/notification-capabilities", nil
	}},

	"GET /api/v1/config": {kind: isoOwn, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/config", nil
	}},
	"PUT /api/v1/config": {kind: isoOwn, request: func(t *testing.T, w *isolationWorld) (string, any) {
		return "/api/v1/config?dry_run=true", settingsOnlyConfig(t, w.alice)
	}},
	"GET /api/v1/change-sets": {kind: isoList, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/change-sets?page_size=100", nil
	}},
	"GET /api/v1/change-sets/{id}": itemFixture(func(w *isolationWorld) string { return "/api/v1/change-sets/" + w.globexChangeSet }, nil),

	"GET /api/v1/devices": {kind: isoList, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/devices?page_size=100", nil
	}},
	"GET /api/v1/devices/{id}":                     itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice }, nil),
	"POST /api/v1/devices/{id}/approve":            itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/approve" }, nil),
	"POST /api/v1/devices/{id}/reject":             itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/reject" }, nil),
	"POST /api/v1/devices/{id}/release-quarantine": itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/release-quarantine" }, nil),
	"POST /api/v1/devices/{id}/update-agent":       itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/update-agent" }, nil),
	"POST /api/v1/devices/{id}/uninstall": itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/uninstall" },
		map[string]any{"mode": "leave", "confirm_hostname": "x", "reason": "isolation"}),
	"POST /api/v1/devices/{id}/uninstall/cancel": itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/uninstall/cancel" }, nil),
	"POST /api/v1/devices/{id}/encrypt": itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/encrypt" },
		map[string]any{"confirm_hostname": "x", "reason": "isolation", "backup_confirmed": true}),
	"POST /api/v1/devices/{id}/encrypt/cancel": itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/encrypt/cancel" },
		map[string]any{"confirm_hostname": "x"}),
	"POST /api/v1/devices/{id}/retire": itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/retire" }, nil),
	"PUT /api/v1/devices/{id}/groups": itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/groups" },
		map[string]any{"device_group_ids": []string{}}),
	"GET /api/v1/devices/{id}/logins": itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/logins" }, nil),
	"PUT /api/v1/devices/{id}/owners": itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/owners" },
		map[string]any{"user_ids": []string{}}),
	"PUT /api/v1/devices/{id}/name": itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/name" },
		map[string]any{"name": "isolation-name"}),
	"GET /api/v1/devices/{id}/effective-config": itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/effective-config" }, nil),
	"GET /api/v1/device-groups/{id}/devices":    itemFixture(func(w *isolationWorld) string { return "/api/v1/device-groups/" + w.globexDeviceGroup + "/devices" }, nil),

	"GET /api/v1/managed-files": {kind: isoList, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/managed-files?page_size=100", nil
	}},
	"POST /api/v1/managed-files": {kind: isoOwn, request: func(t *testing.T, w *isolationWorld) (string, any) {
		return "/api/v1/managed-files", map[string]any{"path": "/etc/paddock-gates/acme-iso-" + uniqueSuffix() + ".conf", "content": "acme",
			"device_group_id": namedGroup(t, w.alice, "acme isolation scope")}
	}},
	"GET /api/v1/managed-files/{id}":    itemFixture(func(w *isolationWorld) string { return "/api/v1/managed-files/" + w.globexFile }, nil),
	"PATCH /api/v1/managed-files/{id}":  itemFixture(func(w *isolationWorld) string { return "/api/v1/managed-files/" + w.globexFile }, map[string]any{"content": "taken over by acme"}),
	"DELETE /api/v1/managed-files/{id}": itemFixture(func(w *isolationWorld) string { return "/api/v1/managed-files/" + w.globexFile }, nil),
	// alice has a step-up (TestOrganizationIsolation), so the confirmations reach the lookup.
	"POST /api/v1/managed-files/{id}/confirm-sensitive": itemFixture(func(w *isolationWorld) string {
		return "/api/v1/managed-files/" + w.globexFile + "/confirm-sensitive"
	}, nil),
	"POST /api/v1/permission-profiles/{id}/confirm-root-grant": itemFixture(func(w *isolationWorld) string {
		return "/api/v1/permission-profiles/" + w.globexProfile + "/confirm-root-grant"
	}, nil),

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
	"GET /api/v1/users/{id}/devices":           itemFixture(func(w *isolationWorld) string { return "/api/v1/users/" + w.globexUser + "/devices" }, nil),
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

	"GET /api/v1/settings/managed-files": {kind: isoOwn, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/settings/managed-files", nil
	}},
	// The roots every gate relies on: the PUT writes acme's current list back (alice has a step-up in this gate).
	// After acmeOperatorRoots, which this gate calls first, no gate changes acme's list, so it cannot lose a root.
	"PUT /api/v1/settings/managed-files": {kind: isoOwn, request: func(t *testing.T, w *isolationWorld) (string, any) {
		operatorRootsMu.Lock()
		defer operatorRootsMu.Unlock()
		res := call(t, w.alice, http.MethodGet, "/api/v1/settings/managed-files", nil)
		var s struct {
			OperatorRoots []string `json:"operator_roots"`
		}
		if err := res.JSON(&s); err != nil {
			t.Fatal(err)
		}
		return "/api/v1/settings/managed-files", map[string]any{"operator_roots": s.OperatorRoots}
	}},
	"GET /api/v1/settings/dms": {kind: isoOwn, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/settings/dms", nil
	}},
	"PUT /api/v1/settings/dms": {kind: isoOwn, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/settings/dms", map[string]any{"enabled": false, "period_days": 30, "warn_days": []int{3, 1}}
	}},
	"GET /api/v1/settings/mcp": {kind: isoOwn, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/settings/mcp", nil
	}},
	// The MCP gates rely on acme's policy: the PUT writes the current one back.
	"PUT /api/v1/settings/mcp": {kind: isoOwn, request: func(t *testing.T, w *isolationWorld) (string, any) {
		return "/api/v1/settings/mcp", currentMCPPolicy(t, w.alice, "/api/v1/settings/mcp")
	}},
	// alice's MCP write opt-in is withdrawn again when the enable sub-test ends.
	"POST /api/v1/me/mcp-write/enable": {kind: isoOwn, request: func(t *testing.T, w *isolationWorld) (string, any) {
		t.Cleanup(func() {
			expectStatus(t, call(t, w.alice, http.MethodPost, "/api/v1/me/mcp-write/disable", nil), http.StatusOK, "")
		})
		return "/api/v1/me/mcp-write/enable", nil
	}},
	"POST /api/v1/me/mcp-write/disable": {kind: isoOwn, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/me/mcp-write/disable", nil
	}},
	"GET /api/v1/mcp/catalog": {kind: isoOwn, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/mcp/catalog", nil
	}},
	"GET /api/v1/mcp/access": {kind: isoOwn, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/mcp/access", nil
	}},

	"POST /api/v1/devices/{id}/lock": itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/lock" },
		map[string]any{"confirm_hostname": "x"}),
	"POST /api/v1/devices/{id}/destroy": itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/destroy" },
		map[string]any{"confirm_hostname": "x"}),
	"GET /api/v1/revocation-requests": {kind: isoList, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/revocation-requests?page_size=100", nil
	}},
	"POST /api/v1/revocation-requests/{id}/approve": itemFixture(func(w *isolationWorld) string {
		return "/api/v1/revocation-requests/" + w.globexRevocation + "/approve"
	}, map[string]any{"confirm_hostname": "x"}),
	"POST /api/v1/revocation-requests/{id}/reject": itemFixture(func(w *isolationWorld) string {
		return "/api/v1/revocation-requests/" + w.globexRevocation + "/reject"
	}, map[string]any{"confirm_hostname": "x"}),
	"POST /api/v1/revocation-requests/{id}/cancel": itemFixture(func(w *isolationWorld) string {
		return "/api/v1/revocation-requests/" + w.globexRevocation + "/cancel"
	}, map[string]any{"confirm_hostname": "x"}),

	"GET /api/v1/devices/{id}/disk": itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/disk" }, nil),
	"POST /api/v1/devices/{id}/disk/recovery-key": itemFixture(func(w *isolationWorld) string {
		return "/api/v1/devices/" + w.globexDevice + "/disk/recovery-key"
	}, map[string]any{"confirm_hostname": "x"}),
	"POST /api/v1/devices/{id}/disk/header": itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/disk/header" },
		map[string]any{"confirm_hostname": "x"}),
	"POST /api/v1/autoinstall": {kind: isoItem, request: func(_ *testing.T, w *isolationWorld) (string, any) {
		return "/api/v1/autoinstall", autoinstallBody(w.globexEnrollment, "26.04")
	}},

	"PUT /api/v1/devices/{id}/login-assignment": itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/login-assignment" },
		map[string]any{"users": []string{}, "groups": []string{}}),
	"POST /api/v1/devices/{id}/suspend-logins": itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/suspend-logins" }, nil),
	"POST /api/v1/devices/{id}/resume-logins":  itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/resume-logins" }, nil),
	"GET /api/v1/devices/{id}/effective-sudo":  itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/effective-sudo" }, nil),
	"GET /api/v1/devices/{id}/commands":        itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/commands" }, nil),
	"GET /api/v1/devices/{id}/local-admin":     itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/local-admin" }, nil),
	// alice has a step-up (TestOrganizationIsolation), so the reveal reaches the device lookup.
	"POST /api/v1/devices/{id}/local-admin/reveal": itemFixture(func(w *isolationWorld) string {
		return "/api/v1/devices/" + w.globexDevice + "/local-admin/reveal"
	}, map[string]any{"confirm_hostname": "x"}),
	"POST /api/v1/devices/{id}/local-admin/rotate": itemFixture(func(w *isolationWorld) string {
		return "/api/v1/devices/" + w.globexDevice + "/local-admin/rotate"
	}, nil),

	"GET /api/v1/devices/{id}/software":        itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/software" }, nil),
	"GET /api/v1/devices/{id}/vulnerabilities": itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/vulnerabilities" }, nil),
	"GET /api/v1/software": {kind: isoList, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/software?page_size=100", nil
	}},
	"GET /api/v1/vulnerabilities": {kind: isoList, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/vulnerabilities?page_size=100", nil
	}},
	"GET /api/v1/vulnerabilities/summary": {kind: isoOwn, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/vulnerabilities/summary", nil
	}},
	"GET /api/v1/vulnerabilities/{cve}/devices": itemFixture(func(w *isolationWorld) string { return "/api/v1/vulnerabilities/" + w.globexCVE + "/devices" }, nil),

	"GET /api/v1/settings/updates": {kind: isoOwn, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/settings/updates", nil
	}},
	"PUT /api/v1/settings/updates": {kind: isoOwn, request: func(t *testing.T, w *isolationWorld) (string, any) {
		return "/api/v1/settings/updates", currentUpdateSettings(t, w.alice)
	}},
	"GET /api/v1/settings/privacy": {kind: isoOwn, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/settings/privacy", nil
	}},
	"PUT /api/v1/settings/privacy": {kind: isoOwn, request: func(t *testing.T, w *isolationWorld) (string, any) {
		return "/api/v1/settings/privacy", currentPrivacySettings(t, w.alice)
	}},
	"GET /api/v1/package-holds": {kind: isoList, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/package-holds?page_size=100", nil
	}},
	"POST /api/v1/package-holds": {kind: isoOwn, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/package-holds", map[string]any{"package": "acme-iso-" + uniqueSuffix()}
	}},
	"GET /api/v1/package-holds/{id}": itemFixture(func(w *isolationWorld) string { return "/api/v1/package-holds/" + w.globexHold }, nil),
	"PATCH /api/v1/package-holds/{id}": itemFixture(func(w *isolationWorld) string { return "/api/v1/package-holds/" + w.globexHold },
		map[string]any{"version": nil, "reason": ""}),
	"DELETE /api/v1/package-holds/{id}": itemFixture(func(w *isolationWorld) string { return "/api/v1/package-holds/" + w.globexHold }, nil),
	"POST /api/v1/devices/{id}/install-now": itemFixture(func(w *isolationWorld) string {
		return "/api/v1/devices/" + w.globexDevice + "/install-now"
	}, map[string]any{"packages": []string{"htop"}}),
	"POST /api/v1/device-groups/{id}/install-now": itemFixture(func(w *isolationWorld) string {
		return "/api/v1/device-groups/" + w.globexDeviceGroup + "/install-now"
	}, map[string]any{"packages": []string{"htop"}}),
	"GET /api/v1/attention": {kind: isoList, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/attention?page_size=100", nil
	}},
	"GET /api/v1/devices/{id}/updates": itemFixture(func(w *isolationWorld) string { return "/api/v1/devices/" + w.globexDevice + "/updates" }, nil),

	"GET /api/v1/permission-profiles": {kind: isoList, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/permission-profiles?page_size=100", nil
	}},
	"POST /api/v1/permission-profiles": {kind: isoOwn, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/permission-profiles", map[string]any{"name": "acme-iso " + uniqueSuffix(), "class": "none"}
	}},
	// The preview evaluates only the class and commands it is given and reads no organization data (plan M8x decision
	// 40), so it has no globex resource to address: alice previews globex's profile commands and the answer must
	// still carry no globex ID.
	"GET /api/v1/permission-profiles/root-equivalence": {kind: isoOwn, request: func(*testing.T, *isolationWorld) (string, any) {
		return "/api/v1/permission-profiles/root-equivalence?" + url.Values{"class": {"restricted"},
			"command": {"/usr/bin/systemctl restart globex.service"}}.Encode(), nil
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
	"/api/v1/device-groups/{id}/devices":    func(w *isolationWorld) string { return w.globexDeviceGroup },
	"/api/v1/user-groups/{id}/members":      func(w *isolationWorld) string { return w.globexUserGroup },
	"/api/v1/devices/{id}/commands":         func(w *isolationWorld) string { return w.globexDevice },
	"/api/v1/devices/{id}/software":         func(w *isolationWorld) string { return w.globexDevice },
	"/api/v1/devices/{id}/vulnerabilities":  func(w *isolationWorld) string { return w.globexDevice },
	"/api/v1/vulnerabilities/{cve}/devices": func(w *isolationWorld) string { return w.globexCVE },
	"/api/v1/users/{id}/devices":            func(w *isolationWorld) string { return w.globexUser },
	"/api/v1/devices/{id}/logins":           func(w *isolationWorld) string { return w.globexDevice },
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
		{"contact": {"never", "ok"}, "page_size": {"100"}},
		{"security_updates": {"overdue"}, "page_size": {"100"}},
	},
	"/api/v1/change-sets": {
		{"q": {"carol"}},
		{"source": {"session"}, "sort": {"applied_at"}, "page_size": {"100"}},
		{"rollout": {"immediate"}, "page_size": {"100"}},
	},
	"/api/v1/api-tokens": {
		{"q": {"globex-iso"}},
		{"status": {"active"}, "sort": {"-created_at"}, "page_size": {"100"}},
	},
	"/api/v1/managed-files": {{"q": {"globex-iso"}}},
	"/api/v1/notification-destinations": {
		{"q": {"globex-iso"}},
		{"type": {"webhook"}, "enabled": {"true"}, "sort": {"-created_at"}, "page_size": {"100"}},
	},
	"/api/v1/findings": {
		{"q": {"globex-iso"}},
		{"kind": {"tamper"}, "status": {"open"}, "sort": {"-opened_at"}, "page_size": {"100"}},
	},
	"/api/v1/accounts": {
		{"q": {"carol"}},
		{"role": {"org_admin"}, "sort": {"username"}, "page_size": {"100"}},
	},
	"/api/v1/managed-units": {{"q": {"globex-iso"}}},
	"/api/v1/package-holds": {{"q": {"globex-iso"}}, {"sort": {"-created_at"}, "page_size": {"100"}}},
	// globex's waiting Destroy (seedGlobexDevices) is a revocation_pending condition.
	"/api/v1/attention":                  {{"q": {"globex-iso"}}, {"kind": {"revocation_pending"}, "page_size": {"100"}}},
	"/api/v1/attention/devices":          {{"q": {"globex-iso"}}, {"kind": {"revocation_pending"}, "sort": {"hostname"}, "page_size": {"100"}}},
	"/api/v1/device-groups/{id}/devices": {{"q": {"globex-iso"}}, {"state": {"active"}}},
	"/api/v1/users":                      {{"q": {"globex-iso"}}, {"source": {"local"}, "sort": {"-created_at"}, "page_size": {"100"}}},
	"/api/v1/user-groups":                {{"q": {"globex-iso"}}},
	"/api/v1/user-groups/{id}/members":   {{"q": {"globex-iso"}}, {"source": {"local"}}},
	"/api/v1/permission-profiles":        {{"q": {"globex-iso"}}, {"class": {"restricted"}, "page_size": {"100"}}},
	"/api/v1/profile-assignments":        {{"q": {"globex-iso"}}, {"subject_type": {"group"}, "page_size": {"100"}}},
	// Upstream groups with a member of the organization only (plan M3b decision 1): the globex-only group of
	// seedGlobexUpstream is carol's, never alice's.
	"/api/v1/upstream-groups":               {{"q": {"globex-iso"}}, {"page_size": {"100"}}},
	"/api/v1/devices/{id}/commands":         {{"q": {"rotate"}}, {"type": {"rotate_admin_password"}, "status": {"pending", "delivered"}}},
	"/api/v1/software":                      {{"q": {"globex-iso"}}, {"has_vulnerabilities": {"true"}, "page_size": {"100"}}},
	"/api/v1/vulnerabilities":               {{"q": {"CVE-2099"}, "page_size": {"100"}}, {"severity": {"high"}, "page_size": {"100"}}},
	"/api/v1/devices/{id}/software":         {{"q": {"globex-iso"}}},
	"/api/v1/devices/{id}/vulnerabilities":  {{"q": {"globex-iso"}}, {"severity": {"high"}}},
	"/api/v1/vulnerabilities/{cve}/devices": {{"q": {"globex-iso"}}},
	"/api/v1/revocation-requests": {
		{"q": {"globex-iso"}},
		{"action": {"destroy"}, "status": {"requested"}, "page_size": {"100"}},
	},
	// globexUser owns globexDevice (seedGlobexOwnersAndLogins), which reported one session start (seedGlobexLogin).
	"/api/v1/users/{id}/devices":  {{"q": {"globex-iso"}}, {"sort": {"-last_contact_at"}}},
	"/api/v1/devices/{id}/logins": {{"q": {"globex-iso"}}, {"sort": {"username"}}},
	// globex's verification run of a day without manifest (seedGlobexVerificationRun).
	"/api/v1/audit/verification-runs": {
		{"q": {isolationVerifyDay + ": no manifest"}, "page_size": {"100"}},
		{"trigger": {"cli"}, "ok": {"false"}, "sort": {"-started_at"}, "page_size": {"100"}},
	},
	// globex's evidence export (seedGlobexExport).
	"/api/v1/audit/exports": {
		{"q": {"globex-iso"}, "page_size": {"100"}},
		{"status": {"pending", "running", "ready", "failed", "expired"}, "sort": {"-requested_at"}, "page_size": {"100"}},
	},
	// globex's sealed current day (seedGlobexManifest); the manifest's object key carries the globex ID.
	"/api/v1/audit/manifests": {
		{"q": {"manifests"}, "page_size": {"100"}},
		{"from": {isolationVerifyDay}, "sort": {"-day"}, "page_size": {"100"}},
	},
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

func sendSessionLogins(t *testing.T, d *devicesim.Device, seq int64, user string, at ...time.Time) {
	t.Helper()
	var events []protocol.Event
	for i, a := range at {
		data, _ := json.Marshal(protocol.SessionLogin{Username: user, At: a})
		events = append(events, protocol.Event{EventSeq: seq + int64(i), Type: protocol.EventSessionLogin, OccurredAt: a, Data: data})
	}
	res, err := d.SendEvents(testContext(t, time.Minute), events)
	if err != nil || res.Status != http.StatusAccepted && res.Status != http.StatusOK {
		t.Fatalf("send events: %v %d", err, res.Status)
	}
}

func putLoginHistory(t *testing.T, p *env.Portal, enabled bool, days int) env.Response {
	t.Helper()
	s := currentLoginSettings(t, p)
	s["login_history_enabled"], s["login_history_days"] = enabled, days
	return call(t, p, http.MethodPut, "/api/v1/settings/login", s)
}

// currentUpdateSettings returns acme's update settings as an update body (unchanged values).
func currentUpdateSettings(t *testing.T, p *env.Portal) map[string]any {
	t.Helper()
	res := call(t, p, http.MethodGet, "/api/v1/settings/updates", nil)
	expectStatus(t, res, http.StatusOK, "")
	var s map[string]any
	if err := res.JSON(&s); err != nil {
		t.Fatal(err)
	}
	delete(s, "updated_at")
	return s
}

// currentPrivacySettings returns acme's privacy settings as an update body (unchanged values).
func currentPrivacySettings(t *testing.T, p *env.Portal) map[string]any {
	t.Helper()
	res := call(t, p, http.MethodGet, "/api/v1/settings/privacy", nil)
	expectStatus(t, res, http.StatusOK, "")
	var s map[string]any
	if err := res.JSON(&s); err != nil {
		t.Fatal(err)
	}
	delete(s, "updated_at")
	return s
}

// listSeeds seed globex data of a collection GET right before the gate checks it: data the development stack's
// retention purges within minutes.
var listSeeds = map[string]func(t *testing.T, w *isolationWorld){
	"/api/v1/devices/{id}/logins":     seedGlobexLogin,
	"/api/v1/audit/verification-runs": seedGlobexVerificationRun,
	"/api/v1/audit/manifests":         seedGlobexManifest,
	"/api/v1/audit/exports":           seedGlobexExport,
}

// seedGlobexExport makes sure globex has an evidence export and adds its ID to the globex IDs: the one of an earlier
// run, or a new one of globex's sealed current day (seedGlobexManifest) requested by carol after a step-up.
func seedGlobexExport(t *testing.T, w *isolationWorld) {
	t.Helper()
	if w.globexExport != "" {
		return
	}
	var page struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	res := call(t, w.carol, http.MethodGet, "/api/v1/audit/exports?q=globex-iso&page_size=10", nil)
	expectStatus(t, res, http.StatusOK, "")
	if err := res.JSON(&page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) > 0 {
		w.globexExport = page.Items[0].ID
	} else {
		seedGlobexManifest(t, w)
		finishOpenExports(t, orgOf(t, w.carol))
		stepUp(t, w.carol, env.Carol, true)
		today := time.Now().UTC().Format(time.DateOnly)
		res := call(t, w.carol, http.MethodPost, "/api/v1/audit/exports",
			map[string]string{"from_day": today, "to_day": today, "purpose": "globex-iso evidence export"})
		expectStatus(t, res, http.StatusAccepted, "")
		w.globexExport = responseID(t, res).String()
	}
	w.globexIDs = append(w.globexIDs, w.globexExport)
}

// acmeSealedDay returns acme's latest sealed day; before acme's first seal it seals acme's days through today with the
// development-only `audit seal --day --org`, as seedGlobexManifest does for globex.
func acmeSealedDay(t *testing.T, w *isolationWorld) string {
	t.Helper()
	var page struct {
		Items []struct {
			Day string `json:"day"`
		} `json:"items"`
	}
	res := call(t, w.alice, http.MethodGet, "/api/v1/audit/manifests?sort=-day&page_size=10", nil)
	expectStatus(t, res, http.StatusOK, "")
	if err := res.JSON(&page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) > 0 {
		return page.Items[0].Day
	}
	today := time.Now().UTC().Format(time.DateOnly)
	acme := orgOf(t, w.alice)
	if code, out, err := stack.PaddockServer(testContext(t, 2*time.Minute), "audit", "seal", "--day", today, "--org", acme.String()); err != nil || code != 0 {
		t.Fatalf("audit seal for acme: exit %d, %v\n%s", code, err, out)
	}
	return today
}

// finishOpenExports marks the pending and running exports of org as failed, as the audit writer does with a stuck
// export, so that the gate's own requests on the long-lived development stack stay below the limit of open exports.
func finishOpenExports(t *testing.T, org uuid.UUID) {
	t.Helper()
	dsn, err := stack.AuditWriterDSN()
	if err != nil {
		t.Fatal(err)
	}
	ctx := testContext(t, time.Minute)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, `UPDATE audit_export SET status = 'failed', error = 'finished by the isolation gate'
		WHERE organization_id = $1 AND status IN ('pending', 'running')`, org); err != nil {
		t.Fatalf("finish open exports of %s: %v", org, err)
	}
}

// seedGlobexManifest seals globex's unsealed days through today with the development-only `audit seal --day --org`.
// Events recorded later today are filed under the first unsealed day (ADR 0010 amendment 2026-10-25), so the early
// seal leaves globex's chain intact for the next nightly verification.
func seedGlobexManifest(t *testing.T, w *isolationWorld) {
	t.Helper()
	globex := orgOf(t, w.carol)
	today := time.Now().UTC().Format(time.DateOnly)
	if code, out, err := stack.PaddockServer(testContext(t, 2*time.Minute), "audit", "seal", "--day", today, "--org", globex.String()); err != nil || code != 0 {
		t.Fatalf("audit seal for globex: exit %d, %v\n%s", code, err, out)
	}
}

// isolationVerifyDay is a day long before any audit data: its verification fails with "no manifest" whatever the
// stack holds, and leaves no trace on the chain itself.
const isolationVerifyDay = "2000-01-01"

// seedGlobexVerificationRun records a failed verification run of globex with `paddock-server audit verify` (plan
// M8b decision 28) and adds its ID to the globex IDs.
func seedGlobexVerificationRun(t *testing.T, w *isolationWorld) {
	t.Helper()
	globex := orgOf(t, w.carol)
	_, out, err := stack.PaddockServer(testContext(t, 2*time.Minute), "audit", "verify", "--org", globex.String(),
		"--from", isolationVerifyDay, "--to", isolationVerifyDay)
	if err != nil {
		t.Fatalf("audit verify for globex: %v\n%s", err, out)
	}
	// printedRun of audit_integrity_test.go is not visible here: this file is also built without the tests.
	for _, line := range strings.Split(out, "\n") {
		if id, ok := strings.CutPrefix(strings.TrimSpace(line), "run "); ok {
			w.globexIDs = append(w.globexIDs, id)
			return
		}
	}
	t.Fatalf("audit verify for globex printed no run ID:\n%s", out)
}

// listIsolationDynamicQueries are list searches whose values are globex IDs known only at run time (plan M7c
// decision 31: the audit log's target_id); the gate runs them like listIsolationQueries.
var listIsolationDynamicQueries = map[string][]func(w *isolationWorld) url.Values{
	"/api/v1/devices/{id}/logins": {
		func(w *isolationWorld) url.Values { return url.Values{"username": {strings.ToLower(w.globexLogin)}} },
	},
	"/api/v1/attention/devices": {
		func(w *isolationWorld) url.Values { return url.Values{"device_id": {w.globexDevice}} },
	},
	"/api/v1/audit-events": {
		// Successes only: acme's own failed attempts on the globex device (the item checks above) are acme events that
		// carry the ID alice sent.
		func(w *isolationWorld) url.Values {
			return url.Values{"target_id": {w.globexDevice}, "outcome": {"success"}, "page_size": {"100"}}
		},
	},
}

// currentMCPPolicy reads the MCP policy at path as an McpSettingsInput, so that writing it back changes nothing.
func currentMCPPolicy(t *testing.T, p *env.Portal, path string) map[string]any {
	t.Helper()
	res := call(t, p, http.MethodGet, path, nil)
	expectStatus(t, res, http.StatusOK, "")
	var cur map[string]any
	if err := res.JSON(&cur); err != nil {
		t.Fatal(err)
	}
	return map[string]any{"enabled": cur["enabled"], "write_enabled": cur["write_enabled"], "mode": cur["mode"],
		"allowed_operations": cur["allowed_operations"]}
}
