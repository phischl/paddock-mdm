package acceptance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/test/acceptance/devicesim"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// The package names the self-service gates assign; no devicesim installs anything.
const (
	ssGroupPackage  = "paddock-gate-ss-group"
	ssDevicePackage = "paddock-gate-ss-device"
)

// softwarePackage returns the package of the section that installs name (an APT package or a Flatpak application).
func softwarePackage(b *bundle.Bundle, name string) (bundle.SoftwarePackage, bool) {
	if b.Software == nil {
		return bundle.SoftwarePackage{}, false
	}
	i := slices.IndexFunc(b.Software.Packages, func(p bundle.SoftwarePackage) bool { return p.Package == name || p.FlatpakRef == name })
	if i < 0 {
		return bundle.SoftwarePackage{}, false
	}
	return b.Software.Packages[i], true
}

// hasPackage is a latestBundle condition: the section installs name.
func hasPackage(name string) func(*bundle.Bundle) bool {
	return func(b *bundle.Bundle) bool { _, ok := softwarePackage(b, name); return ok }
}

// userGroupOf creates a user group of p with the members and deletes it when the test ends.
func userGroupOf(t *testing.T, p *env.Portal, members ...string) string {
	t.Helper()
	res := call(t, p, http.MethodPost, "/api/v1/user-groups", map[string]string{"slug": "ss-" + uniqueSuffix(), "name": uniqueName("self-service")})
	expectStatus(t, res, http.StatusCreated, "")
	group := createdID(t, p, "/api/v1/user-groups", res)
	for _, m := range members {
		expectStatus(t, call(t, p, http.MethodPost, "/api/v1/user-groups/"+group+"/members", map[string]string{"user_id": m}),
			http.StatusNoContent, "")
	}
	return group
}

// setOwners replaces the owners of the device.
func setOwners(t *testing.T, p *env.Portal, device string, users ...string) {
	t.Helper()
	expectStatus(t, call(t, p, http.MethodPut, "/api/v1/devices/"+device+"/owners", map[string]any{"user_ids": append([]string{}, users...)}),
		http.StatusOK, "")
}

// assign creates a software assignment and returns its ID. It is deleted when the test ends, before its catalog entry:
// an entry with assignments cannot be deleted (409 in_use, A10-12).
func assign(t *testing.T, p *env.Portal, body map[string]any) string {
	t.Helper()
	res := call(t, p, http.MethodPost, softwareAssignments, body)
	expectStatus(t, res, http.StatusCreated, "")
	return createdID(t, p, softwareAssignments, res)
}

// audienceUsers is the user list of an available package's audience; nil without an audience or for everyone.
func audienceUsers(p bundle.SoftwarePackage) []string {
	if p.Audience == nil || p.Audience.All {
		return nil
	}
	return p.Audience.Users
}

// TestSoftwareSelfService holds the gates SS1, SS2, SS3, SS5 and SS6 of plan M13b §9 (PDK-806) against the running
// stack; the Flatpak gates (SS4, Q12, A10-9, A10-10, A10-11) are TestSoftwareSelfServiceFlatpak. The self-service
// socket lives on the device, so these gates prove the server side only: the audience the compiler renders from the
// owners, the device's self-service events and status rows, and the user's software.
func TestSoftwareSelfService(t *testing.T) {
	alice, bob, carol := login(t, env.Alice), login(t, env.Bob), login(t, env.Carol)
	group := namedGroup(t, alice, "selfservice")
	owned := activeDevice(t, alice, group, "ss-owned-"+uniqueSuffix())
	shared := activeDevice(t, alice, group, "ss-shared-"+uniqueSuffix())
	// The software section is schema 2 only (plan M13a decision 13); a devicesim reports schema 1 unless told otherwise.
	for _, sim := range []*devicesim.Device{owned, shared} {
		sim.SchemaVersions = []int{bundle.SchemaVersion, bundle.SchemaVersion2}
	}
	member, memberName := localUserIn(t, alice, "ss-member", "acme.test")
	outsider, outsiderName := localUserIn(t, alice, "ss-outsider", "acme.test")
	direct, directName := localUserIn(t, alice, "ss-direct", "acme.test")
	users := userGroupOf(t, alice, member, outsider)
	// owned belongs to a group member and to a user outside the group; shared has no owner (RR-116).
	setOwners(t, alice, owned.DeviceID, member, direct)

	viaGroup := gateEntry(t, alice, "", packageRef("ubuntu", "*", ssGroupPackage))
	deviceWide := gateEntry(t, alice, "", packageRef("ubuntu", "*", ssDevicePackage))
	// The icon exists before any assignment, so every bundle that names deviceWide carries its digest (A10-14).
	expectStatus(t, call(t, alice, http.MethodPut, softwareCatalog+"/"+deviceWide+"/icon", gatePNG(t)), http.StatusNoContent, "")
	groupAssignment := assign(t, alice, map[string]any{"catalog_entry_id": viaGroup, "user_group_id": users, "intent": "available"})
	assign(t, alice, map[string]any{"catalog_entry_id": viaGroup, "user_id": direct, "intent": "available"})
	// Created last: a bundle with the device-group package was compiled after every user-targeted assignment.
	assign(t, alice, map[string]any{"catalog_entry_id": deviceWide, "device_group_id": group, "intent": "available"})

	t.Run("SS1 audience of the owners only", func(t *testing.T) {
		b := latestBundle(t, owned, 2*time.Minute, func(b *bundle.Bundle) bool {
			return hasPackage(ssGroupPackage)(b) && hasPackage(ssDevicePackage)(b)
		})
		p, _ := softwarePackage(b, ssGroupPackage)
		// The union of both assignments' targeted owners; the group member who owns nothing here is not in it.
		if p.Intent != bundle.SoftwareAvailable || p.CatalogEntryID != viaGroup ||
			asJSON(t, audienceUsers(p)) != asJSON(t, sortedPair(memberName, directName)) || p.Audience.All {
			t.Fatalf("user-targeted package %s", asJSON(t, p))
		}
		if slices.Contains(audienceUsers(p), outsiderName) {
			t.Fatalf("the audience names %s, who does not own the device: %s", outsiderName, asJSON(t, p))
		}
		if p, _ := softwarePackage(b, ssDevicePackage); p.Intent != bundle.SoftwareAvailable || p.Audience == nil || !p.Audience.All {
			t.Fatalf("device-group package %s, want an audience of everyone", asJSON(t, p))
		}
	})

	t.Run("SS2 no owners, no user-targeted package", func(t *testing.T) {
		b := latestBundle(t, shared, 2*time.Minute, hasPackage(ssDevicePackage))
		if p, ok := softwarePackage(b, ssGroupPackage); ok {
			t.Fatalf("a device without owners got the user-targeted package %s", asJSON(t, p))
		}
		// An owner change recompiles the device: the outsider owns shared now and is its only audience.
		setOwners(t, alice, shared.DeviceID, outsider)
		b = latestBundle(t, shared, 2*time.Minute, hasPackage(ssGroupPackage))
		if p, _ := softwarePackage(b, ssGroupPackage); asJSON(t, audienceUsers(p)) != asJSON(t, []string{outsiderName}) {
			t.Fatalf("audience after the owner change %s", asJSON(t, p))
		}
		setOwners(t, alice, shared.DeviceID)
		b = latestBundle(t, shared, 2*time.Minute, func(b *bundle.Bundle) bool { return !hasPackage(ssGroupPackage)(b) })
		if !hasPackage(ssDevicePackage)(b) {
			t.Fatalf("the device-group package left with the owner: %s", asJSON(t, b.Software))
		}
	})

	t.Run("SS3 self-service events and status rows", func(t *testing.T) {
		idx := auditIndex(t)
		acme := orgOf(t, alice)
		event := func(seq int64, action, outcome, reason string) {
			t.Helper()
			sendBundleEvent(t, owned, seq, protocol.EventSoftwareSelfService, protocol.SoftwareSelfService{
				User: memberName, EntryID: viaGroup, Package: ssGroupPackage, Scope: bundle.SoftwareScopeSystem, Action: action,
				Outcome: outcome, Reason: reason, Version: "1.0",
			})
		}
		event(1, protocol.SelfServiceInstall, protocol.SelfServiceSucceeded, "")
		event(2, protocol.SelfServiceRemove, protocol.SelfServiceRefused, protocol.SelfServiceRequiredByPolicy)
		event(3, protocol.SelfServiceUpdate, protocol.SelfServiceFailed, protocol.SelfServiceTimeout)
		// A redelivered event is recorded once (expectOneIndexEvent checks exactly one after the settle time).
		event(1, protocol.SelfServiceInstall, protocol.SelfServiceSucceeded, "")

		for _, c := range []struct{ action, outcome, errorCode, reason string }{
			{protocol.SelfServiceInstall, "success", "", ""},
			{protocol.SelfServiceRemove, "failure", "self_service_refused", protocol.SelfServiceRequiredByPolicy},
			{protocol.SelfServiceUpdate, "failure", "self_service_failed", protocol.SelfServiceTimeout},
		} {
			ev := expectOneIndexEvent(t, idx, acme, "code = 'device.software_self_service' AND params->>'action' = '"+c.action+
				"' AND target->>'id' = $1", owned.DeviceID, "device.software_self_service", c.outcome, time.Minute)
			if ev.Params["user"] != memberName || ev.Params["entry_id"] != viaGroup || ev.Params["package"] != ssGroupPackage ||
				ev.Params["scope"] != bundle.SoftwareScopeSystem || ev.Params["version"] != "1.0" || ev.Params["outcome"] == nil {
				t.Fatalf("%s event params %v", c.action, ev.Params)
			}
			if reason, _ := ev.Params["reason"].(string); reason != c.reason {
				t.Fatalf("%s event with reason %q, want %q: %v", c.action, reason, c.reason, ev.Params)
			}
			events, err := alice.AuditEvents(testContext(t, time.Minute), "device.software_self_service")
			if err != nil {
				t.Fatal(err)
			}
			i := slices.IndexFunc(events, func(e env.AuditEvent) bool { return e.EventID == ev.EventID.String() })
			if i < 0 || events[i].ErrorCode != c.errorCode || events[i].Actor.Type != "device" {
				t.Fatalf("%s event in the portal's audit log: %+v, want error code %q and the device as actor", c.action, events, c.errorCode)
			}
		}
		// globex never sees acme's self-service events.
		events, err := carol.AuditEvents(testContext(t, time.Minute), "device.software_self_service")
		if err != nil {
			t.Fatal(err)
		}
		if slices.ContainsFunc(events, func(e env.AuditEvent) bool { return e.Target != nil && e.Target.ID == owned.DeviceID }) {
			t.Fatalf("globex sees an acme self-service event")
		}

		// The status rows carry the scope (plan M13b decision 17). The user name of a user-scope row waits for the
		// maintainer's answer on per-user status (Q2; PDK-929, PDK-940) and is not asserted here.
		requireSingleService(t, testContext(t, time.Minute), "paddock-worker")
		raw, err := json.Marshal(map[string]any{"reconcile": "ok", "software": map[string]any{"digest": "ss-" + uniqueSuffix(), "items": []map[string]any{
			{"id": viaGroup, "package": ssGroupPackage, "intent": "available", "state": "installed", "version": "1.0", "scope": "user"},
			{"id": deviceWide, "package": ssDevicePackage, "intent": "available", "state": "absent", "scope": "system"},
		}}})
		if err != nil {
			t.Fatal(err)
		}
		valkeyCLI(t, "worker", "DEL hb:"+owned.DeviceID)
		owned.Health = raw
		if _, res, err := owned.Checkin(testContext(t, time.Minute)); err != nil || res.Status != http.StatusOK {
			t.Fatalf("check-in: %v %d %s", err, res.Status, res.Body)
		}
		type row struct {
			CatalogEntryID string `json:"catalog_entry_id"`
			DeviceID       string `json:"device_id"`
			Scope, State   string
		}
		rows := func(p *env.Portal, path string) []row {
			t.Helper()
			res := call(t, p, http.MethodGet, path, nil)
			expectStatus(t, res, http.StatusOK, "")
			var page struct {
				Items []row `json:"items"`
			}
			if err := res.JSON(&page); err != nil {
				t.Fatal(err)
			}
			return page.Items
		}
		managed := "/api/v1/devices/" + owned.DeviceID + "/managed-software?scope=user"
		for deadline := time.Now().Add(time.Minute); ; time.Sleep(time.Second) {
			got := rows(alice, managed)
			if len(got) == 1 && got[0].CatalogEntryID == viaGroup && got[0].Scope == "user" && got[0].State == "installed" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("user-scope rows of the device: %+v", got)
			}
		}
		got := rows(alice, "/api/v1/devices/"+owned.DeviceID+"/managed-software?scope=system&page_size=100")
		if i := slices.IndexFunc(got, func(r row) bool { return r.CatalogEntryID == deviceWide }); i < 0 || got[i].Scope != "system" ||
			got[i].State != "absent" || slices.ContainsFunc(got, func(r row) bool { return r.Scope != "system" }) {
			t.Fatalf("system-scope rows of the device: %+v", got)
		}
		if got := rows(alice, softwareCatalog+"/"+viaGroup+"/devices?scope=user"); len(got) != 1 || got[0].DeviceID != owned.DeviceID || got[0].Scope != "user" {
			t.Fatalf("user-scope devices of the entry: %+v", got)
		}
		expectStatus(t, call(t, carol, http.MethodGet, softwareCatalog+"/"+viaGroup+"/devices?scope=user", nil), http.StatusNotFound, "not_found")
	})

	t.Run("A10-14 icon of a catalog entry", func(t *testing.T) {
		b := latestBundle(t, owned, 2*time.Minute, hasPackage(ssDevicePackage))
		p, _ := softwarePackage(b, ssDevicePackage)
		want := sha256.Sum256(gatePNG(t))
		if p.IconSHA256 != hex.EncodeToString(want[:]) {
			t.Fatalf("device-group package %s, want icon_sha256 %x", asJSON(t, p), want)
		}
		icon := func(d *devicesim.Device, entry string) devicesim.Response {
			t.Helper()
			// The redirect itself is the contract; the device follows it without the signed request's headers.
			hc := *d.HTTP
			hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			sim := d.Clone()
			sim.HTTP = &hc
			res, err := sim.Do(testContext(t, time.Minute), devicesim.Request{Method: http.MethodGet, Path: "/v1/catalog/" + entry + "/icon"})
			if err != nil {
				t.Fatal(err)
			}
			return res
		}
		res := icon(owned, deviceWide)
		location := res.Header.Get("Location")
		if res.Status != http.StatusFound || location == "" {
			t.Fatalf("icon: HTTP %d Location %q %s, want 302 with a Location", res.Status, location, res.Body)
		}
		req, err := http.NewRequestWithContext(testContext(t, time.Minute), http.MethodGet, location, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err := owned.HTTP.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = got.Body.Close() }()
		body, err := io.ReadAll(got.Body)
		if err != nil {
			t.Fatal(err)
		}
		if sum := sha256.Sum256(body); got.StatusCode != http.StatusOK || got.Header.Get("Content-Type") != "image/png" || sum != want {
			t.Fatalf("icon at the presigned URL: HTTP %d %s, %d bytes with sha256 %x, want 200 image/png %x",
				got.StatusCode, got.Header.Get("Content-Type"), len(body), sum, want)
		}
		expectNotFound := func(d *devicesim.Device, entry string) {
			t.Helper()
			if res := icon(d, entry); res.Status != http.StatusNotFound || res.Problem().Code != protocol.CodeNotFound {
				t.Fatalf("icon of %s: HTTP %d %s, want 404 not_found", entry, res.Status, res.Body)
			}
		}
		// An entry the device's bundle does not name, and an acme entry asked for by a globex device with a bundle of
		// its own, so the refusal comes from its bundle's icons and not from a missing bundle.
		expectNotFound(owned, uuid.NewString())
		foreign := activeDevice(t, carol, "", "ss-globex-"+uniqueSuffix())
		latestBundle(t, foreign, 2*time.Minute, func(*bundle.Bundle) bool { return true })
		expectNotFound(foreign, deviceWide)
	})

	t.Run("SS5 software of a user", func(t *testing.T) {
		type item struct {
			AssignmentID   string  `json:"assignment_id"`
			CatalogEntryID string  `json:"catalog_entry_id"`
			Intent         string  `json:"intent"`
			UserGroupID    *string `json:"user_group_id"`
		}
		list := func(p *env.Portal, user, query string) []item {
			t.Helper()
			res := call(t, p, http.MethodGet, "/api/v1/users/"+user+"/software?"+query, nil)
			expectStatus(t, res, http.StatusOK, "")
			var page struct {
				Items []item `json:"items"`
				Total int    `json:"total"`
				Sort  string `json:"sort"`
			}
			if err := res.JSON(&page); err != nil || page.Total != len(page.Items) {
				t.Fatalf("software of %s: %v %s", user, err, res.Body)
			}
			return page.Items
		}
		// Through the group; the device-group assignment is not the user's.
		got := list(alice, member, "")
		if len(got) != 1 || got[0].AssignmentID != groupAssignment || got[0].UserGroupID == nil || *got[0].UserGroupID != users ||
			got[0].Intent != "available" {
			t.Fatalf("software of the group member: %+v", got)
		}
		// Directly; an auditor may read it (RolesRead).
		got = list(bob, direct, "intent=available&sort=-intent")
		if len(got) != 1 || got[0].CatalogEntryID != viaGroup || got[0].UserGroupID != nil {
			t.Fatalf("software of the directly targeted user: %+v", got)
		}
		if got := list(alice, direct, "intent=required"); len(got) != 0 {
			t.Fatalf("the intent filter lists %+v", got)
		}
		expectStatus(t, call(t, alice, http.MethodGet, "/api/v1/users/"+member+"/software?sort=hostname", nil), http.StatusBadRequest, "invalid_request")
		expectStatus(t, call(t, alice, http.MethodGet, "/api/v1/users/"+uuid.NewString()+"/software", nil), http.StatusNotFound, "not_found")
	})

	t.Run("SS6 isolation", func(t *testing.T) {
		expectStatus(t, call(t, carol, http.MethodGet, "/api/v1/users/"+member+"/software", nil), http.StatusNotFound, "not_found")
		// Neither organization can target the other's users or user groups.
		foreignUser, _ := localUserIn(t, carol, "ss-foreign", "globex.test")
		foreignGroup := userGroupOf(t, carol, foreignUser)
		for _, target := range []map[string]any{{"user_id": foreignUser}, {"user_group_id": foreignGroup}} {
			body := map[string]any{"catalog_entry_id": viaGroup, "intent": "available"}
			for k, v := range target {
				body[k] = v
			}
			res := call(t, alice, http.MethodPost, softwareAssignments, body)
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneEvent(t, alice, res.RequestID, "software_assignment.created", "failure")
		}
		globexEntry := gateEntry(t, carol, "", packageRef("ubuntu", "*", ssGroupPackage))
		expectStatus(t, call(t, carol, http.MethodPost, softwareAssignments, map[string]any{
			"catalog_entry_id": globexEntry, "user_id": member, "intent": "available",
		}), http.StatusNotFound, "not_found")
		expectStatus(t, call(t, carol, http.MethodPost, softwareAssignments, map[string]any{
			"catalog_entry_id": globexEntry, "user_group_id": users, "intent": "available",
		}), http.StatusNotFound, "not_found")
		// A globex owner never widens an acme audience: globex users cannot own acme devices.
		res := call(t, alice, http.MethodPut, "/api/v1/devices/"+owned.DeviceID+"/owners", map[string]any{"user_ids": []string{foreignUser}})
		expectStatus(t, res, http.StatusBadRequest, "invalid_request")
		res = call(t, alice, http.MethodGet, softwareAssignments+"?target=user&user_id="+foreignUser, nil)
		expectStatus(t, res, http.StatusOK, "")
		var page struct {
			Total int `json:"total"`
		}
		if err := res.JSON(&page); err != nil || page.Total != 0 {
			t.Fatalf("acme lists assignments of a globex user: %v %s", err, res.Body)
		}
	})
}

// TestSoftwareSelfServiceFlatpak holds gate SS4 of plan M13b §9 and the Flatpak amendments (PDK-806): a Flatpak source
// change needs a fresh step-up and is refused for API tokens; an available or required Flatpak application brings its
// remote and the flatpak runtime package with the nil entry ID (Q12); a user-scope required application names the
// targeted owners (A10-11); an agent before alpha.10 gets neither available packages nor Flatpak content but keeps its
// required APT packages (A10-6); a forbid of the flatpak package drops every Flatpak application with its remote and
// the runtime and records flatpak_forbidden compile warnings that another organization cannot read (A10-9, A10-10).
func TestSoftwareSelfServiceFlatpak(t *testing.T) {
	alice, carol := login(t, env.Alice), login(t, env.Carol)
	admin := adminUser(t, "ss-flatpak")
	s := adminStepper(admin)
	group := namedGroup(t, alice, "selfservice-flatpak")
	d := activeDevice(t, alice, group, "ss-flatpak-"+uniqueSuffix())
	d.SchemaVersions = []int{bundle.SchemaVersion, bundle.SchemaVersion2}
	member, memberName := localUserIn(t, alice, "ss-fp-member", "acme.test")
	users := userGroupOf(t, alice, member)
	setOwners(t, alice, d.DeviceID, member)

	s.stepUp(t)
	body := flatpakSourceBody("ss-flatpak")
	res := call(t, admin.Portal, http.MethodPost, softwareSources, body)
	expectStatus(t, res, http.StatusCreated, "")
	source := responseID(t, res).String()
	path := softwareSources + "/" + source
	deleteSourceOnCleanup(t, admin.Portal, s.stepUp, path)
	slug := body["slug"].(string)
	if ev := expectOneEvent(t, alice, res.RequestID, "software_source.created", "success"); ev.Params["kind"] != "flatpak" {
		t.Fatalf("software_source.created params %v, want kind flatpak", ev.Params)
	}

	t.Run("SS4 source changes need a step-up", func(t *testing.T) {
		token := tokenPortal(t, createAPIToken(t, login(t, env.Alice), env.Alice, "org_admin").Secret)
		for _, p := range []*env.Portal{withoutStepUp(t, admin), token} {
			expectRefusal(t, alice, call(t, p, http.MethodPost, softwareSources, flatpakSourceBody("ss-flatpak")),
				http.StatusForbidden, "step_up_required", "software_source.created")
			expectRefusal(t, alice, call(t, p, http.MethodPatch, path, map[string]any{"name": "ss-flatpak renamed"}),
				http.StatusForbidden, "step_up_required", "software_source.updated")
			expectRefusal(t, alice, call(t, p, http.MethodDelete, path, nil),
				http.StatusForbidden, "step_up_required", "software_source.deleted")
		}
		s.stepUp(t)
		res := call(t, admin.Portal, http.MethodPatch, path, map[string]any{"name": "ss-flatpak " + uniqueSuffix()})
		expectStatus(t, res, http.StatusOK, "")
		if ev := expectOneEvent(t, alice, res.RequestID, "software_source.updated", "success"); ev.Params["kind"] != "flatpak" {
			t.Fatalf("software_source.updated params %v, want kind flatpak", ev.Params)
		}
	})

	availableRef := "org.paddock.GateAvailable" + uniqueSuffix()
	requiredRef := "org.paddock.GateRequired" + uniqueSuffix()
	available := gateEntry(t, alice, source, flatpakRef(availableRef, "system"))
	required := gateEntry(t, alice, source, flatpakRef(requiredRef, "user"))
	availableAssignment := assign(t, alice, map[string]any{"catalog_entry_id": available, "user_group_id": users, "intent": "available"})
	requiredAssignment := assign(t, alice, map[string]any{"catalog_entry_id": required, "user_id": member, "intent": "required"})

	t.Run("runtime and remote", func(t *testing.T) {
		b := latestBundle(t, d, 2*time.Minute, func(b *bundle.Bundle) bool { return hasPackage(availableRef)(b) && hasPackage(requiredRef)(b) })
		if p, _ := softwarePackage(b, availableRef); p.Intent != bundle.SoftwareAvailable || p.Source != slug ||
			asJSON(t, audienceUsers(p)) != asJSON(t, []string{memberName}) {
			t.Fatalf("available Flatpak application %s", asJSON(t, p))
		}
		if p, _ := softwarePackage(b, requiredRef); p.Intent != bundle.SoftwareRequired || p.Scope != bundle.SoftwareScopeUser ||
			p.Users == nil || asJSON(t, *p.Users) != asJSON(t, []string{memberName}) {
			t.Fatalf("required user-scope Flatpak application %s, want the targeted owner as its users", asJSON(t, p))
		}
		if i := slices.IndexFunc(b.Software.Sources, func(x bundle.SoftwareSource) bool { return x.Slug == slug }); i < 0 ||
			b.Software.Sources[i].Kind != "flatpak" || b.Software.Sources[i].Fingerprint != gateSourceFP {
			t.Fatalf("sources %s, want the Flatpak remote %s", asJSON(t, b.Software.Sources), slug)
		}
		if p, ok := softwarePackage(b, "flatpak"); !ok || p.Intent != bundle.SoftwareRequired || p.CatalogEntryID != uuid.Nil.String() || p.FlatpakRef != "" {
			t.Fatalf("flatpak runtime package %s (%v)", asJSON(t, p), ok)
		}
	})

	t.Run("A10-6 an agent before alpha.10", func(t *testing.T) {
		requiredAPT, availableAPT := "paddock-gate-ss-old-required", "paddock-gate-ss-old-available"
		assign(t, alice, map[string]any{"catalog_entry_id": gateEntry(t, alice, "", packageRef("ubuntu", "*", requiredAPT)),
			"device_group_id": group, "intent": "required"})
		assign(t, alice, map[string]any{"catalog_entry_id": gateEntry(t, alice, "", packageRef("ubuntu", "*", availableAPT)),
			"device_group_id": group, "intent": "available"})
		latestBundle(t, d, 2*time.Minute, func(b *bundle.Bundle) bool { return hasPackage(requiredAPT)(b) && hasPackage(availableAPT)(b) })
		// Joins the group after every assignment exists and reports alpha.9 from its first check-in on, which comes
		// after the owner is set: a bundle with the required package but without the available one is a gated compile.
		old := activeDevice(t, alice, group, "ss-old-agent-"+uniqueSuffix())
		old.SchemaVersions = []int{bundle.SchemaVersion, bundle.SchemaVersion2}
		old.AgentVersion = "0.1.0-alpha.9"
		setOwners(t, alice, old.DeviceID, member)
		b := latestBundle(t, old, 2*time.Minute, func(b *bundle.Bundle) bool { return hasPackage(requiredAPT)(b) && !hasPackage(availableAPT)(b) })
		if p, _ := softwarePackage(b, requiredAPT); p.Intent != bundle.SoftwareRequired {
			t.Fatalf("required APT package of an alpha.9 agent %s", asJSON(t, p))
		}
		if hasPackage(availableRef)(b) || hasPackage(requiredRef)(b) || hasPackage("flatpak")(b) ||
			slices.ContainsFunc(b.Software.Sources, func(x bundle.SoftwareSource) bool { return x.Kind == bundle.SoftwareSourceFlatpak }) ||
			slices.ContainsFunc(b.Software.Packages, func(p bundle.SoftwarePackage) bool { return p.Intent == bundle.SoftwareAvailable || p.FlatpakRef != "" }) {
			t.Fatalf("an alpha.9 agent got self-service or Flatpak content: %s", asJSON(t, b.Software))
		}
	})

	type warning struct {
		DeviceID       string         `json:"device_id"`
		AssignmentID   *string        `json:"assignment_id"`
		CatalogEntryID *string        `json:"catalog_entry_id"`
		Code           string         `json:"code"`
		Params         map[string]any `json:"params"`
	}
	warnings := func(p *env.Portal, query string) []warning {
		t.Helper()
		res := call(t, p, http.MethodGet, "/api/v1/compile-warnings?"+query, nil)
		expectStatus(t, res, http.StatusOK, "")
		var page struct {
			Items []warning `json:"items"`
		}
		if err := res.JSON(&page); err != nil {
			t.Fatal(err)
		}
		return page.Items
	}
	ofDevice := url.Values{"device_id": {d.DeviceID}, "page_size": {"100"}}.Encode()

	t.Run("forbid flatpak", func(t *testing.T) {
		runtime := gateEntry(t, alice, "", packageRef("ubuntu", "*", "flatpak"))
		forbid := assign(t, alice, map[string]any{"catalog_entry_id": runtime, "device_group_id": group, "intent": "forbid"})
		b := latestBundle(t, d, 2*time.Minute, func(b *bundle.Bundle) bool {
			p, ok := softwarePackage(b, "flatpak")
			return ok && p.Intent == bundle.SoftwareForbid
		})
		if hasPackage(availableRef)(b) || hasPackage(requiredRef)(b) ||
			slices.ContainsFunc(b.Software.Sources, func(x bundle.SoftwareSource) bool { return x.Slug == slug }) {
			t.Fatalf("a forbid of flatpak keeps Flatpak applications or the remote: %s", asJSON(t, b.Software))
		}
		var got []warning
		for deadline := time.Now().Add(time.Minute); ; time.Sleep(time.Second) {
			got = warnings(alice, ofDevice+"&code=flatpak_forbidden")
			if len(got) == 2 || time.Now().After(deadline) {
				break
			}
		}
		want := map[string]string{availableAssignment: availableRef, requiredAssignment: requiredRef}
		for _, w := range got {
			if w.DeviceID != d.DeviceID || w.AssignmentID == nil || want[*w.AssignmentID] == "" || w.Params["flatpak_ref"] != want[*w.AssignmentID] {
				t.Fatalf("compile warnings %+v", got)
			}
			delete(want, *w.AssignmentID)
		}
		if len(want) != 0 {
			t.Fatalf("compile warnings %+v, missing %v", got, want)
		}
		// Another organization reads none of them.
		for _, q := range []string{ofDevice, "assignment_id=" + availableAssignment, "catalog_entry_id=" + required, "code=flatpak_forbidden&page_size=100"} {
			if got := warnings(carol, q); slices.ContainsFunc(got, func(w warning) bool { return w.DeviceID == d.DeviceID }) {
				t.Fatalf("globex reads acme's compile warnings with %s: %+v", q, got)
			}
		}

		// Each compile replaces the device's warnings: without the forbid the applications return and none is left.
		expectStatus(t, call(t, alice, http.MethodDelete, softwareAssignments+"/"+forbid, nil), http.StatusNoContent, "")
		latestBundle(t, d, 2*time.Minute, func(b *bundle.Bundle) bool { return hasPackage(availableRef)(b) && hasPackage(requiredRef)(b) })
		for deadline := time.Now().Add(time.Minute); ; time.Sleep(time.Second) {
			got = warnings(alice, ofDevice)
			if len(got) == 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("compile warnings after the forbid was removed: %+v", got)
			}
		}
	})
}
