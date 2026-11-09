package admin_test

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"math/rand/v2"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

func encodedPNG(t *testing.T, w, h int, noise bool) string {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	rnd := rand.New(rand.NewPCG(1, 2))
	for y := range h {
		for x := range w {
			c := color.RGBA{R: 30, G: 90, B: 200, A: 255}
			if noise {
				c = color.RGBA{R: uint8(rnd.UintN(256)), G: uint8(rnd.UintN(256)), B: uint8(rnd.UintN(256)), A: 255}
			}
			img.Set(x, y, c)
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// TestSoftwareCatalogAPI (ticket PDK-409): the contract of entries, icons and assignments, the roles, the audit
// events and the isolation of another organization's catalog.
func TestSoftwareCatalogAPI(t *testing.T) {
	const (
		catalog     = "/api/v1/software-catalog"
		assignments = "/api/v1/software-assignments"
	)
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	bob := e.session(e.acme, principal.RoleOrgOperator)
	dave := e.session(e.acme, principal.RoleOrgAuditor)
	carol := e.session(e.globex, principal.RoleOrgAdmin)
	nano := []map[string]any{{"distribution": "ubuntu", "release": "*", "architecture": "*", "package": "nano"}}
	entry := func(mod func(b map[string]any)) map[string]any {
		b := map[string]any{"name": "Editor", "packages": nano}
		if mod != nil {
			mod(b)
		}
		return b
	}
	groupID := func(c *http.Cookie, name string) string {
		r := e.do(call{method: "POST", path: "/api/v1/device-groups", cookie: c, body: map[string]any{"name": name}})
		var g adminapi.DeviceGroup
		r.decode(t, &g)
		return g.Id.String()
	}
	vendor := func(c *http.Cookie, org string) string {
		r := e.do(call{method: "POST", path: "/api/v1/software-sources", cookie: e.steppedUp(c, time.Now()), body: map[string]any{
			"slug": "vendor", "name": "Vendor " + org, "uris": []string{"https://apt.vendor.example/"}, "suites": []string{"stable"},
			"components": []string{"main"}, "signing_key": softwareKey(t, "ed25519.asc"),
			"fingerprint": "8a36 7815 ed96 74ed 9013  609a 8f03 dff0 eb10 e2e4",
		}})
		if r.status != http.StatusCreated {
			t.Fatalf("source: %d %s", r.status, r.body)
		}
		var s adminapi.SoftwareSource
		r.decode(t, &s)
		return s.Id.String()
	}

	// Writes by an auditor are denied and audited; reads work.
	r := e.do(call{method: "POST", path: catalog, cookie: dave, body: entry(nil)})
	if r.status != http.StatusForbidden || r.problemCode(t) != "forbidden" {
		t.Fatalf("auditor create: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "software_catalog_entry.created:denied:forbidden")

	r = e.do(call{method: "POST", path: catalog, cookie: bob, body: entry(nil)})
	if r.status != http.StatusCreated {
		t.Fatalf("create: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "software_catalog_entry.created:success:")
	var created adminapi.SoftwareCatalogEntry
	r.decode(t, &created)
	if created.Name != "Editor" || created.HasIcon || created.AssignmentCount != 0 || created.SourceId != nil ||
		len(created.Packages) != 1 || r.header.Get("Location") != catalog+"/"+created.Id.String() {
		t.Fatalf("created %+v, location %q", created, r.header.Get("Location"))
	}
	item := catalog + "/" + created.Id.String()

	r = e.do(call{method: "POST", path: catalog, cookie: bob, body: entry(nil)})
	if r.status != http.StatusConflict || r.problemCode(t) != "already_exists" {
		t.Fatalf("duplicate name: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "software_catalog_entry.created:failure:already_exists")
	for name, b := range map[string]map[string]any{
		"no packages": entry(func(b map[string]any) { b["packages"] = []map[string]any{} }),
		"uppercase": entry(func(b map[string]any) {
			b["packages"] = []map[string]any{{"distribution": "ubuntu", "release": "*", "architecture": "*", "package": "Nano"}}
		}),
		"duplicate tuples": entry(func(b map[string]any) { b["packages"] = append(nano, nano[0]) }),
		"bidi name":        entry(func(b map[string]any) { b["name"] = "Ed\u202eitor" }),
	} {
		r = e.do(call{method: "POST", path: catalog, cookie: bob, body: b, skipReqCheck: true})
		if r.status != http.StatusBadRequest || r.problemCode(t) != "invalid_request" {
			t.Fatalf("%s: %d %s", name, r.status, r.body)
		}
		e.expectEvent(r, "software_catalog_entry.created:failure:invalid_request")
	}

	foreignSource := vendor(carol, "globex")
	r = e.do(call{method: "POST", path: catalog, cookie: bob, body: entry(func(b map[string]any) { b["name"] = "X"; b["source_id"] = foreignSource })})
	if r.status != http.StatusNotFound || r.problemCode(t) != "not_found" {
		t.Fatalf("source of another organization: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "software_catalog_entry.created:failure:not_found")

	// An entry with a source: the source cannot be deleted while it is used.
	source := vendor(alice, "acme")
	r = e.do(call{method: "POST", path: catalog, cookie: bob, body: entry(func(b map[string]any) { b["name"] = "Vendor tool"; b["category"] = "Tools"; b["source_id"] = source })})
	if r.status != http.StatusCreated {
		t.Fatalf("create with source: %d %s", r.status, r.body)
	}
	var withSource adminapi.SoftwareCatalogEntry
	r.decode(t, &withSource)
	if withSource.SourceSlug != "vendor" || withSource.SourceId == nil || withSource.SourceId.String() != source {
		t.Fatalf("with source %+v", withSource)
	}
	r = e.do(call{method: "DELETE", path: "/api/v1/software-sources/" + source, cookie: e.steppedUp(alice, time.Now())})
	if r.status != http.StatusConflict || r.problemCode(t) != "in_use" {
		t.Fatalf("delete used source: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "software_source.deleted:failure:in_use")

	// Lists: search, filters, role.
	var page adminapi.SoftwareCatalogEntryPage
	r = e.do(call{method: "GET", path: catalog + "?q=editor", cookie: dave})
	r.decode(t, &page)
	if r.status != http.StatusOK || page.Total != 1 || page.Items[0].Id != created.Id {
		t.Fatalf("search: %d %s", r.status, r.body)
	}
	r = e.do(call{method: "GET", path: catalog + "?category=Tools&source_id=" + source + "&sort=-name", cookie: dave})
	r.decode(t, &page)
	if page.Total != 1 || page.Items[0].Id != withSource.Id {
		t.Fatalf("filters: %s", r.body)
	}

	// Update replaces the fields; the icon is separate.
	r = e.do(call{method: "PATCH", path: item, cookie: bob, body: map[string]any{"name": "Editor", "description": "A text editor.", "packages": nano}})
	if r.status != http.StatusOK {
		t.Fatalf("update: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "software_catalog_entry.updated:success:")
	r = e.do(call{method: "PATCH", path: item, cookie: bob, body: map[string]any{"name": "Vendor tool", "packages": nano}})
	if r.status != http.StatusConflict {
		t.Fatalf("rename to an existing name: %d %s", r.status, r.body)
	}

	// Icons.
	r = e.do(call{method: "GET", path: item + "/icon", cookie: dave})
	if r.status != http.StatusNotFound || r.problemCode(t) != "not_found" {
		t.Fatalf("icon of an entry without one: %d %s", r.status, r.body)
	}
	icon := encodedPNG(t, 64, 64, false)
	r = e.do(call{method: "PUT", path: item + "/icon", cookie: dave, rawBody: icon, contentType: "image/png"})
	if r.status != http.StatusForbidden {
		t.Fatalf("auditor icon: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "software_catalog_entry.updated:denied:forbidden")
	r = e.do(call{method: "PUT", path: item + "/icon", cookie: bob, rawBody: icon, contentType: "image/png"})
	if r.status != http.StatusNoContent {
		t.Fatalf("set icon: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "software_catalog_entry.updated:success:")
	r = e.do(call{method: "GET", path: item + "/icon", cookie: dave})
	if r.status != http.StatusOK || r.header.Get("Content-Type") != "image/png" || string(r.body) != icon ||
		r.header.Get("Cache-Control") != "private, max-age=300" {
		t.Fatalf("get icon: %d %q %q", r.status, r.header.Get("Content-Type"), r.header.Get("Cache-Control"))
	}
	var jpg bytes.Buffer
	if err := jpeg.Encode(&jpg, image.NewRGBA(image.Rect(0, 0, 8, 8)), nil); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"jpeg": jpg.String(), "600 by 600": encodedPNG(t, 600, 600, false), "above the limit": encodedPNG(t, 150, 150, true), "empty": "",
	} {
		r = e.do(call{method: "PUT", path: item + "/icon", cookie: bob, rawBody: body, contentType: "image/png", skipReqCheck: true})
		if r.status != http.StatusBadRequest || r.problemCode(t) != "invalid_request" {
			t.Fatalf("%s: %d %s", name, r.status, r.body)
		}
		e.expectEvent(r, "software_catalog_entry.updated:failure:invalid_request")
	}
	if len(encodedPNG(t, 150, 150, true)) <= 65536 {
		t.Fatal("the oversized fixture fits the limit")
	}
	if r = e.do(call{method: "GET", path: item, cookie: dave}); !strings.Contains(string(r.body), `"has_icon":true`) {
		t.Fatalf("has_icon: %s", r.body)
	}

	// Assignments.
	group := groupID(alice, "Laptops")
	assign := func(mod func(b map[string]any)) map[string]any {
		b := map[string]any{"catalog_entry_id": created.Id.String(), "device_group_id": group, "intent": "required", "update_rule": "pinned", "version": "1.0"}
		if mod != nil {
			mod(b)
		}
		return b
	}
	r = e.do(call{method: "POST", path: assignments, cookie: dave, body: assign(nil)})
	if r.status != http.StatusForbidden {
		t.Fatalf("auditor assign: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "software_assignment.created:denied:forbidden")
	r = e.do(call{method: "POST", path: assignments, cookie: bob, body: assign(nil)})
	if r.status != http.StatusCreated {
		t.Fatalf("assign: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "software_assignment.created:success:")
	var a adminapi.SoftwareAssignment
	r.decode(t, &a)
	if a.AppName != "Editor" || a.Intent != "required" || a.UpdateRule != "pinned" || a.Version == nil || *a.Version != "1.0" ||
		r.header.Get("Location") != assignments+"/"+a.Id.String() {
		t.Fatalf("assignment %+v", a)
	}
	itemA := assignments + "/" + a.Id.String()
	for name, mod := range map[string]func(b map[string]any){
		"required latest with version": func(b map[string]any) { b["update_rule"] = "latest" },
		"required pinned no version":   func(b map[string]any) { delete(b, "version") },
		"forbid with version":          func(b map[string]any) { b["intent"] = "forbid"; delete(b, "update_rule") },
		"hold pinned":                  func(b map[string]any) { b["intent"] = "hold" },
		"bad version":                  func(b map[string]any) { b["version"] = "1 0" },
		"unknown intent":               func(b map[string]any) { b["intent"] = "available" },
	} {
		r = e.do(call{method: "POST", path: assignments, cookie: bob, body: assign(mod), skipReqCheck: true})
		if r.status != http.StatusBadRequest || r.problemCode(t) != "invalid_request" {
			t.Fatalf("%s: %d %s", name, r.status, r.body)
		}
		e.expectEvent(r, "software_assignment.created:failure:invalid_request")
	}
	r = e.do(call{method: "POST", path: assignments, cookie: bob, body: assign(nil)})
	if r.status != http.StatusConflict || r.problemCode(t) != "already_exists" {
		t.Fatalf("second assignment in the scope: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "software_assignment.created:failure:already_exists")
	r = e.do(call{method: "POST", path: assignments, cookie: bob, body: assign(func(b map[string]any) { b["device_group_id"] = uuid.NewString() })})
	if r.status != http.StatusNotFound || r.problemCode(t) != "not_found" {
		t.Fatalf("unknown group: %d %s", r.status, r.body)
	}
	r = e.do(call{method: "POST", path: assignments, cookie: bob, body: assign(func(b map[string]any) { b["device_group_id"] = groupID(carol, "Foreign") })})
	if r.status != http.StatusNotFound {
		t.Fatalf("group of another organization: %d %s", r.status, r.body)
	}
	r = e.do(call{method: "POST", path: assignments, cookie: bob, body: assign(func(b map[string]any) { b["catalog_entry_id"] = uuid.NewString() })})
	if r.status != http.StatusNotFound {
		t.Fatalf("unknown entry: %d %s", r.status, r.body)
	}
	// The organization-wide assignment of the same entry is a separate scope; an omitted rule is derived.
	r = e.do(call{method: "POST", path: assignments, cookie: bob, body: map[string]any{"catalog_entry_id": created.Id.String(), "intent": "hold"}})
	if r.status != http.StatusCreated {
		t.Fatalf("organization-wide: %d %s", r.status, r.body)
	}
	var orgWide adminapi.SoftwareAssignment
	r.decode(t, &orgWide)
	if orgWide.DeviceGroupId != nil || orgWide.UpdateRule != "latest" {
		t.Fatalf("organization-wide %+v", orgWide)
	}

	r = e.do(call{method: "GET", path: assignments + "?catalog_entry_id=" + created.Id.String() + "&intent=required&device_group_id=" + group + "&q=edit", cookie: dave})
	var apage adminapi.SoftwareAssignmentPage
	r.decode(t, &apage)
	if r.status != http.StatusOK || apage.Total != 1 || apage.Items[0].Id != a.Id {
		t.Fatalf("assignment list: %d %s", r.status, r.body)
	}
	if r = e.do(call{method: "GET", path: assignments + "?target=bogus", cookie: dave, skipReqCheck: true}); r.status != http.StatusBadRequest ||
		r.problemCode(t) != "invalid_request" {
		t.Fatalf("assignment list with an unknown target: %d %s", r.status, r.body)
	}
	if r = e.do(call{method: "GET", path: assignments + "?target=device_group", cookie: dave}); r.status != http.StatusOK {
		t.Fatalf("assignment list with target device_group: %d %s", r.status, r.body)
	}
	if r = e.do(call{method: "GET", path: item, cookie: dave}); !strings.Contains(string(r.body), `"assignment_count":2`) {
		t.Fatalf("assignment_count: %s", r.body)
	}

	// Update: the rules apply to the new state, the entry and the scope are fixed.
	for name, b := range map[string]map[string]any{
		"forbid with version": {"intent": "forbid", "version": "1.0"},
		"entry given":         {"intent": "required", "catalog_entry_id": created.Id.String()},
		"group given":         {"intent": "required", "device_group_id": group},
	} {
		r = e.do(call{method: "PATCH", path: itemA, cookie: bob, body: b})
		if r.status != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", name, r.status, r.body)
		}
		e.expectEvent(r, "software_assignment.updated:failure:invalid_request")
	}
	r = e.do(call{method: "PATCH", path: itemA, cookie: bob, body: map[string]any{"intent": "forbid", "reason": "banned"}})
	if r.status != http.StatusOK {
		t.Fatalf("patch to forbid: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "software_assignment.updated:success:")
	r.decode(t, &a)
	if a.Intent != "forbid" || a.Version != nil || a.UpdateRule != "latest" || a.Reason != "banned" {
		t.Fatalf("patched %+v", a)
	}

	// Isolation: another organization neither sees nor changes anything.
	for _, c := range []call{
		{method: "GET", path: item, cookie: carol},
		{method: "PATCH", path: item, cookie: carol, body: map[string]any{"name": "Mine", "packages": nano}},
		{method: "DELETE", path: item, cookie: carol},
		{method: "GET", path: item + "/icon", cookie: carol},
		{method: "PUT", path: item + "/icon", cookie: carol, rawBody: icon, contentType: "image/png"},
		{method: "GET", path: itemA, cookie: carol},
		{method: "PATCH", path: itemA, cookie: carol, body: map[string]any{"intent": "hold"}},
		{method: "DELETE", path: itemA, cookie: carol},
		{method: "POST", path: assignments, cookie: carol, body: assign(func(b map[string]any) { delete(b, "device_group_id") })},
	} {
		if r := e.do(c); r.status != http.StatusNotFound || r.problemCode(t) != "not_found" {
			t.Fatalf("%s %s by another organization: %d %s", c.method, c.path, r.status, r.body)
		}
	}
	r = e.do(call{method: "GET", path: catalog, cookie: carol})
	r.decode(t, &page)
	if page.Total != 0 {
		t.Fatalf("another organization lists %+v", page)
	}

	// Deleting an entry removes its assignments.
	r = e.do(call{method: "DELETE", path: itemA, cookie: dave})
	if r.status != http.StatusForbidden {
		t.Fatalf("auditor delete assignment: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "software_assignment.deleted:denied:forbidden")
	r = e.do(call{method: "DELETE", path: item, cookie: dave})
	if r.status != http.StatusForbidden {
		t.Fatalf("auditor delete entry: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "software_catalog_entry.deleted:denied:forbidden")
	r = e.do(call{method: "DELETE", path: item, cookie: bob})
	if r.status != http.StatusNoContent {
		t.Fatalf("delete entry: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "software_catalog_entry.deleted:success:")
	r = e.do(call{method: "GET", path: assignments + "?catalog_entry_id=" + created.Id.String(), cookie: dave})
	r.decode(t, &apage)
	if apage.Total != 0 {
		t.Fatalf("assignments after the entry is gone: %s", r.body)
	}
	if r = e.do(call{method: "GET", path: itemA, cookie: dave}); r.status != http.StatusNotFound {
		t.Fatalf("assignment after the entry is gone: %d", r.status)
	}

	// Without an entry, an assignment is deleted on its own.
	r = e.do(call{method: "POST", path: assignments, cookie: bob, body: map[string]any{"catalog_entry_id": withSource.Id.String(), "intent": "uninstall"}})
	var b adminapi.SoftwareAssignment
	r.decode(t, &b)
	r = e.do(call{method: "DELETE", path: assignments + "/" + b.Id.String(), cookie: bob})
	if r.status != http.StatusNoContent {
		t.Fatalf("delete assignment: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "software_assignment.deleted:success:")
}

// TestSoftwareCatalogProtectedPackagesAPI (architect decision 2026-11-02): an entry naming a Paddock package, and an
// intent that would remove a package Paddock depends on, answer 400 invalid_request with one failure event.
func TestSoftwareCatalogProtectedPackagesAPI(t *testing.T) {
	e := newEnv(t)
	bob := e.session(e.acme, principal.RoleOrgOperator)
	entry := func(name, pkg string) map[string]any {
		return map[string]any{"name": name, "packages": []map[string]any{{"distribution": "ubuntu", "release": "*", "architecture": "*", "package": pkg}}}
	}
	r := e.do(call{method: "POST", path: "/api/v1/software-catalog", cookie: bob, body: entry("Agent", "paddock-agent")})
	if r.status != http.StatusBadRequest || r.problemCode(t) != "invalid_request" || !strings.Contains(string(r.body), "paddock-agent") {
		t.Fatalf("entry naming the agent: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "software_catalog_entry.created:failure:invalid_request")

	r = e.do(call{method: "POST", path: "/api/v1/software-catalog", cookie: bob, body: entry("Sudo", "sudo")})
	if r.status != http.StatusCreated {
		t.Fatalf("entry naming sudo: %d %s", r.status, r.body)
	}
	var sudo adminapi.SoftwareCatalogEntry
	r.decode(t, &sudo)
	r = e.do(call{method: "POST", path: "/api/v1/software-assignments", cookie: bob, body: map[string]any{"catalog_entry_id": sudo.Id.String(), "intent": "forbid"}})
	if r.status != http.StatusBadRequest || r.problemCode(t) != "invalid_request" {
		t.Fatalf("forbid sudo: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "software_assignment.created:failure:invalid_request")
	r = e.do(call{method: "POST", path: "/api/v1/software-assignments", cookie: bob, body: map[string]any{"catalog_entry_id": sudo.Id.String(), "intent": "required"}})
	if r.status != http.StatusCreated {
		t.Fatalf("require sudo: %d %s", r.status, r.body)
	}
}
