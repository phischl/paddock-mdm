package admin_test

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

func softwareKey(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "domain", "software", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestSoftwareSourcesAPI (ticket PDK-408): the step-up, the problems of the contract, the list without the signing
// key and the isolation of another organization's sources.
func TestSoftwareSourcesAPI(t *testing.T) {
	const (
		path      = "/api/v1/software-sources"
		ed25519FP = "8A367815ED9674ED9013609A8F03DFF0EB10E2E4"
		rsa3072FP = "5D47E8B7736A9129C4FDA19E1F2C82BB297A4093"
	)
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	bob := e.session(e.acme, principal.RoleOrgOperator)
	carol := e.session(e.globex, principal.RoleOrgAdmin)
	token := e.createAPIToken("acme", alice, "sources", adminapi.ApiTokenRoleOrgAdmin)
	body := func(mod func(b map[string]any)) map[string]any {
		b := map[string]any{
			"slug": "vendor", "name": "Vendor", "uris": []string{"https://apt.vendor.example/"}, "suites": []string{"stable"},
			"components": []string{"main"}, "signing_key": softwareKey(t, "ed25519.asc"),
			"fingerprint": "8a36 7815 ed96 74ed 9013  609a 8f03 dff0 eb10 e2e4",
		}
		if mod != nil {
			mod(b)
		}
		return b
	}
	post := func(c *http.Cookie, b map[string]any) result {
		return e.do(call{method: "POST", path: path, cookie: c, body: b})
	}

	r := post(alice, body(nil))
	if r.status != http.StatusForbidden || r.problemCode(t) != "step_up_required" {
		t.Fatalf("without step-up: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "software_source.created:denied:step_up_required")
	r = e.do(call{method: "POST", path: path, headers: bearer(token.Secret), skipReqCheck: true, body: body(nil)})
	if r.status != http.StatusForbidden || r.problemCode(t) != "step_up_required" {
		t.Fatalf("api token: %d %s", r.status, r.body)
	}
	r = post(e.steppedUp(bob, time.Now()), body(nil))
	if r.status != http.StatusForbidden || r.problemCode(t) != "forbidden" {
		t.Fatalf("operator: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "software_source.created:denied:forbidden")
	r = post(e.steppedUp(alice, time.Now()), body(func(b map[string]any) { b["uris"] = []string{"http://apt.vendor.example/"} }))
	if r.status != http.StatusBadRequest || !strings.Contains(string(r.body), "uris must use https") {
		t.Fatalf("http: %d %s", r.status, r.body)
	}
	r = post(e.steppedUp(alice, time.Now()), body(func(b map[string]any) { b["fingerprint"] = rsa3072FP }))
	if r.status != http.StatusUnprocessableEntity || r.problemCode(t) != "fingerprint_mismatch" {
		t.Fatalf("mismatch: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "software_source.created:failure:fingerprint_mismatch")
	r = post(e.steppedUp(alice, time.Now()), body(func(b map[string]any) { b["suites"] = []string{"./"} }))
	if r.status != http.StatusBadRequest {
		t.Fatalf("flat suite with components: %d %s", r.status, r.body)
	}

	r = post(e.steppedUp(alice, time.Now()), body(nil))
	if r.status != http.StatusCreated {
		t.Fatalf("create: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "software_source.created:success:")
	var created adminapi.SoftwareSource
	r.decode(t, &created)
	if created.Fingerprint != ed25519FP || r.header.Get("Location") != path+"/"+created.Id.String() || created.SigningKey == "" {
		t.Fatalf("created %+v, location %q", created, r.header.Get("Location"))
	}
	for _, dup := range []map[string]any{body(func(b map[string]any) { b["name"] = "Other" }), body(func(b map[string]any) { b["slug"] = "other" })} {
		if r := post(e.steppedUp(alice, time.Now()), dup); r.status != http.StatusConflict || r.problemCode(t) != "already_exists" {
			t.Fatalf("duplicate: %d %s", r.status, r.body)
		}
	}

	r = e.do(call{method: "GET", path: path + "?q=vend&sort=-updated_at&page_size=10", cookie: bob})
	if r.status != http.StatusOK || strings.Contains(string(r.body), "signing_key") {
		t.Fatalf("list: %d %s", r.status, r.body)
	}
	var page adminapi.SoftwareSourcePage
	r.decode(t, &page)
	if page.Total != 1 || page.Items[0].Id != created.Id || page.Items[0].EntryCount != 0 || created.EntryCount != 0 {
		t.Fatalf("page %+v", page)
	}
	item := path + "/" + created.Id.String()
	// PDK-716: entry_count follows the entries that use the source, in the list and in the single read.
	if _, err := e.super.Exec(context.Background(), `INSERT INTO software_catalog_entry (id, organization_id, name, source_id, packages)
		VALUES ($1, $2, 'Counted', $3, '[{"distribution":"ubuntu","release":"*","architecture":"*","package":"nano"}]'::jsonb)`,
		uuid.Must(uuid.NewV7()), e.acme, created.Id); err != nil {
		t.Fatal(err)
	}
	r = e.do(call{method: "GET", path: path + "?q=vend", cookie: bob})
	r.decode(t, &page)
	var single adminapi.SoftwareSource
	e.do(call{method: "GET", path: item, cookie: bob}).decode(t, &single)
	if page.Items[0].EntryCount != 1 || single.EntryCount != 1 {
		t.Fatalf("entry_count %d in the list, %d in the read, want 1", page.Items[0].EntryCount, single.EntryCount)
	}
	if _, err := e.super.Exec(context.Background(), `DELETE FROM software_catalog_entry WHERE name = 'Counted'`); err != nil {
		t.Fatal(err)
	}
	if r := e.do(call{method: "PATCH", path: item, cookie: e.steppedUp(alice, time.Now()), body: map[string]any{"slug": "other"}}); r.status != http.StatusBadRequest {
		t.Fatalf("patch slug: %d %s", r.status, r.body)
	}
	if r := e.do(call{method: "PATCH", path: item, cookie: e.steppedUp(alice, time.Now()), body: map[string]any{"signing_key": softwareKey(t, "rsa3072.asc")}}); r.status != http.StatusBadRequest {
		t.Fatalf("patch key without fingerprint: %d %s", r.status, r.body)
	}
	r = e.do(call{method: "PATCH", path: item, cookie: e.steppedUp(alice, time.Now()), body: map[string]any{
		"signing_key": softwareKey(t, "rsa3072.asc"), "fingerprint": rsa3072FP,
	}})
	if r.status != http.StatusOK {
		t.Fatalf("patch key: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "software_source.updated:success:")

	for _, c := range []call{
		{method: "GET", path: item, cookie: carol},
		{method: "PATCH", path: item, cookie: e.steppedUp(carol, time.Now()), body: map[string]any{"name": "Mine"}},
		{method: "DELETE", path: item, cookie: e.steppedUp(carol, time.Now())},
	} {
		if r := e.do(c); r.status != http.StatusNotFound || r.problemCode(t) != "not_found" {
			t.Fatalf("%s by another organization: %d %s", c.method, r.status, r.body)
		}
	}
	r = e.do(call{method: "GET", path: path, cookie: carol})
	r.decode(t, &page)
	if page.Total != 0 {
		t.Fatalf("another organization lists %+v", page)
	}

	r = e.do(call{method: "DELETE", path: item, cookie: e.steppedUp(alice, time.Now())})
	if r.status != http.StatusNoContent {
		t.Fatalf("delete: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "software_source.deleted:success:")
}
