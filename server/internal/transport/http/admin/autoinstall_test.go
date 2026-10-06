package admin_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	"aead.dev/minisign"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/releasesig"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// The contract answers user-data as text/yaml (plan M4b decision 2); kin-openapi checks such a body as a string.
func init() { openapi3filter.RegisterBodyDecoder("text/yaml", openapi3filter.FileBodyDecoder) }

// installRelease publishes a release with both Debian packages as the newest one, so that the autoinstall uses it.
func (e *env) installRelease(t *testing.T) string {
	t.Helper()
	root := e.platformSession()
	v := "3.0.0-ai" + uuid.NewString()[:6]
	base := "/api/platform/v1/agent-releases/" + v
	if r := e.do(call{method: "POST", path: "/api/platform/v1/agent-releases", body: map[string]string{"version": v}, cookie: root}); r.status != http.StatusCreated {
		t.Fatalf("create release: %d %s", r.status, r.body)
	}
	for _, name := range []string{"paddock-agent", "paddock-supervisor"} {
		deb := []byte(name + " " + v)
		sig := base64.StdEncoding.EncodeToString(minisign.Sign(e.release, deb))
		if r := e.do(call{method: "PUT", path: base + "/packages/" + name + "/amd64", rawBody: string(deb), contentType: "application/octet-stream",
			headers: map[string]string{"X-Paddock-Minisig": sig}, cookie: root}); r.status != http.StatusOK {
			t.Fatalf("upload %s: %d %s", name, r.status, r.body)
		}
	}
	bin := []byte("paddockd " + v)
	sig := base64.StdEncoding.EncodeToString(minisign.SignWithComments(e.release, bin, releasesig.Comment(v, "amd64"), ""))
	if r := e.do(call{method: "PUT", path: base + "/artifacts/amd64", rawBody: string(bin), contentType: "application/octet-stream",
		headers: map[string]string{"X-Paddock-Minisig": sig}, cookie: root}); r.status != http.StatusOK {
		t.Fatalf("upload binary: %d %s", r.status, r.body)
	}
	if r := e.do(call{method: "POST", path: base + "/publish", cookie: root}); r.status != http.StatusOK {
		t.Fatalf("publish: %d %s", r.status, r.body)
	}
	return v
}

func (e *env) enrollmentConfig(t *testing.T, cookie *http.Cookie) adminapi.EnrollmentTokenCreated {
	t.Helper()
	created := e.do(call{method: "POST", path: "/api/v1/enrollment-tokens", cookie: cookie, body: map[string]any{
		"name": "autoinstall", "expires_at": time.Now().Add(time.Hour).UTC().Truncate(time.Second), "max_uses": 1, "auto_approve": true,
	}})
	if created.status != http.StatusCreated {
		t.Fatalf("token: %d %s", created.status, created.body)
	}
	var tok adminapi.EnrollmentTokenCreated
	created.decode(t, &tok)
	return tok
}

func TestGenerateAutoinstall(t *testing.T) {
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	bob := e.session(e.acme, principal.RoleOrgOperator)
	auditor := e.session(e.acme, principal.RoleOrgAuditor)
	carol := e.session(e.globex, principal.RoleOrgAdmin)
	v := e.installRelease(t)
	tok := e.enrollmentConfig(t, alice)
	body := func(cfg adminapi.EnrollmentConfig) map[string]any {
		return map[string]any{"enrollment_config": cfg, "release": "26.04", "hostname": "laptop-1", "locale": "en_US.UTF-8",
			"keyboard_layout": "us", "timezone": "Etc/UTC"}
	}

	res := e.do(call{method: "POST", path: "/api/v1/autoinstall", cookie: bob, body: body(tok.EnrollmentConfig)})
	if res.status != http.StatusOK || res.header.Get("Content-Type") != "text/yaml" || res.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("generate: %d %v %s", res.status, res.header, res.body)
	}
	e.expectEvent(res, "autoinstall.generated:success:")
	for _, want := range []string{"#cloud-config", `hostname: "laptop-1"`, "https://bundles.test/packages/" + v + "/paddock-agent_" + v + "_amd64.deb",
		"https://bundles.test/packages/" + v + "/paddock-supervisor_" + v + "_amd64.deb", `{\"boot_pin_min_length\":8}`} {
		if !strings.Contains(string(res.body), want) {
			t.Errorf("user-data lacks %s", want)
		}
	}
	// The token and the passphrase never reach the audit trail.
	var params string
	if err := e.super.QueryRow(context.Background(), "SELECT params::text FROM action WHERE correlation_id = $1", res.header.Get("X-Request-Id")).Scan(&params); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(params, tok.Secret) || !strings.Contains(params, `"agent_version": "`+v+`"`) || !strings.Contains(params, `"release": "26.04"`) {
		t.Fatalf("audit params %s", params)
	}

	if r := e.do(call{method: "POST", path: "/api/v1/autoinstall", cookie: auditor, body: body(tok.EnrollmentConfig)}); r.status != http.StatusForbidden {
		t.Fatalf("auditor: %d", r.status)
	}
	bad := body(tok.EnrollmentConfig)
	bad["hostname"] = "Laptop_1"
	if r := e.do(call{method: "POST", path: "/api/v1/autoinstall", cookie: alice, body: bad}); r.status != http.StatusBadRequest {
		t.Fatalf("invalid hostname: %d %s", r.status, r.body)
	}
	// Another organization's configuration is not found, like a made-up token.
	if r := e.do(call{method: "POST", path: "/api/v1/autoinstall", cookie: carol, body: body(tok.EnrollmentConfig)}); r.status != http.StatusNotFound || r.problemCode(t) != "not_found" {
		t.Fatalf("foreign configuration: %d %s", r.status, r.body)
	}
	forged := tok.EnrollmentConfig
	forged.Token = "made-up"
	if r := e.do(call{method: "POST", path: "/api/v1/autoinstall", cookie: alice, body: body(forged)}); r.status != http.StatusNotFound || r.problemCode(t) != "not_found" {
		t.Fatalf("unknown token: %d %s", r.status, r.body)
	}
	if r := e.do(call{method: "POST", path: "/api/v1/enrollment-tokens/" + tok.Token.Id.String() + "/revoke", cookie: alice}); r.status != http.StatusOK {
		t.Fatalf("revoke: %d", r.status)
	}
	r := e.do(call{method: "POST", path: "/api/v1/autoinstall", cookie: alice, body: body(tok.EnrollmentConfig)})
	if r.status != http.StatusUnprocessableEntity || r.problemCode(t) != "token_revoked" {
		t.Fatalf("revoked token: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "autoinstall.generated:failure:token_revoked")
}
