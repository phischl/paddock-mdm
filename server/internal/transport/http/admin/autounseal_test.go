package admin_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

const autoUnsealPath = "/api/platform/v1/openbao/auto-unseal"

// resetAutoUnseal returns the platform-wide row to the state of the migration, now and after the test.
func (e *env) resetAutoUnseal() {
	reset := func() {
		if _, err := e.super.Exec(context.Background(), `UPDATE openbao_auto_unseal SET state = 'disabled',
			disclaimer_version = NULL, acknowledgement = NULL, acknowledged_by = NULL, acknowledged_by_subject = NULL,
			acknowledged_at = NULL, disabled_by = NULL, disabled_at = NULL, unsealer_seen_at = NULL WHERE id = 1`); err != nil {
			e.t.Fatal(err)
		}
	}
	reset()
	e.t.Cleanup(reset)
}

// TestAutoUnsealAPI covers plan M8u decision 7 and §9 U1–U3 at the handler: platform administrators read; enabling
// and disabling need a step-up; organization administrators and API tokens are refused; every attempt is audited and
// the responses follow the contract.
func TestAutoUnsealAPI(t *testing.T) {
	e := newEnv(t)
	e.resetAutoUnseal()
	root := e.platformSession()
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	token := e.createAPIToken("acme", alice, "auto-unseal", adminapi.ApiTokenRoleOrgAdmin)

	r := e.do(call{method: "GET", path: autoUnsealPath, cookie: root})
	var st adminapi.AutoUnsealStatus
	r.decode(t, &st)
	if r.status != http.StatusOK || st.State != adminapi.Disabled || st.DisclaimerVersion != "2026-10-17" ||
		st.AcknowledgementVersion != nil || st.Unsealer.Running || st.Seal.Reachable {
		t.Fatalf("GET: %d %s", r.status, r.body)
	}
	if got := e.events(r.header.Get("X-Request-Id")); len(got) != 0 {
		t.Fatalf("a read recorded %v", got)
	}
	if r := e.do(call{method: "GET", path: autoUnsealPath, cookie: alice}); r.status != http.StatusForbidden || r.problemCode(t) != "forbidden" {
		t.Fatalf("GET by an organization administrator: %d %s", r.status, r.body)
	}
	if r := e.do(call{method: "GET", path: autoUnsealPath, headers: bearer(token.Secret), skipReqCheck: true}); r.status < 401 || r.status == http.StatusOK {
		t.Fatalf("GET with an API token: %d %s", r.status, r.body)
	}

	enable := func(c *http.Cookie, version, ack string) result {
		return e.do(call{method: "POST", path: autoUnsealPath + "/enable", cookie: c,
			body: map[string]any{"disclaimer_version": version, "acknowledgement": ack}})
	}
	r = enable(root, "2026-10-17", "I understand and accept the risk")
	if r.status != http.StatusForbidden || r.problemCode(t) != "step_up_required" {
		t.Fatalf("enable without step-up: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.auto_unseal_enabled:denied:step_up_required")

	r = enable(e.steppedUp(alice, time.Now()), "2026-10-17", "I understand and accept the risk")
	if r.status != http.StatusForbidden || r.problemCode(t) != "forbidden" {
		t.Fatalf("enable by an organization administrator: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.auto_unseal_enabled:denied:forbidden")

	stepped := e.steppedUp(root, time.Now())
	r = enable(stepped, "2000-01-01", "I understand and accept the risk")
	if r.status != http.StatusConflict || r.problemCode(t) != "disclaimer_outdated" {
		t.Fatalf("outdated disclaimer: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.auto_unseal_enabled:failure:disclaimer_outdated")

	r = enable(stepped, "2026-10-17", "I accept")
	if r.status != http.StatusBadRequest || r.problemCode(t) != "invalid_request" {
		t.Fatalf("wrong sentence: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.auto_unseal_enabled:failure:invalid_request")

	r = enable(stepped, "2026-10-17", "Ich verstehe und akzeptiere das Risiko")
	r.decode(t, &st)
	if r.status != http.StatusOK || st.State != adminapi.Enabled || st.AcknowledgedBy == nil || *st.AcknowledgedBy != "root@test" ||
		st.AcknowledgementVersion == nil || *st.AcknowledgementVersion != "2026-10-17" || st.Acknowledgement == nil ||
		*st.Acknowledgement != "Ich verstehe und akzeptiere das Risiko" || st.AcknowledgedAt == nil {
		t.Fatalf("enable: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.auto_unseal_enabled:success:")

	if _, err := e.super.Exec(context.Background(), "UPDATE openbao_auto_unseal SET unsealer_seen_at = now(), unsealer_shares_present = true WHERE id = 1"); err != nil {
		t.Fatal(err)
	}
	r = e.do(call{method: "GET", path: autoUnsealPath, cookie: root})
	r.decode(t, &st)
	if !st.Unsealer.Running || !st.Unsealer.SharesPresent || st.Unsealer.SeenAt == nil {
		t.Fatalf("unsealer report: %s", r.body)
	}

	r = e.do(call{method: "POST", path: autoUnsealPath + "/disable", cookie: root})
	if r.status != http.StatusForbidden || r.problemCode(t) != "step_up_required" {
		t.Fatalf("disable without step-up: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.auto_unseal_disabled:denied:step_up_required")

	r = e.do(call{method: "POST", path: autoUnsealPath + "/disable", cookie: e.steppedUp(alice, time.Now())})
	if r.status != http.StatusForbidden || r.problemCode(t) != "forbidden" {
		t.Fatalf("disable by an organization administrator: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.auto_unseal_disabled:denied:forbidden")

	r = e.do(call{method: "POST", path: autoUnsealPath + "/disable", cookie: stepped})
	r.decode(t, &st)
	if r.status != http.StatusOK || st.State != adminapi.Disabled || st.DisabledBy == nil || st.DisabledAt == nil ||
		st.Acknowledgement == nil || st.AcknowledgedBy == nil {
		t.Fatalf("disable: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.auto_unseal_disabled:success:")

	r = e.do(call{method: "POST", path: autoUnsealPath + "/disable", cookie: stepped, noCSRF: true, skipReqCheck: true})
	if r.status != http.StatusForbidden || r.problemCode(t) != "csrf_missing" {
		t.Fatalf("disable without CSRF header: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.auto_unseal_disabled:denied:csrf_missing")
}
