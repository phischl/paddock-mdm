package acceptance

import (
	"net/http"
	"slices"
	"sync"
	"testing"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// operatorUser is a stepped-up temporary acme operator (role org_operator) with a TOTP authenticator.
func operatorUser(t *testing.T) *mfaUser {
	t.Helper()
	return steppedUpTempUser(t, "op", env.RoleGroup("acme", "operators"))
}

// adminUser is a stepped-up temporary acme organization administrator with a TOTP authenticator; its dev-user
// colleagues keep their sessions without a step-up.
func adminUser(t *testing.T, prefix string) *mfaUser {
	t.Helper()
	return steppedUpTempUser(t, prefix, env.RoleGroup("acme", "admins"))
}

// withoutStepUp signs u in again: a second session of the same administrator that has no step-up.
func withoutStepUp(t *testing.T, u *mfaUser) *env.Portal {
	t.Helper()
	p, err := loginAs(t, u.username, u.password)
	if err != nil {
		t.Fatalf("login %s: %v", u.username, err)
	}
	return p
}

// problemDetail returns the detail of a problem response.
func problemDetail(t *testing.T, res env.Response) string {
	t.Helper()
	var p struct {
		Detail string `json:"detail"`
	}
	if err := res.JSON(&p); err != nil {
		t.Fatalf("problem body %s: %v", res.Body, err)
	}
	return p.Detail
}

// expectRefusal checks a refused request: its status and problem code, and exactly one denied audit event of code
// with that error code.
func expectRefusal(t *testing.T, viewer *env.Portal, res env.Response, status int, problemCode, code string) {
	t.Helper()
	expectStatus(t, res, status, problemCode)
	if ev := expectOneEvent(t, viewer, res.RequestID, code, "denied"); ev.ErrorCode != problemCode {
		t.Fatalf("event %s/%s with error code %q, want %q", ev.Code, ev.Outcome, ev.ErrorCode, problemCode)
	}
}

// gateOperatorRoots are the operator roots below which the gates write managed files as operators, API tokens or
// administrators without a step-up (ADR 0034 amendment 2026-10-16: every other path needs a step-up).
var gateOperatorRoots = []string{"/etc/paddock-gates/", "/opt/paddock-gates/"}

// ensureOperatorRoots adds roots to the operator roots of p's organization unless they are there; stepUp gives p a
// fresh step-up first. The list is replaced as a whole, so concurrent callers only ever add the same entries.
func ensureOperatorRoots(t *testing.T, p *env.Portal, stepUp func(), roots ...string) {
	t.Helper()
	res := call(t, p, http.MethodGet, "/api/v1/settings/managed-files", nil)
	expectStatus(t, res, http.StatusOK, "")
	var s struct {
		OperatorRoots []string `json:"operator_roots"`
	}
	if err := res.JSON(&s); err != nil {
		t.Fatal(err)
	}
	missing := false
	for _, r := range roots {
		if !slices.Contains(s.OperatorRoots, r) {
			s.OperatorRoots, missing = append(s.OperatorRoots, r), true
		}
	}
	if !missing {
		return
	}
	stepUp()
	expectStatus(t, call(t, p, http.MethodPut, "/api/v1/settings/managed-files", map[string]any{"operator_roots": s.OperatorRoots}), http.StatusOK, "")
}

// acmeRoots configures gateOperatorRoots in acme once per run, as a stepped-up temporary administrator.
var acmeRoots sync.Once

func acmeOperatorRoots(t *testing.T) {
	t.Helper()
	acmeRoots.Do(func() {
		admin := adminUser(t, "roots")
		ensureOperatorRoots(t, admin.Portal, func() { admin.stepUp(t) }, gateOperatorRoots...)
	})
}
