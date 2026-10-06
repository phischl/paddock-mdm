package app

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

func TestOutcomeOf(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		outcome audit.Outcome
		code    string
	}{
		{"nil", nil, audit.OutcomeSuccess, ""},
		{"forbidden", ErrForbidden, audit.OutcomeDenied, "forbidden"},
		{"wrapped forbidden", fmt.Errorf("x: %w", problem.Forbidden.WithDetail("role")), audit.OutcomeDenied, "forbidden"},
		{"no organization", problem.NoOrganization, audit.OutcomeDenied, "no_organization"},
		{"step-up required", problem.StepUpRequired.WithDetail("old"), audit.OutcomeDenied, "step_up_required"},
		{"validation", problem.InvalidRequest.WithDetail("name"), audit.OutcomeFailure, "invalid_request"},
		{"not found", problem.NotFound, audit.OutcomeFailure, "not_found"},
		{"conflict", problem.NameTaken, audit.OutcomeFailure, "name_taken"},
		{"upstream", problem.UpstreamUnavailable, audit.OutcomeFailure, "upstream_unavailable"},
		{"canceled", context.Canceled, audit.OutcomeFailure, "canceled"},
		{"wrapped canceled", fmt.Errorf("db: %w", context.Canceled), audit.OutcomeFailure, "canceled"},
		{"anything else", errors.New("boom"), audit.OutcomeFailure, "internal"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o, code := OutcomeOf(c.err)
			if o != c.outcome || code != c.code {
				t.Fatalf("OutcomeOf(%v) = %s/%q, want %s/%q", c.err, o, code, c.outcome, c.code)
			}
		})
	}
}

func testRunner() *ActionRunner {
	return NewActionRunner(nil, nil, func(context.Context) string { return "req-1" })
}

func TestParamsAreCopied(t *testing.T) {
	r := testRunner()
	params := map[string]any{"name": "a"}
	p := principal.Principal{Kind: principal.KindAdmin, OrganizationID: uuid.Must(uuid.NewV7())}
	rec := r.newRecorder(context.Background(), p, ScopeOrg, ActionSpec{Code: audit.CodeDeviceGroupCreated, Params: params})
	rec.SetParam("name", "b")
	params["other"] = 1
	if params["name"] != "a" {
		t.Fatal("SetParam modified the caller's map")
	}
	if _, ok := rec.params["other"]; ok {
		t.Fatal("the recorder shares the caller's map")
	}
	if rec.correlated != "req-1" || rec.org != p.OrganizationID || rec.actor.Type != audit.ActorAdmin {
		t.Fatalf("recorder not initialized from principal and request: %+v", rec)
	}
}

func TestSecretParamsPanic(t *testing.T) {
	r := testRunner()
	p := principal.Principal{Kind: principal.KindAdmin, OrganizationID: uuid.Must(uuid.NewV7())}
	for _, key := range []string{"password", "client_secret", "api_token", "Password"} {
		t.Run("spec "+key, func(t *testing.T) {
			defer expectPanic(t)
			r.newRecorder(context.Background(), p, ScopeOrg, ActionSpec{Code: audit.CodeDeviceGroupCreated, Params: map[string]any{key: "x"}})
		})
		t.Run("SetParam "+key, func(t *testing.T) {
			rec := r.newRecorder(context.Background(), p, ScopeOrg, ActionSpec{Code: audit.CodeDeviceGroupCreated})
			defer expectPanic(t)
			rec.SetParam(key, "x")
		})
	}
}

func TestUnregisteredCodePanics(t *testing.T) {
	defer expectPanic(t)
	testRunner().newRecorder(context.Background(), principal.Principal{}, ScopePlatform, ActionSpec{Code: "made.up"})
}

func TestReaperCodeIsNeverEmitted(t *testing.T) {
	defer expectPanic(t)
	testRunner().newRecorder(context.Background(), principal.Principal{}, ScopePlatform, ActionSpec{Code: audit.CodeActionFinalizedUnknown})
}

func TestAuthorize(t *testing.T) {
	org := uuid.Must(uuid.NewV7())
	spec := ActionSpec{Code: audit.CodeDeviceGroupDeleted, AllowedRoles: []principal.Role{principal.RoleOrgAdmin}}
	cases := []struct {
		name  string
		p     principal.Principal
		scope Scope
		want  error
	}{
		{"admin allowed", principal.Principal{Kind: principal.KindAdmin, Role: principal.RoleOrgAdmin, OrganizationID: org}, ScopeOrg, nil},
		{"auditor denied", principal.Principal{Kind: principal.KindAdmin, Role: principal.RoleOrgAuditor, OrganizationID: org}, ScopeOrg, problem.Forbidden},
		{"platform admin has no organization", principal.Principal{Kind: principal.KindPlatformAdmin, Role: principal.RolePlatform}, ScopeOrg, problem.NoOrganization},
		{"org admin in platform scope", principal.Principal{Kind: principal.KindAdmin, Role: principal.RoleOrgAdmin, OrganizationID: org}, ScopePlatform, problem.Forbidden},
		{"system with organization", principal.Principal{Kind: principal.KindSystem, OrganizationID: org}, ScopeOrg, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := authorizeRole(c.p, c.scope, spec)
			if (c.want == nil) != (err == nil) || (c.want != nil && !errors.Is(err, c.want)) {
				t.Fatalf("authorize = %v, want %v", err, c.want)
			}
		})
	}
}

func expectPanic(t *testing.T) {
	t.Helper()
	if recover() == nil {
		t.Fatal("expected a panic")
	}
}
