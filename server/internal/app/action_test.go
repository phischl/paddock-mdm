package app

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

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
		{"release source disabled", problem.ReleaseSourceDisabled, audit.OutcomeDenied, "release_source_disabled"},
		{"release source unavailable", problem.ReleaseSourceUnavailable, audit.OutcomeFailure, "release_source_unavailable"},
		{"validation", problem.InvalidRequest.WithDetail("name"), audit.OutcomeFailure, "invalid_request"},
		{"not found", problem.NotFound, audit.OutcomeFailure, "not_found"},
		{"conflict", problem.NameTaken, audit.OutcomeFailure, "name_taken"},
		{"upstream", problem.UpstreamUnavailable, audit.OutcomeFailure, "upstream_unavailable"},
		{"canceled", context.Canceled, audit.OutcomeFailure, "canceled"},
		{"wrapped canceled", fmt.Errorf("db: %w", context.Canceled), audit.OutcomeFailure, "canceled"},
		{"anything else", errors.New("boom"), audit.OutcomeFailure, "internal"},
		{"mcp disabled", problem.MCPDisabled, audit.OutcomeDenied, "mcp_disabled"},
		{"mcp tool not allowed", problem.MCPToolNotAllowed.WithDetail("portal only"), audit.OutcomeDenied, "mcp_tool_not_allowed"},
		{"mcp write not enabled", problem.MCPWriteNotEnabled, audit.OutcomeDenied, "mcp_write_not_enabled"},
		{"rate limited", problem.RateLimited, audit.OutcomeDenied, "rate_limited"},
		{"mcp login required", problem.MCPLoginRequired, audit.OutcomeFailure, "mcp_login_required"},
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

// TestCheckStepUpChannels: an MCP session never satisfies a step-up, even with a fresh one on the principal, and says
// so in its own detail; the API-token refusal and the portal step-up are unchanged (plan M14 §3.2 item 9).
func TestCheckStepUpChannels(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	r := NewActionRunner(nil, nil, func(context.Context) string { return "" }, WithClock(func() time.Time { return now }))
	org := uuid.Must(uuid.NewV7())
	portal := principal.Principal{Kind: principal.KindAdmin, Role: principal.RoleOrgAdmin, OrganizationID: org, StepUpAt: now}
	mcp := portal
	mcp.Channel, mcp.MCPClient, mcp.MCPWriteEnabled = principal.ChannelMCP, "claude-code/2.1", true
	token := portal
	token.APITokenID = uuid.Must(uuid.NewV7())
	platformMCP := principal.Principal{Kind: principal.KindPlatformAdmin, Role: principal.RolePlatform, StepUpAt: now, Channel: principal.ChannelMCP}
	for _, c := range []struct {
		name   string
		p      principal.Principal
		detail string
	}{
		{"mcp", mcp, "this change needs an interactive administrator in the portal: MCP sessions cannot complete a step-up"},
		{"mcp platform administrator", platformMCP, "this change needs an interactive administrator in the portal: MCP sessions cannot complete a step-up"},
		{"api token", token, "this change needs an interactive administrator: API tokens cannot complete a step-up"},
		{"portal", portal, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := r.checkStepUp(c.p)
			if c.detail == "" {
				if err != nil {
					t.Fatalf("checkStepUp = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, problem.StepUpRequired) || problem.From(err).Detail != c.detail {
				t.Fatalf("checkStepUp = %v, want step_up_required %q", err, c.detail)
			}
		})
	}
}

// TestRecorderSourceAndClient: the recorder takes the source from the principal's channel at creation and copies the
// MCP client into the actor only on the MCP channel.
func TestRecorderSourceAndClient(t *testing.T) {
	r := testRunner()
	org := uuid.Must(uuid.NewV7())
	spec := ActionSpec{Code: audit.CodeDeviceGroupCreated}
	mcp := principal.Principal{Kind: principal.KindAdmin, OrganizationID: org, Channel: principal.ChannelMCP, MCPClient: "claude-code/2.1"}
	if rec := r.newRecorder(context.Background(), mcp, ScopeOrg, spec); rec.source != audit.SourceMCP ||
		rec.actor.Type != audit.ActorAdmin || rec.actor.Client != "claude-code/2.1" {
		t.Fatalf("mcp recorder: source %q actor %+v", rec.source, rec.actor)
	}
	portal := principal.Principal{Kind: principal.KindAdmin, OrganizationID: org, MCPClient: "stray"}
	if rec := r.newRecorder(context.Background(), portal, ScopeOrg, spec); rec.source != audit.SourcePortal || rec.actor.Client != "" {
		t.Fatalf("portal recorder: source %q actor %+v", rec.source, rec.actor)
	}
	anonymous := spec
	anonymous.Actor = &audit.Actor{Type: audit.ActorAnonymous}
	if rec := r.newRecorder(context.Background(), principal.Principal{Kind: principal.KindSystem}, ScopePlatform, anonymous); rec.source != audit.SourcePortal {
		t.Fatalf("explicit anonymous actor: source %q", rec.source)
	}
}

func expectPanic(t *testing.T) {
	t.Helper()
	if recover() == nil {
		t.Fatal("expected a panic")
	}
}
