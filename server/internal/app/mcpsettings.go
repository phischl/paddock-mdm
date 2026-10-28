package app

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/mcpcatalog"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Privileged actions of the MCP policies (plan M14 §3.4 item 17).
var (
	SpecMCPSettingsUpdate         = ActionSpec{Code: audit.CodeOrganizationMCPPolicyChanged, AllowedRoles: RolesAdmin, RequiresStepUp: true}
	SpecPlatformMCPSettingsUpdate = ActionSpec{Code: audit.CodePlatformMCPPolicyChanged, AllowedRoles: RolesPlatform, RequiresStepUp: true}
)

// MCP policy modes: all allows every exposed tool of the scope, selected only the listed ones.
const (
	MCPModeAll      = "all"
	MCPModeSelected = "selected"
)

// MaxMCPAllowedOperations bounds the selected tools of a policy (the columns' check constraint).
const MaxMCPAllowedOperations = 500

// MCPPolicy is the MCP policy of an organization or of the platform (ADR 0044 decision 5).
type MCPPolicy struct {
	Enabled, WriteEnabled bool
	Mode                  string
	AllowedOperations     []string
	UpdatedAt             *time.Time
	UpdatedBy             *uuid.UUID
}

// MCPPolicyInput is a complete replacement of an MCP policy.
type MCPPolicyInput struct {
	Enabled, WriteEnabled bool
	Mode                  string
	AllowedOperations     []string
}

// defaultMCPPolicy applies while a scope has no saved policy: the MCP is off until an administrator saves one
// (ADR 0044, maintainer decision 2026-10-25).
func defaultMCPPolicy() MCPPolicy {
	return MCPPolicy{Mode: MCPModeAll, AllowedOperations: []string{}}
}

// MCPSettings are the use cases of the MCP policies.
type MCPSettings struct {
	runner   *ActionRunner
	org      *db.OrgPool
	platform *db.PlatformPool
}

// NewMCPSettings creates the use cases.
func NewMCPSettings(runner *ActionRunner, org *db.OrgPool, platform *db.PlatformPool) *MCPSettings {
	return &MCPSettings{runner: runner, org: org, platform: platform}
}

// ValidateMCPPolicy checks a policy: mode all with no operations, or mode selected with 1 … 500 distinct ids of
// exposed MCP tools that need no step-up. The error is 400 invalid_request naming the offending value.
func ValidateMCPPolicy(in MCPPolicyInput) error {
	switch in.Mode {
	case MCPModeAll:
		if len(in.AllowedOperations) > 0 {
			return problem.InvalidRequest.WithDetail("mode all requires an empty allowed_operations")
		}
		return nil
	case MCPModeSelected:
	default:
		return problem.InvalidRequest.WithDetail(fmt.Sprintf("unknown mode %q", in.Mode))
	}
	switch n := len(in.AllowedOperations); {
	case n == 0:
		return problem.InvalidRequest.WithDetail("mode selected requires at least one operation in allowed_operations")
	case n > MaxMCPAllowedOperations:
		return problem.InvalidRequest.WithDetail(fmt.Sprintf("at most %d operations in allowed_operations, got %d", MaxMCPAllowedOperations, n))
	}
	seen := make(map[string]bool, len(in.AllowedOperations))
	for _, id := range in.AllowedOperations {
		if seen[id] {
			return problem.InvalidRequest.WithDetail(fmt.Sprintf("operation %q is listed twice", id))
		}
		seen[id] = true
		tool, ok := mcpcatalog.ByName(id)
		switch {
		case !ok:
			return problem.InvalidRequest.WithDetail(fmt.Sprintf("unknown operation %q", id))
		case tool.StepUp:
			return problem.InvalidRequest.WithDetail(fmt.Sprintf("operation %q needs a step-up and is never available through the MCP", id))
		case !tool.Expose:
			return problem.InvalidRequest.WithDetail(fmt.Sprintf("operation %q is not available through the MCP", id))
		}
	}
	return nil
}

// GetOrg returns the MCP policy of the caller's organization (roles org_admin, org_operator, org_auditor).
func (s *MCPSettings) GetOrg(ctx context.Context) (MCPPolicy, error) {
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return MCPPolicy{}, err
	}
	out := defaultMCPPolicy()
	err := s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		row, err := q.GetOrgMcpSettings(ctx)
		if db.IsNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		out = mcpPolicy(row.Enabled, row.WriteEnabled, row.Mode, row.AllowedOperations, row.UpdatedAt, row.UpdatedBy)
		return nil
	})
	return out, err
}

// UpdateOrg replaces the MCP policy of the caller's organization (audited: organization.mcp_policy_changed).
func (s *MCPSettings) UpdateOrg(ctx context.Context, in MCPPolicyInput) (MCPPolicy, error) {
	var out MCPPolicy
	err := s.runner.RunTx(ctx, ScopeOrg, withMCPPolicyParams(SpecMCPSettingsUpdate, in), func(ctx context.Context, q *pgstore.Queries, _ Recorder) error {
		if err := ValidateMCPPolicy(in); err != nil {
			return err
		}
		org, err := orgOf(ctx)
		if err != nil {
			return err
		}
		p, _ := principal.From(ctx)
		row, err := q.UpsertOrgMcpSettings(ctx, pgstore.UpsertOrgMcpSettingsParams{
			OrganizationID: org, Enabled: in.Enabled, WriteEnabled: in.WriteEnabled, Mode: in.Mode,
			AllowedOperations: nonNil(in.AllowedOperations),
			UpdatedBy:         uuid.NullUUID{UUID: p.ID, Valid: p.Kind == principal.KindAdmin && p.ID != uuid.Nil},
		})
		if err != nil {
			return err
		}
		out = mcpPolicy(row.Enabled, row.WriteEnabled, row.Mode, row.AllowedOperations, row.UpdatedAt, row.UpdatedBy)
		return nil
	})
	return out, err
}

// GetPlatform returns the MCP policy of the platform (role platform_admin).
func (s *MCPSettings) GetPlatform(ctx context.Context) (MCPPolicy, error) {
	if _, err := RequirePlatform(ctx); err != nil {
		return MCPPolicy{}, err
	}
	out := defaultMCPPolicy()
	err := s.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		row, err := q.GetPlatformMcpSettings(ctx)
		if db.IsNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		out = mcpPolicy(row.Enabled, row.WriteEnabled, row.Mode, row.AllowedOperations, row.UpdatedAt, row.UpdatedBy)
		return nil
	})
	return out, err
}

// UpdatePlatform replaces the MCP policy of the platform (audited: platform.mcp_policy_changed).
func (s *MCPSettings) UpdatePlatform(ctx context.Context, in MCPPolicyInput) (MCPPolicy, error) {
	var out MCPPolicy
	err := s.runner.RunTx(ctx, ScopePlatform, withMCPPolicyParams(SpecPlatformMCPSettingsUpdate, in), func(ctx context.Context, q *pgstore.Queries, _ Recorder) error {
		if err := ValidateMCPPolicy(in); err != nil {
			return err
		}
		p, _ := principal.From(ctx)
		row, err := q.UpsertPlatformMcpSettings(ctx, pgstore.UpsertPlatformMcpSettingsParams{
			Enabled: in.Enabled, WriteEnabled: in.WriteEnabled, Mode: in.Mode,
			AllowedOperations: nonNil(in.AllowedOperations),
			UpdatedBy:         uuid.NullUUID{UUID: p.ID, Valid: p.Kind == principal.KindPlatformAdmin && p.ID != uuid.Nil},
		})
		if err != nil {
			return err
		}
		out = mcpPolicy(row.Enabled, row.WriteEnabled, row.Mode, row.AllowedOperations, row.UpdatedAt, row.UpdatedBy)
		return nil
	})
	return out, err
}

// withMCPPolicyParams puts the requested policy into the event params, so a denied or refused attempt shows what was
// asked for as well as a successful one.
func withMCPPolicyParams(spec ActionSpec, in MCPPolicyInput) ActionSpec {
	spec.Params = map[string]any{
		"enabled": in.Enabled, "write_enabled": in.WriteEnabled, "mode": in.Mode, "allowed_count": len(in.AllowedOperations),
	}
	return spec
}

func mcpPolicy(enabled, write bool, mode string, ops []string, at time.Time, by uuid.NullUUID) MCPPolicy {
	out := MCPPolicy{Enabled: enabled, WriteEnabled: write, Mode: mode, AllowedOperations: nonNil(ops), UpdatedAt: &at}
	if by.Valid {
		id := by.UUID
		out.UpdatedBy = &id
	}
	return out
}
