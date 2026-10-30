package app

import (
	"context"
	"slices"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/mcpcatalog"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// Scopes and channels of an MCPAccess.
const (
	MCPScopeOrganization = "organization"
	MCPScopePlatform     = "platform"
	MCPChannelPortal     = "portal"
	MCPChannelAPI        = "api"
	MCPChannelMCP        = "mcp"
)

// MCPAccess is what the MCP sessions of a principal may do (plan M14 §6.1 McpAccess).
type MCPAccess struct {
	Scope, Channel                                      string
	Enabled, WriteEnabled, WriteOptedIn, WriteEffective bool
	AllowedOperations                                   []string
	CatalogVersion                                      string
}

// MCPWriteRoles returns the roles allowed to perform the privileged action behind a route pattern; ok is false for a
// pattern without one. The admin transport owns that table, so it is passed in.
type MCPWriteRoles func(pattern string) (roles []principal.Role, ok bool)

// MCPAccessService answers the MCP policy that applies to a principal and what its MCP sessions may do (plan M14 §3.4
// item 19). It enforces nothing itself: the admin API's MCP guard and the ActionRunner do.
type MCPAccessService struct {
	org      *db.OrgPool
	platform *db.PlatformPool
	roles    MCPWriteRoles
}

// NewMCPAccessService creates the service; roles may be nil, which leaves write tools unfiltered by role.
func NewMCPAccessService(org *db.OrgPool, platform *db.PlatformPool, roles MCPWriteRoles) *MCPAccessService {
	return &MCPAccessService{org: org, platform: platform, roles: roles}
}

// Policy returns the MCP policy of the principal's scope: the platform's for a platform administrator, its
// organization's otherwise. Without a saved policy it is the default with the MCP off — absence never allows.
func (m *MCPAccessService) Policy(ctx context.Context, p principal.Principal) (MCPPolicy, error) {
	ctx = principal.With(ctx, p)
	out := defaultMCPPolicy()
	if p.Kind == principal.KindPlatformAdmin {
		err := m.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
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
	err := m.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
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

// Access computes what the principal's MCP sessions may do under the policy of its scope.
func (m *MCPAccessService) Access(ctx context.Context, p principal.Principal) (MCPAccess, error) {
	policy, err := m.Policy(ctx, p)
	if err != nil {
		return MCPAccess{}, err
	}
	optedIn, err := m.writeOptedIn(ctx, p)
	if err != nil {
		return MCPAccess{}, err
	}
	return mcpAccessOf(p, policy, optedIn, m.roles), nil
}

// writeOptedIn is the account's MCP write opt-in. An MCP principal carries it, re-read from its row on every request;
// a portal session reads its own row; an API token never acts through the MCP, so it has none.
func (m *MCPAccessService) writeOptedIn(ctx context.Context, p principal.Principal) (bool, error) {
	switch {
	case p.Channel == principal.ChannelMCP:
		return p.MCPWriteEnabled, nil
	case p.APITokenID != uuid.Nil:
		return false, nil
	}
	ctx = principal.With(ctx, p)
	var out bool
	if p.Kind == principal.KindPlatformAdmin {
		err := m.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
			write, err := q.GetPlatformAdminState(ctx, p.ID)
			if err != nil {
				return notFound(err)
			}
			out = write
			return nil
		})
		return out, unauthenticatedIfGone(err)
	}
	err := m.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		row, err := q.GetAdminAccountState(ctx, p.ID)
		if err != nil {
			return notFound(err)
		}
		out = row.McpWriteEnabled
		return nil
	})
	return out, unauthenticatedIfGone(err)
}

// mcpAccessOf filters the exposed, step-up-free tools by the principal's scope and the policy; write tools only
// while writes are effective and the principal's role may perform them.
func mcpAccessOf(p principal.Principal, policy MCPPolicy, optedIn bool, roles MCPWriteRoles) MCPAccess {
	out := MCPAccess{
		Scope: MCPScopeOrganization, Channel: MCPChannelPortal,
		Enabled: policy.Enabled, WriteEnabled: policy.WriteEnabled, WriteOptedIn: optedIn,
		WriteEffective:    policy.Enabled && policy.WriteEnabled && optedIn,
		AllowedOperations: []string{}, CatalogVersion: mcpcatalog.Version,
	}
	scope := mcpcatalog.ScopeOrganization
	if p.Kind == principal.KindPlatformAdmin {
		out.Scope, scope = MCPScopePlatform, mcpcatalog.ScopePlatform
	}
	switch {
	case p.Channel == principal.ChannelMCP:
		out.Channel = MCPChannelMCP
	case p.APITokenID != uuid.Nil:
		out.Channel = MCPChannelAPI
	}
	if !policy.Enabled {
		return out
	}
	for _, t := range mcpcatalog.Exposed() {
		switch {
		case t.StepUp, t.Scope != scope && t.Scope != mcpcatalog.ScopeAny:
			continue
		case policy.Mode == MCPModeSelected && !slices.Contains(policy.AllowedOperations, t.Name):
			continue
		case t.Class == mcpcatalog.ClassWrite && (!out.WriteEffective || !roleMayWrite(p, t.Pattern, roles)):
			continue
		}
		out.AllowedOperations = append(out.AllowedOperations, t.Name)
	}
	return out
}

func roleMayWrite(p principal.Principal, pattern string, roles MCPWriteRoles) bool {
	if roles == nil {
		return true
	}
	allowed, ok := roles(pattern)
	return !ok || len(allowed) == 0 || slices.Contains(allowed, p.Role)
}
