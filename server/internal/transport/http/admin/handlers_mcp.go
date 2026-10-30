package admin

import (
	"context"

	"github.com/phischl/paddock-mdm/pkg/mcpcatalog"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// GetMcpSettings answers the MCP policy of the caller's organization.
func (h *handlers) GetMcpSettings(ctx context.Context, _ adminapi.GetMcpSettingsRequestObject) (adminapi.GetMcpSettingsResponseObject, error) {
	p, err := h.mcpSettings.GetOrg(ctx)
	if err != nil {
		return nil, err
	}
	return adminapi.GetMcpSettings200JSONResponse(toMcpSettings(p)), nil
}

// UpdateMcpSettings replaces the MCP policy of the caller's organization (org_admin with a step-up).
func (h *handlers) UpdateMcpSettings(ctx context.Context, req adminapi.UpdateMcpSettingsRequestObject) (adminapi.UpdateMcpSettingsResponseObject, error) {
	p, err := h.mcpSettings.UpdateOrg(ctx, toMCPPolicyInput(*req.Body))
	if err != nil {
		return nil, err
	}
	return adminapi.UpdateMcpSettings200JSONResponse(toMcpSettings(p)), nil
}

// GetPlatformMcpSettings answers the MCP policy of the platform.
func (h *handlers) GetPlatformMcpSettings(ctx context.Context, _ adminapi.GetPlatformMcpSettingsRequestObject) (adminapi.GetPlatformMcpSettingsResponseObject, error) {
	p, err := h.mcpSettings.GetPlatform(ctx)
	if err != nil {
		return nil, err
	}
	return adminapi.GetPlatformMcpSettings200JSONResponse(toMcpSettings(p)), nil
}

// UpdatePlatformMcpSettings replaces the MCP policy of the platform (platform_admin with a step-up).
func (h *handlers) UpdatePlatformMcpSettings(ctx context.Context, req adminapi.UpdatePlatformMcpSettingsRequestObject) (adminapi.UpdatePlatformMcpSettingsResponseObject, error) {
	p, err := h.mcpSettings.UpdatePlatform(ctx, toMCPPolicyInput(*req.Body))
	if err != nil {
		return nil, err
	}
	return adminapi.UpdatePlatformMcpSettings200JSONResponse(toMcpSettings(p)), nil
}

// EnableMcpWrite opts the caller's own account in to MCP write access (step-up).
func (h *handlers) EnableMcpWrite(ctx context.Context, _ adminapi.EnableMcpWriteRequestObject) (adminapi.EnableMcpWriteResponseObject, error) {
	me, err := h.accounts.EnableMCPWrite(ctx)
	if err != nil {
		return nil, err
	}
	return adminapi.EnableMcpWrite200JSONResponse(h.requestMe(ctx, me)), nil
}

// DisableMcpWrite withdraws the caller's own MCP write opt-in.
func (h *handlers) DisableMcpWrite(ctx context.Context, _ adminapi.DisableMcpWriteRequestObject) (adminapi.DisableMcpWriteResponseObject, error) {
	me, err := h.accounts.DisableMCPWrite(ctx)
	if err != nil {
		return nil, err
	}
	return adminapi.DisableMcpWrite200JSONResponse(h.requestMe(ctx, me)), nil
}

// requestMe is the Me of an answer the portal replaces its session with, completed from the request like PATCH
// /api/v1/me.
func (h *handlers) requestMe(ctx context.Context, me app.Me) adminapi.Me {
	out := h.toMe(me)
	p, _ := principal.From(ctx)
	out.Channel = meChannel(p)
	out.ClientIp = p.IP
	out.StepUpValidUntil = h.stepUpValidUntil(p)
	out.AlternateRole = h.alternateRole(ctx)
	out.RoleFallback = roleFallback(ctx)
	return out
}

// GetMcpCatalog answers the shared MCP tool catalog.
func (h *handlers) GetMcpCatalog(_ context.Context, _ adminapi.GetMcpCatalogRequestObject) (adminapi.GetMcpCatalogResponseObject, error) {
	tools := mcpcatalog.Tools()
	out := adminapi.McpCatalog{Version: mcpcatalog.Version, Tools: make([]adminapi.McpTool, len(tools))}
	for i, t := range tools {
		out.Tools[i] = adminapi.McpTool{
			OperationId: t.Name, Method: t.Method, Path: t.Path, Tag: t.Tag, Scope: adminapi.McpToolScope(t.Scope),
			Class: adminapi.McpToolClass(t.Class), StepUp: t.StepUp, Destructive: t.Destructive, Exposed: t.Expose,
			Summary: t.Summary,
		}
	}
	return adminapi.GetMcpCatalog200JSONResponse(out), nil
}

// GetMcpAccess answers what the caller's MCP sessions may do under the MCP policy of its scope.
func (h *handlers) GetMcpAccess(ctx context.Context, _ adminapi.GetMcpAccessRequestObject) (adminapi.GetMcpAccessResponseObject, error) {
	p, ok := principal.From(ctx)
	if !ok {
		return nil, problem.Unauthenticated
	}
	a, err := h.mcpAccess.Access(ctx, p)
	if err != nil {
		return nil, err
	}
	return adminapi.GetMcpAccess200JSONResponse(adminapi.McpAccess{
		Scope: adminapi.McpAccessScope(a.Scope), Channel: adminapi.McpAccessChannel(a.Channel),
		Enabled: a.Enabled, WriteEnabled: a.WriteEnabled, WriteOptedIn: a.WriteOptedIn, WriteEffective: a.WriteEffective,
		AllowedOperations: a.AllowedOperations, CatalogVersion: a.CatalogVersion,
	}), nil
}

func toMCPPolicyInput(in adminapi.McpSettingsInput) app.MCPPolicyInput {
	return app.MCPPolicyInput{
		Enabled: in.Enabled, WriteEnabled: in.WriteEnabled, Mode: string(in.Mode), AllowedOperations: in.AllowedOperations,
	}
}

func toMcpSettings(p app.MCPPolicy) adminapi.McpSettings {
	return adminapi.McpSettings{
		Enabled: p.Enabled, WriteEnabled: p.WriteEnabled, Mode: adminapi.McpSettingsMode(p.Mode),
		AllowedOperations: p.AllowedOperations, UpdatedAt: utcPtr(p.UpdatedAt), UpdatedBy: p.UpdatedBy,
	}
}
