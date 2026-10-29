package admin

import (
	"context"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/principal"
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
	return out
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
