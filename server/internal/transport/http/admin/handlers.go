package admin

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/listing"
)

// handlers implements the generated strict server. Errors are returned as *problem.Error and rendered by the
// response error handler.
type handlers struct {
	groups   *app.DeviceGroups
	orgs     *app.Organizations
	accounts *app.Accounts
	audit    *app.AuditLog
	// integrity is the evidence integrity of the audit log (plan M8b decision 31).
	integrity *app.AuditIntegrity
	tokens    *app.EnrollmentTokens
	devices   *app.Devices
	managed   *app.ManagedConfig
	releases  *app.AgentReleases
	// imports is the agent release import from the release source (ADR 0043).
	imports *app.ReleaseImports
	// exports are the evidence exports of the audit log (plan M10 decision 29).
	exports *app.AuditExports
	// API tokens and the declarative configuration (plan M6c).
	apiTokens   *app.APITokens
	declarative *app.Declarative
	// sessions ends every portal session (plan M8s decision 16).
	sessions *app.Sessions
	// autoUnseal is the automatic unseal of OpenBao (plan M8u decision 7).
	autoUnseal *app.AutoUnseal

	users         *app.Users
	userGroups    *app.UserGroups
	logins        *app.Logins
	loginSettings *app.LoginSettings
	loginHistory  *app.LoginHistory
	agentUpdates  *app.AgentUpdates
	uninstalls    *app.Uninstalls
	conversions   *app.DiskConversions
	privileges    *app.Privileges

	commands    *app.DeviceCommands
	localAdmin  *app.LocalAdmin
	autoinstall *app.Autoinstall
	disk        *app.Disk
	revocations *app.Revocations
	dms         *app.DMS
	inventory   *app.Inventory
	updates     *app.Updates
	privacy     *app.Privacy
	readAudit   *app.ReadAudit
	attention   *app.Attention
	ipAllowlist *app.IPAllowlist
	overview    *app.Overview
	// securityReview is the review of existing data (ADR 0034 decision 7).
	securityReview *app.SecurityReview
	// mcpSettings are the MCP policies of the organizations and the platform (plan M14 §3.4 item 17).
	mcpSettings *app.MCPSettings
	mcpAccess   *app.MCPAccessService

	now func() time.Time
	// stepUpTiming is exposed in GET /api/v1/me in development only (nil otherwise).
	stepUpTiming *stepUpTiming
	// stepUpWindow is how long a step-up satisfies a privileged action (step_up_valid_until of GET /api/v1/me).
	stepUpWindow time.Duration
	// serverVersion is server_version of GET and PATCH /api/v1/me.
	serverVersion string
}

// stepUpTiming is the step-up window of the action runner and the maximum auth age of the step-up callback.
type stepUpTiming struct{ window, maxAuthAge time.Duration }

// stepUpClassesKey carries the session's step-up authenticator classes to GET /api/v1/me (development only).
type stepUpClassesKey struct{}

// alternateRoleKey carries the session's alternate role (ADR 0045) to GET and PATCH /api/v1/me; only the session
// middleware sets it, so API tokens and every other principal answer null.
type alternateRoleKey struct{}

// alternateRole is the value under alternateRoleKey: the role and, for an organization role, the slug.
type alternateRole struct{ role, slug string }

// alternateRole is the alternate_role of GET and PATCH /api/v1/me; nil without one.
func (h *handlers) alternateRole(ctx context.Context) *adminapi.MeAlternateRole {
	alt, ok := ctx.Value(alternateRoleKey{}).(alternateRole)
	if !ok || alt.role == "" {
		return nil
	}
	out := &adminapi.MeAlternateRole{Role: adminapi.MeAlternateRoleRole(alt.role)}
	if alt.slug != "" {
		out.OrganizationSlug = &alt.slug
	}
	return out
}

// roleFallbackKey carries the session's sign-in fallback (ADR 0045 amendment 2026-10-29) to GET and PATCH /api/v1/me.
type roleFallbackKey struct{}

// roleFallback is the role_fallback of GET and PATCH /api/v1/me; nil without one.
func roleFallback(ctx context.Context) *adminapi.MeRoleFallback {
	f, ok := ctx.Value(roleFallbackKey{}).(string)
	if !ok || f == "" {
		return nil
	}
	out := adminapi.MeRoleFallback(f)
	return &out
}

var _ adminapi.StrictServerInterface = (*handlers)(nil)

func (h *handlers) GetMe(ctx context.Context, _ adminapi.GetMeRequestObject) (adminapi.GetMeResponseObject, error) {
	me, err := h.accounts.GetMe(ctx)
	if err != nil {
		return nil, err
	}
	out := h.toMe(me)
	p, _ := principal.From(ctx)
	out.Channel = meChannel(p)
	out.ClientIp = p.IP
	out.StepUpValidUntil = h.stepUpValidUntil(p)
	out.AlternateRole = h.alternateRole(ctx)
	out.RoleFallback = roleFallback(ctx)
	if h.stepUpTiming != nil {
		out.StepUp = &adminapi.MeStepUp{
			WindowSeconds:     int(h.stepUpTiming.window.Seconds()),
			MaxAuthAgeSeconds: int(h.stepUpTiming.maxAuthAge.Seconds()),
		}
		if !p.StepUpAt.IsZero() {
			at := p.StepUpAt.UTC()
			out.StepUp.At = &at
			if classes, ok := ctx.Value(stepUpClassesKey{}).([]string); ok {
				out.StepUp.MfaClasses = &classes
			}
		}
	}
	return adminapi.GetMe200JSONResponse(out), nil
}

func (h *handlers) UpdateMe(ctx context.Context, req adminapi.UpdateMeRequestObject) (adminapi.UpdateMeResponseObject, error) {
	var settings app.AccountSettings
	if req.Body.Locale != nil {
		settings.Locale = (*string)(req.Body.Locale)
	}
	if req.Body.Theme != nil {
		settings.Theme = (*string)(req.Body.Theme)
	}
	me, err := h.accounts.UpdateSettings(ctx, settings)
	if err != nil {
		return nil, err
	}
	out := h.toMe(me)
	// The portal replaces its session with this answer; without the address the IP allow list page would lose it.
	p, _ := principal.From(ctx)
	out.Channel = meChannel(p)
	out.ClientIp = p.IP
	out.StepUpValidUntil = h.stepUpValidUntil(p)
	out.AlternateRole = h.alternateRole(ctx)
	out.RoleFallback = roleFallback(ctx)
	return adminapi.UpdateMe200JSONResponse(out), nil
}

// meChannel is Me.channel: how the request authenticated (ADR 0044).
func meChannel(p principal.Principal) adminapi.MeChannel {
	switch {
	case p.Channel == principal.ChannelMCP:
		return adminapi.MeChannel(principal.ChannelMCP)
	case p.APITokenID != uuid.Nil:
		return "api"
	default:
		return "portal"
	}
}

// stepUpValidUntil is the end of the principal's step-up window, nil without a step-up or once the window has passed.
func (h *handlers) stepUpValidUntil(p principal.Principal) *time.Time {
	if p.StepUpAt.IsZero() {
		return nil
	}
	until := p.StepUpAt.Add(h.stepUpWindow).UTC()
	if !until.After(h.now()) {
		return nil
	}
	return &until
}

func (h *handlers) toMe(me app.Me) adminapi.Me {
	out := adminapi.Me{
		Id: me.ID, Username: me.Username, DisplayName: me.DisplayName, Role: adminapi.MeRole(me.Role),
		Locale: adminapi.MeLocale(me.Locale), Theme: adminapi.MeTheme(me.Theme), RevocationEnabled: h.revocations.Enabled(),
		ServerVersion: h.serverVersion, McpWriteEnabled: me.MCPWriteEnabled,
	}
	if me.Organization != nil {
		domains := me.Organization.Domains
		if domains == nil {
			domains = []string{}
		}
		out.Organization = &adminapi.MeOrganization{Id: me.Organization.ID, Slug: me.Organization.Slug, Name: me.Organization.Name,
			Domains: domains}
	}
	if me.MCPWriteEnabledAt != nil {
		at := me.MCPWriteEnabledAt.UTC()
		out.McpWriteEnabledAt = &at
	}
	if me.APIToken != nil {
		out.ApiToken = &adminapi.MeApiToken{Id: me.APIToken.ID, Name: me.APIToken.Name, ExpiresAt: me.APIToken.ExpiresAt.UTC()}
	}
	return out
}

// List definitions of the collection endpoints; TestListSpecsMatchContract keeps them equal to x-paddock-list.
var (
	deviceGroupList  = listing.Spec{Sort: []string{"name", "created_at", "updated_at"}, DefaultSort: "name"}
	auditEventList   = listing.Spec{Sort: []string{"occurred_at", "code", "outcome"}, DefaultSort: "-occurred_at"}
	organizationList = listing.Spec{Sort: []string{"slug", "name", "created_at", "status"}, DefaultSort: "slug"}
)

func (h *handlers) ListDeviceGroups(ctx context.Context, req adminapi.ListDeviceGroupsRequestObject) (adminapi.ListDeviceGroupsResponseObject, error) {
	params, err := listing.Parse(deviceGroupList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	res, err := h.groups.List(ctx, params.ListPage())
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.DeviceGroup, len(res.Items))
	for i, g := range res.Items {
		items[i] = toDeviceGroup(g)
	}
	return adminapi.ListDeviceGroups200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func (h *handlers) CreateDeviceGroup(ctx context.Context, req adminapi.CreateDeviceGroupRequestObject) (adminapi.CreateDeviceGroupResponseObject, error) {
	policy := app.DeviceGroupPolicy{
		AgentUpdatePolicy: (*string)(req.Body.AgentUpdatePolicy), DiskUnlockMode: (*string)(req.Body.DiskUnlockMode),
	}
	if s := req.Body.Staleness; s != nil {
		policy.Staleness = &app.GroupStaleness{WarningH: s.WarningH, CriticalH: s.CriticalH}
	}
	g, err := h.groups.Create(ctx, req.Body.Name, req.Body.Description, policy)
	if err != nil {
		return nil, err
	}
	loc := "/api/v1/device-groups/" + g.ID.String()
	return adminapi.CreateDeviceGroup201JSONResponse{
		Body: toDeviceGroup(g), Headers: adminapi.CreateDeviceGroup201ResponseHeaders{Location: &loc},
	}, nil
}

func (h *handlers) GetDeviceGroup(ctx context.Context, req adminapi.GetDeviceGroupRequestObject) (adminapi.GetDeviceGroupResponseObject, error) {
	g, err := h.groups.Get(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.GetDeviceGroup200JSONResponse(toDeviceGroup(g)), nil
}

func (h *handlers) UpdateDeviceGroup(ctx context.Context, req adminapi.UpdateDeviceGroupRequestObject) (adminapi.UpdateDeviceGroupResponseObject, error) {
	var patch app.DeviceGroupPolicyPatch
	var err error
	if patch.Staleness, err = rawChange[app.GroupStaleness]("staleness", req.Body.Staleness); err != nil {
		return nil, err
	}
	if patch.AgentUpdatePolicy, err = rawChange[string]("agent_update_policy", req.Body.AgentUpdatePolicy); err != nil {
		return nil, err
	}
	if patch.DiskUnlockMode, err = rawChange[string]("disk_unlock_mode", req.Body.DiskUnlockMode); err != nil {
		return nil, err
	}
	g, err := h.groups.Update(ctx, req.Id, req.Body.Name, req.Body.Description, patch)
	if err != nil {
		return nil, err
	}
	return adminapi.UpdateDeviceGroup200JSONResponse(toDeviceGroup(g)), nil
}

func (h *handlers) DeleteDeviceGroup(ctx context.Context, req adminapi.DeleteDeviceGroupRequestObject) (adminapi.DeleteDeviceGroupResponseObject, error) {
	if err := h.groups.Delete(ctx, req.Id); err != nil {
		return nil, err
	}
	return adminapi.DeleteDeviceGroup204Response{}, nil
}

// rawChange decodes a field of a partial update whose null differs from its absence: absent keeps the value, null
// clears it (plan M8d decision 11).
func rawChange[T any](field string, raw json.RawMessage) (app.Change[T], error) {
	if len(raw) == 0 {
		return app.Change[T]{}, nil
	}
	if string(raw) == "null" {
		return app.Change[T]{Set: true}, nil
	}
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		return app.Change[T]{}, problem.InvalidRequest.WithDetail(field + " is malformed")
	}
	return app.Change[T]{Set: true, Value: &v}, nil
}

func toDeviceGroup(g pgstore.DeviceGroup) adminapi.DeviceGroup {
	out := adminapi.DeviceGroup{Id: g.ID, Name: g.Name, Description: g.Description, CreatedAt: g.CreatedAt.UTC(), UpdatedAt: g.UpdatedAt.UTC(),
		AgentUpdatePolicy: (*adminapi.AgentUpdatePolicy)(g.AgentUpdatePolicy), DiskUnlockMode: (*adminapi.DiskUnlockMode)(g.DiskUnlockMode)}
	if p := app.PolicyOf(g).Staleness; p != nil {
		out.Staleness = &adminapi.DeviceGroupStaleness{WarningH: p.WarningH, CriticalH: p.CriticalH}
	}
	return out
}

func (h *handlers) ListAuditEvents(ctx context.Context, req adminapi.ListAuditEventsRequestObject) (adminapi.ListAuditEventsResponseObject, error) {
	params, err := listing.Parse(auditEventList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	outcomes, err := listing.Enum("outcome", req.Params.Outcome)
	if err != nil {
		return nil, err
	}
	actorTypes, err := listing.Enum("actor_type", req.Params.ActorType)
	if err != nil {
		return nil, err
	}
	query := app.AuditQuery{
		From: req.Params.From, To: req.Params.To, Codes: listing.Strings(req.Params.Code), Outcomes: outcomes,
		ActorTypes: actorTypes, TargetID: req.Params.TargetId, Page: params.ListPage(),
	}
	if _, err := h.readAudit.AuditSearched(ctx, query); err != nil {
		return nil, err
	}
	res, err := h.audit.List(ctx, query)
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.AuditEvent, len(res.Items))
	for i, e := range res.Items {
		if items[i], err = toAuditEvent(e); err != nil {
			return nil, err
		}
		if d, ok := res.Devices[e.EventID]; ok {
			items[i].Device = &adminapi.AuditDeviceRef{Id: d.ID, Hostname: d.Hostname}
		}
	}
	return adminapi.ListAuditEvents200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

// toAuditEvent maps an index row to the API. The writer keeps error_code inside params in the index (there is no
// column for it); it is presented in its own field again.
func toAuditEvent(e auditstore.AuditEvent) (adminapi.AuditEvent, error) {
	out := adminapi.AuditEvent{
		EventId: e.EventID, OccurredAt: e.OccurredAt.UTC(), RecordedAt: e.RecordedAt.UTC(), Code: e.Code,
		Outcome: adminapi.AuditOutcome(e.Outcome), Source: e.Source, CorrelationId: e.CorrelationID,
		Params: map[string]any{},
	}
	if err := json.Unmarshal(e.Actor, &out.Actor); err != nil {
		return out, err
	}
	if len(e.Target) > 0 && string(e.Target) != "null" {
		out.Target = &adminapi.AuditTarget{}
		if err := json.Unmarshal(e.Target, out.Target); err != nil {
			return out, err
		}
	}
	if err := json.Unmarshal(e.Params, &out.Params); err != nil {
		return out, err
	}
	if code, ok := out.Params["error_code"].(string); ok {
		out.ErrorCode = &code
		delete(out.Params, "error_code")
	}
	return out, nil
}

func (h *handlers) ListOrganizations(ctx context.Context, req adminapi.ListOrganizationsRequestObject) (adminapi.ListOrganizationsResponseObject, error) {
	params, err := listing.Parse(organizationList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	statuses, err := listing.Enum("status", req.Params.Status)
	if err != nil {
		return nil, err
	}
	res, err := h.orgs.List(ctx, params.ListPage(), statuses)
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.Organization, len(res.Items))
	for i, o := range res.Items {
		items[i] = toOrganization(o)
	}
	return adminapi.ListOrganizations200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func (h *handlers) CreateOrganization(ctx context.Context, req adminapi.CreateOrganizationRequestObject) (adminapi.CreateOrganizationResponseObject, error) {
	org, reprovisioned, err := h.orgs.Create(ctx, req.Body.Slug, req.Body.Name)
	if err != nil {
		return nil, err
	}
	if reprovisioned {
		return adminapi.CreateOrganization200JSONResponse(toOrganization(org)), nil
	}
	loc := "/api/platform/v1/organizations/" + org.ID.String()
	return adminapi.CreateOrganization201JSONResponse{
		Body: toOrganization(org), Headers: adminapi.CreateOrganization201ResponseHeaders{Location: &loc},
	}, nil
}

func (h *handlers) GetOrganization(ctx context.Context, req adminapi.GetOrganizationRequestObject) (adminapi.GetOrganizationResponseObject, error) {
	org, err := h.orgs.Get(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.GetOrganization200JSONResponse(toOrganization(org)), nil
}

func toOrganization(o pgstore.Organization) adminapi.Organization {
	return adminapi.Organization{
		Id: openapi_types.UUID(o.ID), Slug: o.Slug, Name: o.Name, Status: adminapi.OrganizationStatus(o.Status),
		Domains: o.Domains, CreatedAt: o.CreatedAt.UTC(),
	}
}
