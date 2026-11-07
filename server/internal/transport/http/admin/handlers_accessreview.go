package admin

import (
	"bytes"
	"context"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

func reviewPeriod(from, to *time.Time) app.Period {
	var p app.Period
	if from != nil {
		p.From = *from
	}
	if to != nil {
		p.To = *to
	}
	return p
}

func mapItems[T, U any](in []T, f func(T) U) []U {
	out := make([]U, len(in))
	for i, v := range in {
		out[i] = f(v)
	}
	return out
}

func toAccessReviewRoles(roles []app.RoleMembers) []adminapi.AccessReviewRoleMembers {
	return mapItems(roles, func(r app.RoleMembers) adminapi.AccessReviewRoleMembers {
		return adminapi.AccessReviewRoleMembers{Role: r.Role, SnapshotTakenAt: r.SnapshotTakenAt, Total: r.Members.Total,
			Members: mapItems(r.Members.Items, func(m app.RoleMember) adminapi.AccessReviewRoleMember {
				return adminapi.AccessReviewRoleMember{Username: m.Username, AuthentikPk: m.AuthentikPK, FirstSeenAt: m.FirstSeenAt}
			})}
	})
}

func toAccessReviewRoleChanges(s app.Section[app.RoleChange]) adminapi.AccessReviewRoleChanges {
	return adminapi.AccessReviewRoleChanges{Total: s.Total, Items: mapItems(s.Items, func(c app.RoleChange) adminapi.AccessReviewRoleChange {
		return adminapi.AccessReviewRoleChange{At: c.At, Code: c.Code, Username: c.Username, Role: c.Role, Actor: c.Actor}
	})}
}

func toAccessReviewReport(r app.Report) adminapi.AccessReviewReport {
	return adminapi.AccessReviewReport{
		GeneratedAt: r.GeneratedAt, Period: adminapi.AccessReviewPeriod{From: r.Period.From, To: r.Period.To},
		RowCap: app.AccessReviewRowCap, Roles: toAccessReviewRoles(r.Roles), RoleChanges: toAccessReviewRoleChanges(r.RoleChanges),
		Accounts: adminapi.AccessReviewAccounts{Total: r.Accounts.Total, Items: mapItems(r.Accounts.Items, func(a app.ReviewAccount) adminapi.AccessReviewAccount {
			return adminapi.AccessReviewAccount{Username: a.Username, DisplayName: a.DisplayName, Role: a.Role, LastLoginAt: a.LastLoginAt, Disabled: a.Disabled}
		})},
		ApiTokens: adminapi.AccessReviewTokens{Total: r.APITokens.Total, Items: mapItems(r.APITokens.Items, func(t app.ReviewToken) adminapi.AccessReviewToken {
			return adminapi.AccessReviewToken{Name: t.Name, Role: t.Role, Prefix: t.Prefix, CreatedBy: t.CreatedBy, CreatedAt: t.CreatedAt,
				ExpiresAt: t.ExpiresAt, LastUsedAt: t.LastUsedAt, RevokedAt: t.RevokedAt, RevokedBy: t.RevokedBy}
		})},
		TokenDenials: r.TokenDenials,
		Reveals: adminapi.AccessReviewReveals{Total: r.Reveals.Total, Items: mapItems(r.Reveals.Items, func(v app.Reveal) adminapi.AccessReviewReveal {
			return adminapi.AccessReviewReveal{At: v.At, Code: v.Code, Actor: v.Actor, DeviceHostname: v.DeviceHostname, Params: v.Params}
		})},
		StepUp: adminapi.AccessReviewStepUp{Succeeded: r.StepUp.Succeeded, Failed: r.StepUp.Failed},
		SessionsRevoked: adminapi.AccessReviewSessionRevocations{Total: r.SessionsRevoked.Total, Items: mapItems(r.SessionsRevoked.Items,
			func(s app.SessionRevocation) adminapi.AccessReviewSessionRevocation {
				return adminapi.AccessReviewSessionRevocation{At: s.At, Username: s.Username, Reason: s.Reason}
			})},
		BreakGlassAccounts: r.BreakGlassAccounts,
		Destructive: adminapi.AccessReviewDestructiveActions{Total: r.Destructive.Total, Items: mapItems(r.Destructive.Items,
			func(d app.DestructiveAction) adminapi.AccessReviewDestructiveAction {
				return adminapi.AccessReviewDestructiveAction{At: d.At, Code: d.Code, Actor: d.Actor, Target: d.Target}
			})},
	}
}

func toPlatformAccessReviewReport(r app.PlatformReport) adminapi.PlatformAccessReviewReport {
	return adminapi.PlatformAccessReviewReport{
		GeneratedAt: r.GeneratedAt, Period: adminapi.AccessReviewPeriod{From: r.Period.From, To: r.Period.To},
		RowCap: app.AccessReviewRowCap, Roles: toAccessReviewRoles(r.Roles), RoleChanges: toAccessReviewRoleChanges(r.RoleChanges),
		Administrators: adminapi.AccessReviewPlatformAdministrators{Total: r.Administrators.Total, Items: mapItems(r.Administrators.Items,
			func(a app.PlatformAdministrator) adminapi.AccessReviewPlatformAdministrator {
				return adminapi.AccessReviewPlatformAdministrator{Username: a.Username, DisplayName: a.DisplayName, LastLoginAt: a.LastLoginAt}
			})},
		Events: adminapi.AccessReviewPlatformEvents{Total: r.Events.Total, Items: mapItems(r.Events.Items,
			func(e app.PlatformEvent) adminapi.AccessReviewPlatformEvent {
				return adminapi.AccessReviewPlatformEvent{At: e.At, Code: e.Code, Actor: e.Actor, Target: e.Target}
			})},
		OrganizationsCreated: adminapi.AccessReviewCreatedOrganizations{Total: r.OrganizationsCreated.Total, Items: mapItems(r.OrganizationsCreated.Items,
			func(o app.CreatedOrganization) adminapi.AccessReviewCreatedOrganization {
				return adminapi.AccessReviewCreatedOrganization{Slug: o.Slug, Name: o.Name, CreatedAt: o.CreatedAt}
			})},
	}
}

// attachment is the Content-Disposition of an export; the file name holds only characters that need no quoting.
func attachment(filename string) *string {
	v := `attachment; filename="` + filename + `"`
	return &v
}

func (h *handlers) GetAccessReview(ctx context.Context, req adminapi.GetAccessReviewRequestObject) (adminapi.GetAccessReviewResponseObject, error) {
	r, err := h.accessReview.Organization(ctx, reviewPeriod(req.Params.From, req.Params.To))
	if err != nil {
		return nil, err
	}
	return adminapi.GetAccessReview200JSONResponse(toAccessReviewReport(r)), nil
}

func (h *handlers) ExportAccessReview(ctx context.Context, req adminapi.ExportAccessReviewRequestObject) (adminapi.ExportAccessReviewResponseObject, error) {
	e, err := h.accessReview.ExportOrganization(ctx, reviewPeriod(req.Params.From, req.Params.To), string(req.Params.Format))
	if err != nil {
		return nil, err
	}
	headers := adminapi.ExportAccessReview200ResponseHeaders{ContentDisposition: attachment(e.Filename)}
	if e.Format == app.AccessReviewCSV {
		return adminapi.ExportAccessReview200TextcsvResponse{Body: bytes.NewReader(e.CSV), ContentLength: int64(len(e.CSV)), Headers: headers}, nil
	}
	return adminapi.ExportAccessReview200JSONResponse{Body: toAccessReviewReport(*e.Org), Headers: headers}, nil
}

func (h *handlers) GetPlatformAccessReview(ctx context.Context, req adminapi.GetPlatformAccessReviewRequestObject) (adminapi.GetPlatformAccessReviewResponseObject, error) {
	r, err := h.accessReview.Platform(ctx, reviewPeriod(req.Params.From, req.Params.To))
	if err != nil {
		return nil, err
	}
	return adminapi.GetPlatformAccessReview200JSONResponse(toPlatformAccessReviewReport(r)), nil
}

func (h *handlers) ExportPlatformAccessReview(ctx context.Context, req adminapi.ExportPlatformAccessReviewRequestObject) (adminapi.ExportPlatformAccessReviewResponseObject, error) {
	e, err := h.accessReview.ExportPlatform(ctx, reviewPeriod(req.Params.From, req.Params.To), string(req.Params.Format))
	if err != nil {
		return nil, err
	}
	headers := adminapi.ExportPlatformAccessReview200ResponseHeaders{ContentDisposition: attachment(e.Filename)}
	if e.Format == app.AccessReviewCSV {
		return adminapi.ExportPlatformAccessReview200TextcsvResponse{Body: bytes.NewReader(e.CSV), ContentLength: int64(len(e.CSV)), Headers: headers}, nil
	}
	return adminapi.ExportPlatformAccessReview200JSONResponse{Body: toPlatformAccessReviewReport(*e.Platform), Headers: headers}, nil
}
