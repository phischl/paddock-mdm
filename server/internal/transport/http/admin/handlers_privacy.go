package admin

import (
	"context"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

func (h *handlers) GetPrivacySettings(ctx context.Context, _ adminapi.GetPrivacySettingsRequestObject) (adminapi.GetPrivacySettingsResponseObject, error) {
	s, err := h.privacy.Get(ctx)
	if err != nil {
		return nil, err
	}
	return adminapi.GetPrivacySettings200JSONResponse(toPrivacySettings(s)), nil
}

func (h *handlers) UpdatePrivacySettings(ctx context.Context, req adminapi.UpdatePrivacySettingsRequestObject) (adminapi.UpdatePrivacySettingsResponseObject, error) {
	b := req.Body
	s, err := h.privacy.Update(ctx, app.PrivacySettings{
		RetiredInventoryDays: b.RetiredInventoryDays, AuditSearchRecorded: b.AuditSearchRecorded,
		InventoryViewRecorded: b.InventoryViewRecorded,
	})
	if err != nil {
		return nil, err
	}
	return adminapi.UpdatePrivacySettings200JSONResponse(toPrivacySettings(s)), nil
}

func toPrivacySettings(s app.PrivacySettings) adminapi.PrivacySettings {
	return adminapi.PrivacySettings{
		RetiredInventoryDays: s.RetiredInventoryDays, AuditSearchRecorded: s.AuditSearchRecorded,
		InventoryViewRecorded: s.InventoryViewRecorded, UpdatedAt: s.UpdatedAt.UTC(),
	}
}
