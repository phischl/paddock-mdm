package admin

import (
	"context"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/configrollout"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

func (h *handlers) GetRolloutSettings(ctx context.Context, _ adminapi.GetRolloutSettingsRequestObject) (adminapi.GetRolloutSettingsResponseObject, error) {
	s, err := h.rolloutSettings.Get(ctx)
	if err != nil {
		return nil, err
	}
	return adminapi.GetRolloutSettings200JSONResponse(toRolloutSettings(s)), nil
}

func (h *handlers) UpdateRolloutSettings(ctx context.Context, req adminapi.UpdateRolloutSettingsRequestObject) (adminapi.UpdateRolloutSettingsResponseObject, error) {
	b := req.Body
	s, err := h.rolloutSettings.Update(ctx, app.RolloutConfig{
		Settings: configrollout.Settings{
			Enabled: b.Enabled, Waves: b.Waves, MinWaveMinutes: b.MinWaveMinutes,
			FailureThresholdPercent: b.FailureThresholdPercent, FailureThresholdMin: b.FailureThresholdMin,
		},
		CanaryDeviceGroupID: b.CanaryDeviceGroupId,
	})
	if err != nil {
		return nil, err
	}
	return adminapi.UpdateRolloutSettings200JSONResponse(toRolloutSettings(s)), nil
}

func toRolloutSettings(s app.RolloutConfig) adminapi.RolloutSettings {
	return adminapi.RolloutSettings{
		Enabled: s.Enabled, Waves: s.Waves, MinWaveMinutes: s.MinWaveMinutes,
		FailureThresholdPercent: s.FailureThresholdPercent, FailureThresholdMin: s.FailureThresholdMin,
		CanaryDeviceGroupId: s.CanaryDeviceGroupID, UpdatedAt: utcPtr(s.UpdatedAt),
	}
}
