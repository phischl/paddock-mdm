package admin

import (
	"context"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/configrollout"
	"github.com/phischl/paddock-mdm/server/internal/problem"
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
	// The use case reads zero as "keep the stored value", so a value sent as zero is refused here.
	if (b.WaveSuccessThresholdPercent != nil && *b.WaveSuccessThresholdPercent == 0) || (b.StallWarningHours != nil && *b.StallWarningHours == 0) {
		return nil, problem.InvalidRequest.WithDetail("wave_success_threshold_percent and stall_warning_hours must be at least 1")
	}
	s, err := h.rolloutSettings.Update(ctx, app.RolloutConfig{
		Settings: configrollout.Settings{
			Enabled: b.Enabled, Waves: b.Waves, MinWaveMinutes: b.MinWaveMinutes,
			FailureThresholdPercent: b.FailureThresholdPercent, FailureThresholdMin: b.FailureThresholdMin,
			WaveSuccessThresholdPercent: deref(b.WaveSuccessThresholdPercent, 0), StallWarningHours: deref(b.StallWarningHours, 0),
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
		WaveSuccessThresholdPercent: new(s.WaveSuccessThresholdPercent), StallWarningHours: new(s.StallWarningHours),
	}
}
