package admin

import (
	"context"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/autounseal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

func (h *handlers) GetAutoUnseal(ctx context.Context, _ adminapi.GetAutoUnsealRequestObject) (adminapi.GetAutoUnsealResponseObject, error) {
	st, err := h.autoUnseal.Status(ctx)
	if err != nil {
		return nil, err
	}
	return adminapi.GetAutoUnseal200JSONResponse(h.autoUnsealStatus(st)), nil
}

func (h *handlers) EnableAutoUnseal(ctx context.Context, req adminapi.EnableAutoUnsealRequestObject) (adminapi.EnableAutoUnsealResponseObject, error) {
	st, err := h.autoUnseal.Enable(ctx, req.Body.DisclaimerVersion, req.Body.Acknowledgement)
	if err != nil {
		return nil, err
	}
	return adminapi.EnableAutoUnseal200JSONResponse(h.autoUnsealStatus(st)), nil
}

func (h *handlers) DisableAutoUnseal(ctx context.Context, _ adminapi.DisableAutoUnsealRequestObject) (adminapi.DisableAutoUnsealResponseObject, error) {
	st, err := h.autoUnseal.Disable(ctx)
	if err != nil {
		return nil, err
	}
	return adminapi.DisableAutoUnseal200JSONResponse(h.autoUnsealStatus(st)), nil
}

func (h *handlers) autoUnsealStatus(st app.AutoUnsealStatus) adminapi.AutoUnsealStatus {
	s, r := st.Setting, st.Setting.Report
	out := adminapi.AutoUnsealStatus{
		State:                  adminapi.AutoUnsealStatusState(s.State),
		DisclaimerVersion:      autounseal.DisclaimerVersion,
		AcknowledgementVersion: optString(s.DisclaimerVersion),
		Acknowledgement:        optString(s.Acknowledgement),
		AcknowledgedBy:         optString(s.AcknowledgedBy),
		AcknowledgedAt:         optTime(s.AcknowledgedAt),
		DisabledBy:             optString(s.DisabledBy),
		DisabledAt:             optTime(s.DisabledAt),
		Unsealer: adminapi.UnsealerReport{
			Running:       r.UnsealerRunning(h.now()),
			SeenAt:        optTime(r.SeenAt),
			SharesPresent: r.SharesOnHost(h.now()),
			UnsealCount:   r.UnsealCount,
			LastUnsealAt:  optTime(r.LastUnsealAt),
			FailureCount:  r.FailureCount,
			LastFailureAt: optTime(r.LastFailureAt),
		},
		Seal: adminapi.SealStatus{
			Reachable: st.Seal.Reachable, Initialized: st.Seal.Initialized, Sealed: st.Seal.Sealed, Type: st.Seal.Type,
			Threshold: st.Seal.Threshold, Shares: st.Seal.Shares,
		},
	}
	if r.LastFailureReason != "" {
		reason := adminapi.UnsealerReportLastFailureReason(r.LastFailureReason)
		out.Unsealer.LastFailureReason = &reason
	}
	return out
}

func optString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func optTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}
