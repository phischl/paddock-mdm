package admin

import (
	"context"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

func (h *handlers) GetUpgradeCheck(ctx context.Context, req adminapi.GetUpgradeCheckRequestObject) (adminapi.GetUpgradeCheckResponseObject, error) {
	// Optional in the contract so that the generated binder does not answer 400 before Report's platform check; an
	// empty version is no known release and ends in 400 after it.
	target := ""
	if req.Params.TargetVersion != nil {
		target = *req.Params.TargetVersion
	}
	r, err := h.upgradeCheck.Report(ctx, target)
	if err != nil {
		return nil, err
	}
	return adminapi.GetUpgradeCheck200JSONResponse(UpgradeCheckDocument(r)), nil
}

// UpgradeCheckDocument is the report as the API returns it; paddock-server admin upgrade-check --json prints the same.
func UpgradeCheckDocument(r app.UpgradeCheckReport) adminapi.UpgradeCheck {
	out := adminapi.UpgradeCheck{
		GeneratedAt: r.GeneratedAt, TargetVersion: r.TargetVersion, Window: r.Window,
		Items:         make([]adminapi.UpgradeCheckItem, len(r.Items)),
		AgentsOutside: make([]adminapi.UpgradeCheckAgent, len(r.AgentsOutside)),
	}
	for i, it := range r.Items {
		out.Items[i] = adminapi.UpgradeCheckItem{Name: adminapi.UpgradeCheckItemName(it.Name), Status: adminapi.UpgradeCheckItemStatus(it.Status), Detail: it.Detail}
	}
	for i, a := range r.AgentsOutside {
		out.AgentsOutside[i] = adminapi.UpgradeCheckAgent{DeviceId: a.DeviceID, Hostname: a.Hostname, AgentVersion: a.AgentVersion}
	}
	return out
}
