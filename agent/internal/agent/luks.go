package agent

import (
	"context"

	"github.com/phischl/paddock-mdm/agent/internal/health"
)

// tickLUKS advances the disk encryption (plan M4b decisions 8–12) and puts its state into the health report: full
// inventories the volume (drift pass, check-in), otherwise only a pending escrow is polled.
func (a *Agent) tickLUKS(ctx context.Context, full bool) {
	if a.luks == nil || a.st.DeviceID == "" {
		return
	}
	disk := a.luks.Tick(ctx, a.bundleKeys(), full)
	if disk != nil {
		a.d.Health.Update(func(r *health.Report) { r.Disk = disk })
	}
}
