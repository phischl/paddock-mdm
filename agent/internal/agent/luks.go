package agent

import (
	"context"

	"github.com/phischl/paddock-mdm/agent/internal/health"
	"github.com/phischl/paddock-mdm/agent/internal/luks"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
)

// luksReconciler is the luks reconciler of the root volume on the agent's state.
func (a *Agent) luksReconciler() *reconcile.LUKS {
	d := a.d
	return &reconcile.LUKS{Tools: d.LUKS, Layout: d.Layout, Escrow: escrowClient{a}, State: &a.st.LUKS, Save: a.persist,
		Emit: a.event, Now: d.Now, TPM2Present: func() bool { return luks.TPM2Present(d.Layout.Root) }, Encrypt: d.Encrypt,
		CleanupPending:   func() bool { return a.st.Conversion != nil && a.st.Conversion.CleanupPending },
		ConversionHold:   func() bool { return a.st.Conversion != nil && !a.st.Conversion.InitrdRegenerated },
		ConversionHealth: a.conversionHealth}
}

// tickLUKS advances the disk encryption (plan M4b decisions 8–12) and puts its state into the health report: full
// inventories the volume (drift pass, check-in), otherwise only a pending escrow is polled.
func (a *Agent) tickLUKS(ctx context.Context, full bool) {
	if a.luks == nil || a.st.DeviceID == "" {
		return
	}
	mode := ""
	if a.current != nil && a.current.Disk != nil {
		mode = a.current.Disk.UnlockMode
	}
	disk := a.luks.Tick(ctx, a.bundleKeys(), full, mode)
	if disk != nil {
		a.d.Health.Update(func(r *health.Report) { r.Disk = disk })
	}
}
