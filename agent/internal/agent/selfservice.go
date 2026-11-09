package agent

import (
	"context"

	"github.com/phischl/paddock-mdm/agent/internal/selfservice"
)

// refreshSelfService hands the self-service the applied bundle after every apply and drift pass (plan M13b decisions
// 11 and 14), with the credentials its icon cache fetches with.
func (a *Agent) refreshSelfService() {
	if a.d.SelfService == nil {
		return
	}
	var fetch selfservice.IconFetch
	if c := a.d.Client; c != nil && a.st.DeviceID != "" {
		device, seq := a.st.DeviceID, a.st.Seq
		fetch = func(ctx context.Context, entryID string) ([]byte, error) {
			return c.CatalogIcon(ctx, device, seq, entryID)
		}
	}
	a.d.SelfService.SetBundle(a.current, fetch)
}
