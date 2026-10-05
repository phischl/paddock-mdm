package authentik

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
)

// Flows of the blueprints paddock-recovery.yaml and paddock-device.yaml that the default brand must use (plan M3.1
// decision 5): recovery links of new local users open the brand's recovery flow (without one Authentik answers 502
// "No recovery flow set"), and /device runs the brand's device-code flow.
const (
	recoveryFlow   = "paddock-recovery"
	deviceCodeFlow = "paddock-device-code"
)

type brand struct {
	UUID           string `json:"brand_uuid"`
	FlowRecovery   string `json:"flow_recovery"`
	FlowDeviceCode string `json:"flow_device_code"`
}

// EnsureBrandFlows sets the recovery and device-code flows of Authentik's default brand to Paddock's if they differ.
// It fails while a flow is missing, e.g. before Authentik has applied the blueprints.
func (c *Client) EnsureBrandFlows(ctx context.Context) error {
	recovery, err := c.blueprintFlow(ctx, recoveryFlow, "paddock-recovery.yaml")
	if err != nil {
		return err
	}
	deviceCode, err := c.blueprintFlow(ctx, deviceCodeFlow, "paddock-device.yaml")
	if err != nil {
		return err
	}
	var page struct {
		Results []brand `json:"results"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v3/core/brands/?"+url.Values{"default": {"true"}}.Encode(), nil, &page); err != nil {
		return upstream(err)
	}
	if len(page.Results) != 1 {
		return upstream(fmt.Errorf("authentik: %d default brands, want 1", len(page.Results)))
	}
	b := page.Results[0]
	if b.FlowRecovery == recovery && b.FlowDeviceCode == deviceCode {
		return nil
	}
	patch := map[string]string{"flow_recovery": recovery, "flow_device_code": deviceCode}
	if err := c.do(ctx, http.MethodPatch, "/api/v3/core/brands/"+url.PathEscape(b.UUID)+"/", patch, nil); err != nil {
		return upstream(err)
	}
	slog.InfoContext(ctx, "default brand flows set", "flow_recovery", recoveryFlow, "flow_device_code", deviceCodeFlow)
	return nil
}

func (c *Client) blueprintFlow(ctx context.Context, slug, blueprint string) (string, error) {
	pk, err := c.findOne(ctx, "/api/v3/flows/instances/", url.Values{"slug": {slug}})
	if err != nil {
		return "", err
	}
	if pk == "" {
		return "", upstream(fmt.Errorf("flow %s missing (blueprint %s not applied)", slug, blueprint))
	}
	return pk, nil
}
