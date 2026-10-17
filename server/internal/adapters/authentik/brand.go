package authentik

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
)

// Flows of the blueprints paddock-recovery.yaml, paddock-device.yaml and paddock-portal.yaml that the default brand
// must use (plan M3.1 decision 5, plan M8x decision 4): recovery links of new local users open the brand's recovery
// flow (without one Authentik answers 502 "No recovery flow set"), /device runs the brand's device-code flow, and
// every sign-in at Authentik's own interfaces runs Paddock's login flow with its second factor.
const (
	recoveryFlow       = "paddock-recovery"
	deviceCodeFlow     = "paddock-device-code"
	authenticationFlow = "paddock-admin-login"
)

type brand struct {
	UUID               string `json:"brand_uuid"`
	FlowRecovery       string `json:"flow_recovery"`
	FlowDeviceCode     string `json:"flow_device_code"`
	FlowAuthentication string `json:"flow_authentication"`
}

// EnsureBrandFlows sets the recovery, device-code and authentication flows of Authentik's default brand to Paddock's
// if they differ. It fails while a flow is missing, e.g. before Authentik has applied the blueprints.
func (c *Client) EnsureBrandFlows(ctx context.Context) error {
	recovery, err := c.blueprintFlow(ctx, recoveryFlow, "paddock-recovery.yaml")
	if err != nil {
		return err
	}
	deviceCode, err := c.blueprintFlow(ctx, deviceCodeFlow, "paddock-device.yaml")
	if err != nil {
		return err
	}
	authentication, err := c.blueprintFlow(ctx, authenticationFlow, "paddock-portal.yaml")
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
	if b.FlowRecovery == recovery && b.FlowDeviceCode == deviceCode && b.FlowAuthentication == authentication {
		return nil
	}
	patch := map[string]string{"flow_recovery": recovery, "flow_device_code": deviceCode, "flow_authentication": authentication}
	if err := c.do(ctx, http.MethodPatch, "/api/v3/core/brands/"+url.PathEscape(b.UUID)+"/", patch, nil); err != nil {
		return upstream(err)
	}
	slog.InfoContext(ctx, "default brand flows set", "flow_recovery", recoveryFlow, "flow_device_code", deviceCodeFlow,
		"flow_authentication", authenticationFlow)
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
