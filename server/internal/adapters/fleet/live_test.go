package fleet_test

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/adapters/fleet"
	"github.com/phischl/paddock-mdm/server/internal/inventory"
)

// TestLiveFleet runs the adapter against a real Fleet (the development stack, whose Fleet UI port is published on
// 127.0.0.1:8412) with the token of the API-only user paddock. It is opt-in:
//
//	PADDOCK_FLEET_LIVE_URL=http://127.0.0.1:8412 \
//	PADDOCK_FLEET_LIVE_TOKEN_FILE=deploy/compose/.secrets/fleet_api_token go test -run TestLiveFleet ./internal/adapters/fleet/
//
// It changes Fleet's settings (and corrects them again), creates and removes a scheduled query, applies Paddock's
// policies and reads every host's inventory.
func TestLiveFleet(t *testing.T) {
	base := os.Getenv("PADDOCK_FLEET_LIVE_URL")
	if base == "" {
		t.Skip("PADDOCK_FLEET_LIVE_URL is not set (opt-in test against a running Fleet)")
	}
	ctx := context.Background()
	c := fleet.New(base, readToken(t), "https://fleet.paddock.localhost:8443")
	if _, err := c.EnsureSettings(ctx); err != nil {
		t.Fatal(err)
	}
	if corrected, err := c.EnsureSettings(ctx); err != nil || len(corrected) != 0 {
		t.Fatalf("second round corrected %v, %v", corrected, err)
	}
	drift(ctx, t)
	corrected, err := c.EnsureSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"server_settings", "features", "webhook_settings", "query paddock-live-test"}
	if strings.Join(corrected, ",") != strings.Join(want, ",") {
		t.Fatalf("corrected %v, want %v", corrected, want)
	}
	if corrected, err := c.EnsureSettings(ctx); err != nil || len(corrected) != 0 {
		t.Fatalf("after the correction %v, %v", corrected, err)
	}

	policies, err := inventory.Policies()
	if err != nil {
		t.Fatal(err)
	}
	for range 2 { // idempotent
		if err := c.ApplyPolicies(ctx, policies); err != nil {
			t.Fatal(err)
		}
	}
	page, err := c.ListHostsChangedSince(ctx, time.Time{}, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range page.Hosts {
		inv, err := c.HostInventory(ctx, h.Ref)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("host %s %s: %s, agent %s, %d packages, policies %+v", h.Ref, h.HardwareUUID, inv.OSVersion, inv.AgentVersion,
			len(inv.Software), inv.Policies)
	}
}

// drift changes every enforced setting group and adds a scheduled query, as an operator in Fleet's UI could.
func drift(ctx context.Context, t *testing.T) {
	t.Helper()
	base, token := os.Getenv("PADDOCK_FLEET_LIVE_URL"), readToken(t)
	call(ctx, t, base, token, "PATCH", "/api/latest/fleet/config", `{"server_settings":{"enable_analytics":true},
		"features":{"enable_host_users":true,"detail_query_overrides":{"os_version":"SELECT 1;"}},
		"webhook_settings":{"activities_webhook":{"enable_activities_webhook":true,"destination_url":"https://example.invalid/hook"}}}`)
	call(ctx, t, base, token, "POST", "/api/latest/fleet/queries", `{"name":"paddock-live-test","query":"SELECT 1;","interval":600}`)
}

func readToken(t *testing.T) string {
	t.Helper()
	token, err := os.ReadFile(os.Getenv("PADDOCK_FLEET_LIVE_TOKEN_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(token))
}

func call(ctx context.Context, t *testing.T, base, token, method, path, body string) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, method, base+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, data)
	}
}
