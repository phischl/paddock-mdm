package acceptance

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// TestInventoryF0FleetNotPublic is gate F0 of plan M5a (AC2): from outside, Fleet's UI, admin API and file carving
// answer 404 under fleet.<domain>, while the device endpoints of osquery and fleetd reach Fleet; a production
// deployment publishes no Fleet port, MySQL and Redis are on an internal network; paddock-worker keeps Fleet's data
// minimization settings (plan M5a decision 2).
func TestInventoryF0FleetNotPublic(t *testing.T) {
	ctx := testContext(t, 3*time.Minute)
	client, err := env.NewHTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	status := func(method, path string) int {
		t.Helper()
		res, err := env.Call(ctx, client, method, stack.FleetURL()+path, map[string]any{}, false)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		return res.Status
	}
	t.Run("not public", func(t *testing.T) {
		for _, c := range []struct{ method, path string }{
			{http.MethodGet, "/"},
			{http.MethodGet, "/login"},
			{http.MethodGet, "/dashboard"},
			{http.MethodGet, "/api/latest/fleet/version"},
			{http.MethodGet, "/api/v1/fleet/hosts"},
			{http.MethodPatch, "/api/latest/fleet/config"},
			{http.MethodPost, "/api/v1/fleet/login"},
			{http.MethodPost, "/api/v1/setup"},
			{http.MethodGet, "/healthz"},
			{http.MethodPost, "/api/v1/osquery/carve/begin"},
			{http.MethodPost, "/api/osquery/carve/block"},
		} {
			if got := status(c.method, c.path); got != http.StatusNotFound {
				t.Errorf("%s %s: HTTP %d, want 404", c.method, c.path, got)
			}
		}
	})
	t.Run("device paths", func(t *testing.T) {
		// An unknown enroll secret or node key is refused by Fleet itself (401), not by the proxy.
		for _, path := range []string{"/api/v1/osquery/enroll", "/api/osquery/enroll", "/api/v1/osquery/config",
			"/api/fleet/orbit/enroll", "/api/fleet/orbit/config"} {
			if got := status(http.MethodPost, path); got != http.StatusUnauthorized {
				t.Errorf("POST %s: HTTP %d, want 401 from Fleet", path, got)
			}
		}
		if got := status(http.MethodHead, "/api/fleet/orbit/ping"); got != http.StatusOK {
			t.Errorf("HEAD /api/fleet/orbit/ping: HTTP %d, want 200", got)
		}
	})
	t.Run("production compose", func(t *testing.T) {
		out, err := stack.ComposeProduction(ctx, nil, "config", "--format", "json")
		if err != nil {
			t.Fatal(err)
		}
		var cfg struct {
			Services map[string]struct {
				Networks map[string]any `json:"networks"`
				Ports    []any          `json:"ports"`
			} `json:"services"`
			Networks map[string]struct {
				Internal bool `json:"internal"`
			} `json:"networks"`
		}
		if err := json.Unmarshal([]byte(out), &cfg); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"fleet", "fleet-mysql", "fleet-redis"} {
			if svc, ok := cfg.Services[name]; !ok || len(svc.Ports) != 0 {
				t.Errorf("%s: present %v, ports %v", name, ok, svc.Ports)
			}
		}
		for _, name := range []string{"fleet-mysql", "fleet-redis"} {
			nets := cfg.Services[name].Networks
			if _, on := nets["fleet"]; len(nets) != 1 || !on {
				t.Errorf("%s on networks %v, want fleet only", name, nets)
			}
		}
		if !cfg.Networks["fleet"].Internal {
			t.Error("network fleet is not internal")
		}
	})
	t.Run("settings", func(t *testing.T) {
		dir, err := stack.SecretsDir()
		if err != nil {
			t.Fatal(err)
		}
		token, err := os.ReadFile(filepath.Join(dir, "fleet_api_token"))
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, stack.FleetAdminURL()+"/api/latest/fleet/config", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var cfg struct {
			ServerSettings map[string]any `json:"server_settings"`
			Features       struct {
				EnableHostUsers      bool               `json:"enable_host_users"`
				DetailQueryOverrides map[string]*string `json:"detail_query_overrides"`
			} `json:"features"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
			t.Fatalf("HTTP %d: %v", resp.StatusCode, err)
		}
		for key, want := range map[string]any{"enable_analytics": false, "live_query_disabled": true, "scripts_disabled": true} {
			if cfg.ServerSettings[key] != want {
				t.Errorf("server_settings.%s = %v, want %v", key, cfg.ServerSettings[key], want)
			}
		}
		if cfg.Features.EnableHostUsers {
			t.Error("Fleet collects host users")
		}
		if q, ok := cfg.Features.DetailQueryOverrides["software_deb_last_opened_at"]; !ok || q != nil {
			t.Errorf("last-use times of packages are collected: %v", cfg.Features.DetailQueryOverrides)
		}
	})
}
