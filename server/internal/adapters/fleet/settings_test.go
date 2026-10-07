package fleet_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/adapters/fleet"
)

func client(srv string) *fleet.Client {
	return fleet.New(srv, fakeToken, "https://fleet.example.org").WithBackoff(time.Millisecond)
}

// TestEnsureSettingsMinimizesAFreshFleet: a freshly set-up Fleet collects host users, sends usage statistics and
// allows live queries and scripts; one round applies Paddock's settings (plan M5a decision 2), the next finds no drift.
func TestEnsureSettingsMinimizesAFreshFleet(t *testing.T) {
	ctx := context.Background()
	f, srv := newFake(t)
	c := client(srv.URL)
	corrected, err := c.EnsureSettings(ctx)
	if err != nil || !slices.Equal(corrected, []string{"server_settings", "features"}) {
		t.Fatalf("corrected %v, %v", corrected, err)
	}
	server := f.section("server_settings")
	for key, want := range map[string]any{"server_url": "https://fleet.example.org", "enable_analytics": false,
		"live_query_disabled": true, "query_reports_disabled": true, "scripts_disabled": true, "ai_features_disabled": true} {
		if server[key] != want {
			t.Errorf("server_settings.%s = %v, want %v", key, server[key], want)
		}
	}
	features := f.section("features")
	if features["enable_host_users"] != false || features["enable_software_inventory"] != true {
		t.Errorf("features %v", features)
	}
	overrides, _ := features["detail_query_overrides"].(map[string]any)
	for _, off := range []string{"network_interface_unix", "software_deb_last_opened_at", "software_vscode_extensions",
		"software_python_packages_with_users_dir"} {
		if v, ok := overrides[off]; !ok || v != nil {
			t.Errorf("detail query %s not switched off: %v", off, overrides)
		}
	}
	software, _ := overrides["software_linux"].(string)
	if !strings.Contains(software, "FROM deb_packages") || strings.Contains(software, "chrome_extensions") ||
		strings.Contains(software, "users") {
		t.Errorf("software_linux override %q", software)
	}
	f.requests = nil
	if corrected, err := c.EnsureSettings(ctx); err != nil || len(corrected) != 0 {
		t.Fatalf("second round corrected %v, %v", corrected, err)
	}
	for _, r := range f.requests {
		if !strings.HasPrefix(r, "GET ") {
			t.Fatalf("second round changed something: %v", f.requests)
		}
	}
}

// TestEnsureSettingsResetsDrift: foreign detail query overrides, additional queries, webhooks, scheduled queries and
// packs are removed; saved queries without a schedule stay (they run only live, and live queries are off).
func TestEnsureSettingsResetsDrift(t *testing.T) {
	ctx := context.Background()
	f, srv := newFake(t)
	c := client(srv.URL)
	if _, err := c.EnsureSettings(ctx); err != nil {
		t.Fatal(err)
	}
	merge(f.config, map[string]any{
		"features": map[string]any{"additional_queries": map[string]any{"time": "SELECT * FROM time"},
			"detail_query_overrides": map[string]any{"os_version": "SELECT * FROM processes"}},
		"webhook_settings": map[string]any{"vulnerabilities_webhook": map[string]any{"enable_vulnerabilities_webhook": true}},
	}, false)
	f.addQuery("scheduled", 600)
	f.addQuery("saved", 0)
	f.addPack("old pack")
	corrected, err := c.EnsureSettings(ctx)
	want := []string{"features", "webhook_settings", "query scheduled", "pack old pack"}
	if err != nil || !slices.Equal(corrected, want) {
		t.Fatalf("corrected %v, %v; want %v", corrected, err, want)
	}
	features := f.section("features")
	overrides, _ := features["detail_query_overrides"].(map[string]any)
	if _, ok := overrides["os_version"]; ok || features["additional_queries"] != nil {
		t.Fatalf("drift kept: %v", features)
	}
	if len(f.queries) != 1 || len(f.packs) != 0 {
		t.Fatalf("queries %v, packs %v", f.queries, f.packs)
	}
}

// TestEnsureSettingsRetriesUnavailableFleet: 5xx answers are retried; a rejected token is not.
func TestEnsureSettingsRetriesUnavailableFleet(t *testing.T) {
	ctx := context.Background()
	f, srv := newFake(t)
	f.failNext = 2
	if _, err := client(srv.URL).EnsureSettings(ctx); err != nil {
		t.Fatalf("after two 503: %v", err)
	}
	f.requests = nil
	_, err := fleet.New(srv.URL, "wrong", "https://fleet.example.org").WithBackoff(time.Millisecond).EnsureSettings(ctx)
	if err == nil || !strings.Contains(err.Error(), "HTTP 401") || len(f.requests) != 1 {
		t.Fatalf("wrong token: %v after %v", err, f.requests)
	}
}
