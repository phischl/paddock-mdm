package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
)

// softwareLinux replaces Fleet's Linux software query (plan M5a decision 2): the system package managers only. Fleet's
// own query also reads browser extensions, npm packages and their paths from every user's home directory.
const softwareLinux = `SELECT name, version, '' AS extension_id, '' AS extension_for, 'deb_packages' AS source,
  '' AS release, '' AS vendor, '' AS arch, '' AS installed_path
FROM deb_packages WHERE status LIKE '% ok installed'
UNION
SELECT name, version, '' AS extension_id, '' AS extension_for, 'rpm_packages' AS source,
  release, vendor, arch, '' AS installed_path
FROM rpm_packages;`

// detailQueryOverrides are Paddock's changes to Fleet's detail queries (docs/compliance/privacy.md): a nil query
// switches Fleet's query off. Off are network interfaces (addresses), the last-use times of packages (file access
// times), and every software query that reads users' home directories.
func detailQueryOverrides() map[string]*string {
	q := softwareLinux
	return map[string]*string{
		"software_linux":                          &q,
		"network_interface_unix":                  nil,
		"software_deb_last_opened_at":             nil,
		"software_rpm_last_opened_at":             nil,
		"software_python_packages_with_users_dir": nil,
		"software_vscode_extensions":              nil,
		"software_jetbrains_plugins":              nil,
		"software_go_binaries":                    nil,
	}
}

// settings is the part of Fleet's configuration Paddock enforces (plan M5a decision 2).
type settings struct {
	ServerSettings struct {
		ServerURL            string `json:"server_url"`
		LiveQueryDisabled    bool   `json:"live_query_disabled"`
		EnableAnalytics      bool   `json:"enable_analytics"`
		QueryReportsDisabled bool   `json:"query_reports_disabled"`
		ScriptsDisabled      bool   `json:"scripts_disabled"`
		AIFeaturesDisabled   bool   `json:"ai_features_disabled"`
	} `json:"server_settings"`
	Features struct {
		EnableHostUsers         bool               `json:"enable_host_users"`
		EnableSoftwareInventory bool               `json:"enable_software_inventory"`
		AdditionalQueries       json.RawMessage    `json:"additional_queries"`
		DetailQueryOverrides    map[string]*string `json:"detail_query_overrides"`
	} `json:"features"`
	WebhookSettings struct {
		ActivitiesWebhook struct {
			Enable bool `json:"enable_activities_webhook"`
		} `json:"activities_webhook"`
		HostStatusWebhook struct {
			Enable bool `json:"enable_host_status_webhook"`
		} `json:"host_status_webhook"`
		FailingPoliciesWebhook struct {
			Enable bool `json:"enable_failing_policies_webhook"`
		} `json:"failing_policies_webhook"`
		VulnerabilitiesWebhook struct {
			Enable bool `json:"enable_vulnerabilities_webhook"`
		} `json:"vulnerabilities_webhook"`
	} `json:"webhook_settings"`
}

// wanted: no host users, software inventory on, no additional queries, no live queries, reports, scripts, analytics,
// AI features or webhooks; Fleet's server URL is the public device URL.
func (c *Client) wanted() settings {
	var s settings
	s.ServerSettings.ServerURL = c.publicURL
	s.ServerSettings.LiveQueryDisabled = true
	s.ServerSettings.QueryReportsDisabled = true
	s.ServerSettings.ScriptsDisabled = true
	s.ServerSettings.AIFeaturesDisabled = true
	s.Features.EnableSoftwareInventory = true
	s.Features.AdditionalQueries = json.RawMessage("null")
	s.Features.DetailQueryOverrides = detailQueryOverrides()
	return s
}

// EnsureSettings checks Fleet's settings of the data minimization and resets drift (plan M5a decision 2): the
// configuration above, and no scheduled queries or query packs (Paddock defines policies only). It returns what it
// corrected ("server_settings", "features", "webhook_settings", "query <name>", "pack <name>").
func (c *Client) EnsureSettings(ctx context.Context) ([]string, error) {
	var have settings
	if err := c.do(ctx, "GET", "/api/latest/fleet/config", nil, &have); err != nil {
		return nil, fmt.Errorf("get fleet config: %w", err)
	}
	if len(have.Features.AdditionalQueries) == 0 {
		have.Features.AdditionalQueries = json.RawMessage("null")
	}
	want := c.wanted()
	var corrected []string
	if have.ServerSettings != want.ServerSettings {
		corrected = append(corrected, "server_settings")
	}
	if !reflect.DeepEqual(have.Features, want.Features) {
		corrected = append(corrected, "features")
	}
	if have.WebhookSettings != want.WebhookSettings {
		corrected = append(corrected, "webhook_settings")
	}
	if len(corrected) > 0 {
		// A PATCH merges detail_query_overrides into the stored map; null clears it first so that no foreign
		// override stays.
		if !reflect.DeepEqual(have.Features.DetailQueryOverrides, want.Features.DetailQueryOverrides) {
			reset := map[string]any{"features": map[string]any{"detail_query_overrides": nil}}
			if err := c.do(ctx, "PATCH", "/api/latest/fleet/config", reset, nil); err != nil {
				return nil, fmt.Errorf("clear fleet detail query overrides: %w", err)
			}
		}
		if err := c.do(ctx, "PATCH", "/api/latest/fleet/config", want, nil); err != nil {
			return nil, fmt.Errorf("patch fleet config: %w", err)
		}
	}
	removed, err := c.removeSchedules(ctx)
	return append(corrected, removed...), err
}

// removeSchedules deletes scheduled queries and query packs.
func (c *Client) removeSchedules(ctx context.Context) ([]string, error) {
	var queries struct {
		Queries []struct {
			ID       int    `json:"id"`
			Name     string `json:"name"`
			Interval int    `json:"interval"`
		} `json:"queries"`
	}
	if err := c.do(ctx, "GET", "/api/latest/fleet/queries?per_page=1000", nil, &queries); err != nil {
		return nil, fmt.Errorf("list fleet queries: %w", err)
	}
	var removed []string
	for _, q := range queries.Queries {
		if q.Interval == 0 {
			continue // a saved query runs only live, and live queries are off
		}
		if err := c.do(ctx, "DELETE", "/api/latest/fleet/queries/id/"+strconv.Itoa(q.ID), nil, nil); err != nil {
			return removed, fmt.Errorf("delete fleet query %s: %w", q.Name, err)
		}
		removed = append(removed, "query "+q.Name)
	}
	var packs struct {
		Packs []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"packs"`
	}
	if err := c.do(ctx, "GET", "/api/latest/fleet/packs", nil, &packs); err != nil {
		return removed, fmt.Errorf("list fleet packs: %w", err)
	}
	for _, p := range packs.Packs {
		if err := c.do(ctx, "DELETE", "/api/latest/fleet/packs/id/"+strconv.Itoa(p.ID), nil, nil); err != nil {
			return removed, fmt.Errorf("delete fleet pack %s: %w", p.Name, err)
		}
		removed = append(removed, "pack "+p.Name)
	}
	return removed, nil
}
