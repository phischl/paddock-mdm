package agent

import (
	"net/url"
	"strings"
)

// BundlesURL derives the public package store https://bundles.<domain>[:port] from the agent's server URL
// https://device.<domain>[:port] (architecture §4.1), from which the agent installs fleetd (plan M5a decision 5);
// "" if the server URL does not name a device host.
func BundlesURL(serverURL string) string {
	u, err := url.Parse(serverURL)
	if err != nil || u.Scheme != "https" || !strings.HasPrefix(u.Host, "device.") {
		return ""
	}
	return "https://bundles." + strings.TrimPrefix(u.Host, "device.")
}
