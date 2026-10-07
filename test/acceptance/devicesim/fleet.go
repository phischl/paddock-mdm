package devicesim

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// FleetHost plays osquery of one host against Fleet's public device endpoints (fleet.<domain>): it enrolls with the
// global enroll secret and answers Fleet's detail queries as an Ubuntu 24.04 host with the given deb packages; every
// policy passes. The inventory gates and the portal end-to-end tests run without VMs this way; the VM gates
// (test/system) run the real fleetd.
type FleetHost struct {
	HTTP     *http.Client
	FleetURL string
	UUID     string
	Packages [][2]string // name, version
	nodeKey  string
}

// EnrollFleet enrolls a host whose hardware UUID is uuid (a simulated device's HardwareUUID, so that it maps to that
// device).
func EnrollFleet(ctx context.Context, client *http.Client, fleetURL, enrollSecret, uuid, hostname string, packages [][2]string) (*FleetHost, error) {
	h := &FleetHost{HTTP: client, FleetURL: strings.TrimSuffix(fleetURL, "/"), UUID: uuid, Packages: packages}
	var out struct {
		NodeKey     string `json:"node_key"`
		NodeInvalid bool   `json:"node_invalid"`
	}
	err := h.post(ctx, "/api/v1/osquery/enroll", map[string]any{
		"enroll_secret": enrollSecret, "host_identifier": uuid,
		"host_details": map[string]any{
			"system_info":   map[string]string{"uuid": uuid, "hostname": hostname, "computer_name": hostname},
			"os_version":    osVersion(),
			"osquery_info":  map[string]string{"version": "5.23.1", "uuid": uuid},
			"platform_info": map[string]string{},
		},
	}, &out)
	if err != nil {
		return nil, err
	}
	if out.NodeKey == "" || out.NodeInvalid {
		return nil, fmt.Errorf("fleet enrollment of %s: %+v", hostname, out)
	}
	h.nodeKey = out.NodeKey
	return h, nil
}

func osVersion() map[string]string {
	return map[string]string{"name": "Ubuntu", "version": "24.04.5 LTS (Noble Numbat)", "major": "24", "minor": "4",
		"patch": "5", "build": "", "platform": "ubuntu", "platform_like": "debian", "codename": "noble", "arch": "x86_64"}
}

// Answer runs one round of distributed queries: detail queries get the host's facts and packages, policies pass,
// everything else is answered empty. It reports how many queries Fleet sent.
func (h *FleetHost) Answer(ctx context.Context) (int, error) {
	var read struct {
		Queries map[string]string `json:"queries"`
	}
	if err := h.post(ctx, "/api/v1/osquery/distributed/read", map[string]any{"node_key": h.nodeKey}, &read); err != nil {
		return 0, err
	}
	if len(read.Queries) == 0 {
		return 0, nil
	}
	results, statuses := map[string]any{}, map[string]int{}
	for name := range read.Queries {
		statuses[name] = 0
		results[name] = h.rows(name)
	}
	err := h.post(ctx, "/api/v1/osquery/distributed/write",
		map[string]any{"node_key": h.nodeKey, "queries": results, "statuses": statuses, "messages": map[string]string{}}, nil)
	return len(read.Queries), err
}

// WaitAnswered answers distributed queries until Fleet sent some and has no more.
func (h *FleetHost) WaitAnswered(ctx context.Context) error {
	for asked := 0; ; {
		n, err := h.Answer(ctx)
		if err != nil {
			return err
		}
		if asked += n; asked > 0 && n == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("fleet sent %d queries to %s: %w", asked, h.UUID, ctx.Err())
		case <-time.After(2 * time.Second):
		}
	}
}

func (h *FleetHost) rows(query string) []map[string]string {
	switch {
	case query == "fleet_detail_query_os_version":
		return []map[string]string{osVersion()}
	case query == "fleet_detail_query_os_unix_like":
		os := osVersion()
		os["kernel_version"] = "7.0.0-38-generic"
		return []map[string]string{os}
	case query == "fleet_detail_query_system_info":
		return []map[string]string{{"uuid": h.UUID, "hostname": "sim", "computer_name": "sim", "cpu_type": "x86_64",
			"physical_memory": "4294967296", "cpu_physical_cores": "2", "cpu_logical_cores": "2"}}
	case query == "fleet_detail_query_osquery_info":
		return []map[string]string{{"version": "5.23.1", "uuid": h.UUID, "build_platform": "ubuntu"}}
	case query == "fleet_detail_query_software_linux":
		var rows []map[string]string
		for _, p := range h.Packages {
			rows = append(rows, map[string]string{"name": p[0], "version": p[1], "source": "deb_packages", "extension_id": "",
				"extension_for": "", "release": "", "vendor": "", "arch": "", "installed_path": ""})
		}
		return rows
	case strings.HasPrefix(query, "fleet_policy_query_"):
		return []map[string]string{{"1": "1"}}
	}
	return []map[string]string{}
}

func (h *FleetHost) post(ctx context.Context, path string, body, out any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.FleetURL+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := h.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	defer func() { _ = res.Body.Close() }()
	got, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("POST %s: HTTP %d %s", path, res.StatusCode, got)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(got, out)
}
