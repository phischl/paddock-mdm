package fleet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/ports"
)

var _ ports.Inventory = (*Client)(nil)

// hostsPerPage is the page size of the host list.
const hostsPerPage = 500

type host struct {
	ID                int        `json:"id"`
	UUID              string     `json:"uuid"`
	OSVersion         string     `json:"os_version"`
	OsqueryVersion    string     `json:"osquery_version"`
	OrbitVersion      *string    `json:"orbit_version"`
	SeenTime          *time.Time `json:"seen_time"`
	DetailUpdatedAt   time.Time  `json:"detail_updated_at"`
	SoftwareUpdatedAt time.Time  `json:"software_updated_at"`
	PolicyUpdatedAt   time.Time  `json:"policy_updated_at"`
	Software          []struct {
		Name            string `json:"name"`
		Version         string `json:"version"`
		Source          string `json:"source"`
		Vulnerabilities []struct {
			CVE string `json:"cve"`
			// Fleet Premium only; Fleet free omits them.
			CVSSScore         *float64 `json:"cvss_score"`
			ResolvedInVersion *string  `json:"resolved_in_version"`
		} `json:"vulnerabilities"`
	} `json:"software"`
	Policies []struct {
		Name     string `json:"name"`
		Response string `json:"response"` // pass, fail, or "" before the host answered
	} `json:"policies"`
}

// changedAt is the newest of the host's detail, software and policy updates.
func (h host) changedAt() time.Time {
	t := h.DetailUpdatedAt
	for _, u := range []time.Time{h.SoftwareUpdatedAt, h.PolicyUpdatedAt} {
		if u.After(t) {
			t = u
		}
	}
	return t
}

// ListHostsChangedSince implements ports.Inventory: Fleet's host list in pages ordered by ID (the cursor is the page
// number), filtered by the hosts' update times; Fleet itself cannot filter by them.
func (c *Client) ListHostsChangedSince(ctx context.Context, since time.Time, cursor string) (ports.HostPage, error) {
	page := 0
	if cursor != "" {
		var err error
		if page, err = strconv.Atoi(cursor); err != nil || page < 0 {
			return ports.HostPage{}, fmt.Errorf("fleet: invalid host cursor %q", cursor)
		}
	}
	q := url.Values{"page": {strconv.Itoa(page)}, "per_page": {strconv.Itoa(hostsPerPage)}, "order_key": {"id"},
		"disable_failing_policies": {"true"}}
	var out struct {
		Hosts []host `json:"hosts"`
	}
	if err := c.do(ctx, "GET", "/api/latest/fleet/hosts?"+q.Encode(), nil, &out); err != nil {
		return ports.HostPage{}, fmt.Errorf("list fleet hosts: %w", err)
	}
	var res ports.HostPage
	for _, h := range out.Hosts {
		if h.UUID == "" || h.changedAt().Before(since) {
			continue
		}
		res.Hosts = append(res.Hosts, ports.InventoryHost{Ref: ports.HostRef(strconv.Itoa(h.ID)), HardwareUUID: h.UUID, ChangedAt: h.changedAt()})
	}
	if len(out.Hosts) == hostsPerPage {
		res.Next = strconv.Itoa(page + 1)
	}
	return res, nil
}

// HostInventory implements ports.Inventory with one request: Fleet's host detail carries the software with its
// vulnerabilities and the policy results.
func (c *Client) HostInventory(ctx context.Context, ref ports.HostRef) (ports.HostInventory, error) {
	id, err := strconv.Atoi(string(ref))
	if err != nil {
		return ports.HostInventory{}, fmt.Errorf("fleet: invalid host reference %q", ref)
	}
	var out struct {
		Host host `json:"host"`
	}
	if err := c.do(ctx, "GET", "/api/latest/fleet/hosts/"+strconv.Itoa(id), nil, &out); err != nil {
		return ports.HostInventory{}, fmt.Errorf("get fleet host %d: %w", id, err)
	}
	h := out.Host
	inv := ports.HostInventory{OSVersion: h.OSVersion, AgentVersion: h.OsqueryVersion, LastSeenAt: h.SeenTime}
	if h.OrbitVersion != nil && *h.OrbitVersion != "" {
		inv.AgentVersion = *h.OrbitVersion
	}
	for _, s := range h.Software {
		p := ports.SoftwarePackage{Name: s.Name, Version: s.Version, Source: s.Source}
		for _, v := range s.Vulnerabilities {
			vuln := ports.Vulnerability{CVE: v.CVE, CVSSScore: v.CVSSScore}
			if v.ResolvedInVersion != nil {
				vuln.FixedVersion = *v.ResolvedInVersion
			}
			p.Vulnerabilities = append(p.Vulnerabilities, vuln)
		}
		inv.Software = append(inv.Software, p)
	}
	for _, p := range h.Policies {
		if p.Response == "pass" || p.Response == "fail" {
			inv.Policies = append(inv.Policies, ports.PolicyResult{Key: p.Name, Passing: p.Response == "pass"})
		}
	}
	return inv, nil
}

// VulnerabilityState implements ports.Inventory: a digest of Fleet's vulnerable software versions and their CVEs.
func (c *Client) VulnerabilityState(ctx context.Context) (string, error) {
	h := sha256.New()
	for page := 0; ; page++ {
		q := url.Values{"vulnerable": {"true"}, "page": {strconv.Itoa(page)}, "per_page": {strconv.Itoa(hostsPerPage)}, "order_key": {"id"}}
		var out struct {
			Software []struct {
				ID              int `json:"id"`
				Vulnerabilities []struct {
					CVE string `json:"cve"`
				} `json:"vulnerabilities"`
			} `json:"software"`
			Meta struct {
				HasNextResults bool `json:"has_next_results"`
			} `json:"meta"`
		}
		if err := c.do(ctx, "GET", "/api/latest/fleet/software/versions?"+q.Encode(), nil, &out); err != nil {
			return "", fmt.Errorf("list fleet vulnerable software: %w", err)
		}
		for _, s := range out.Software {
			cves := make([]string, len(s.Vulnerabilities))
			for i, v := range s.Vulnerabilities {
				cves[i] = v.CVE
			}
			slices.Sort(cves)
			fmt.Fprintf(h, "%d:%s\n", s.ID, strings.Join(cves, ","))
		}
		if !out.Meta.HasNextResults || len(out.Software) == 0 {
			return hex.EncodeToString(h.Sum(nil)), nil
		}
	}
}

// ApplyPolicies implements ports.Inventory: Fleet's policy spec creates or updates global policies by name.
func (c *Client) ApplyPolicies(ctx context.Context, policies []ports.PolicyDefinition) error {
	type spec struct {
		Name        string `json:"name"`
		Query       string `json:"query"`
		Description string `json:"description"`
		Platform    string `json:"platform"`
	}
	specs := make([]spec, len(policies))
	for i, p := range policies {
		specs[i] = spec{Name: p.Key, Query: p.Query, Description: p.Description, Platform: "linux"}
	}
	if err := c.do(ctx, "POST", "/api/latest/fleet/spec/policies", map[string]any{"specs": specs}, nil); err != nil {
		return fmt.Errorf("apply fleet policies: %w", err)
	}
	return nil
}
