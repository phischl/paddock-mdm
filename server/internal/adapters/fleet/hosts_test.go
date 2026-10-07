package fleet_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/ports"
)

// TestListHostsChangedSince: the host list is filtered by the newest of the hosts' update times; the zero time lists
// every host, and the refs are Fleet's IDs.
func TestListHostsChangedSince(t *testing.T) {
	ctx := context.Background()
	_, srv := newFake(t)
	c := client(srv.URL)
	page, err := c.ListHostsChangedSince(ctx, time.Time{}, "")
	if err != nil || len(page.Hosts) != 2 || page.Next != "" {
		t.Fatalf("all hosts %+v, %v", page, err)
	}
	if h := page.Hosts[1]; h.Ref != "2" || h.HardwareUUID != "a7ace4c5-76d1-ab48-a28d-55cd12a90b68" ||
		!h.ChangedAt.Equal(time.Date(2026, 10, 7, 13, 18, 30, 0, time.UTC)) {
		t.Fatalf("host %+v", h)
	}
	page, err = c.ListHostsChangedSince(ctx, time.Date(2026, 10, 7, 13, 18, 25, 0, time.UTC), "")
	if err != nil || len(page.Hosts) != 1 || page.Hosts[0].Ref != "2" {
		t.Fatalf("changed hosts %+v, %v", page, err)
	}
	if _, err := c.ListHostsChangedSince(ctx, time.Time{}, "x"); err == nil {
		t.Fatal("invalid cursor accepted")
	}
}

// TestHostInventory maps Fleet's host detail: software with its CVEs (no CVSS score or fixed version in Fleet free),
// answered policies only, osquery's version without an orbit version.
func TestHostInventory(t *testing.T) {
	_, srv := newFake(t)
	inv, err := client(srv.URL).HostInventory(context.Background(), "1")
	if err != nil {
		t.Fatal(err)
	}
	if inv.OSVersion != "Ubuntu 24.04.5 LTS" || inv.AgentVersion != "5.23.1" || inv.LastSeenAt == nil || len(inv.Software) != 3 {
		t.Fatalf("inventory %+v", inv)
	}
	apport := inv.Software[2]
	if apport.Name != "apport" || apport.Source != "deb_packages" ||
		!slices.Equal(apport.Vulnerabilities, []ports.Vulnerability{{CVE: "CVE-2022-28653"}}) {
		t.Fatalf("apport %+v", apport)
	}
	if !slices.Equal(inv.Policies, []ports.PolicyResult{{Key: "disk_encrypted", Passing: true}, {Key: "paddock_agent_running"}}) {
		t.Fatalf("policies %+v", inv.Policies)
	}
	if _, err := client(srv.URL).HostInventory(context.Background(), "../config"); err == nil {
		t.Fatal("invalid host reference accepted")
	}
}

// TestApplyPolicies sends Paddock's policies as Fleet's policy spec for Linux hosts.
func TestApplyPolicies(t *testing.T) {
	f, srv := newFake(t)
	err := client(srv.URL).ApplyPolicies(context.Background(), []ports.PolicyDefinition{{Key: "k", Description: "d", Query: "SELECT 1;"}})
	if err != nil || len(f.policySpecs) != 1 {
		t.Fatalf("%v, specs %v", err, f.policySpecs)
	}
	if s := f.policySpecs[0]; s["name"] != "k" || s["query"] != "SELECT 1;" || s["description"] != "d" || s["platform"] != "linux" {
		t.Fatalf("spec %v", s)
	}
}

// TestVulnerabilityState: the digest of Fleet's vulnerable software versions is stable and changes with a new match.
func TestVulnerabilityState(t *testing.T) {
	ctx := context.Background()
	f, srv := newFake(t)
	c := client(srv.URL)
	first, err := c.VulnerabilityState(ctx)
	if err != nil || first == "" {
		t.Fatalf("state %q, %v", first, err)
	}
	if again, _ := c.VulnerabilityState(ctx); again != first {
		t.Fatalf("unstable state %q, %q", first, again)
	}
	f.vulnerableSoftware = []map[string]any{{"id": 82, "vulnerabilities": []map[string]any{{"cve": "CVE-2022-28653"}, {"cve": "CVE-2026-0001"}}}}
	if changed, _ := c.VulnerabilityState(ctx); changed == first {
		t.Fatal("a new match did not change the state")
	}
}
