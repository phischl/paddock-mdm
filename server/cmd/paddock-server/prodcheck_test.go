package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

// TestProdCheckHosts: --host accepts controlplane, audit and lab; the lab gets its own items, and --online reads the
// audit bucket on the audit and the lab host only.
func TestProdCheckHosts(t *testing.T) {
	check := func(args ...string) (string, error) {
		var out bytes.Buffer
		err := runProdCheck(context.Background(), args, strings.NewReader(`{}`), &out)
		return out.String(), err
	}
	if _, err := check("--host", "edge"); !errors.Is(err, errUsage) {
		t.Fatalf("--host edge: %v, want the usage error", err)
	}
	out, err := check("--host", "lab")
	if !errors.Is(err, errProdCheckFailed) || !strings.Contains(out, "FAIL  only Caddy's HTTP port published, on the bind address") ||
		strings.Contains(out, "only 80/443 published") {
		t.Fatalf("--host lab: %v\n%s", err, out)
	}
	for _, host := range []string{"lab", "audit"} {
		if _, err := check("--host", host, "--online"); err == nil || !strings.Contains(err.Error(), "no service paddock-audit-writer") {
			t.Fatalf("--host %s --online: %v, want the audit bucket to be read", host, err)
		}
	}
	if out, err := check("--host", "controlplane", "--online"); err != nil || strings.Contains(out, "Object Lock") {
		t.Fatalf("--host controlplane --online: %v, want the checklist without the audit bucket\n%s", err, out)
	}
}

// TestProdCheckDockerNetworks: --docker-networks checks the edge subnet against the listed networks (an overlap
// warns), and without it the item is absent (decisions-alpha10 A10-1).
func TestProdCheckDockerNetworks(t *testing.T) {
	const cfg = `{"services":{"caddy":{"networks":{"edge":{"ipv4_address":"172.28.0.10"}}}},` +
		`"networks":{"edge":{"name":"paddock_edge","ipam":{"config":[{"subnet":"172.28.0.0/24","ip_range":"172.28.0.128/25"}]}}}}`
	check := func(args ...string) string {
		var out bytes.Buffer
		_ = runProdCheck(context.Background(), args, strings.NewReader(cfg), &out)
		return out.String()
	}
	const item = "networks: edge subnet free on this host"
	if out := check(); strings.Contains(out, item) {
		t.Fatalf("without --docker-networks:\n%s", out)
	}
	if out := check("--docker-networks"); !strings.Contains(out, "PASS  "+item) {
		t.Fatalf("no other network:\n%s", out)
	}
	out := check("--docker-networks", "--docker-network", "paddock_edge=172.28.0.0/24",
		"--docker-network", "bridge=172.17.0.0/16", "--docker-network", "paddock_cp=fd00::/64,172.28.0.0/16")
	if !strings.Contains(out, "WARN  "+item) ||
		!strings.Contains(out, "Docker network paddock_cp (172.28.0.0/16) overlaps the edge subnet 172.28.0.0/24") ||
		strings.Contains(out, "network bridge") || strings.Contains(out, "network paddock_edge") {
		t.Fatalf("overlapping paddock_cp:\n%s", out)
	}
}
