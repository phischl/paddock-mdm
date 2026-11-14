package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
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

// TestCheckContainers: check-containers reads `docker inspect` from stdin and the exceptions file, passes a hardened
// container and fails (exit 1) one that adds a capability the matrix does not list; prod-check --online --containers
// prints the same item.
func TestCheckContainers(t *testing.T) {
	dir := t.TempDir()
	exceptions := filepath.Join(dir, "hardening-exceptions.yaml")
	if err := os.WriteFile(exceptions, []byte("services:\n  caddy:\n    cap_add:\n      value: [NET_BIND_SERVICE]\n      reason: r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inspect := func(capAdd string) string {
		return `[{"Name":"/p-caddy-1","Config":{"Labels":{"com.docker.compose.service":"caddy"}},"HostConfig":{"CapAdd":` + capAdd +
			`,"CapDrop":["ALL"],"SecurityOpt":["no-new-privileges:true"],"PidsLimit":64,"Memory":1048576}}]`
	}
	const item = "containers: capabilities and security options match the matrix"
	var out bytes.Buffer
	if err := runCheckContainers([]string{"--exceptions", exceptions}, strings.NewReader(inspect(`["CAP_NET_BIND_SERVICE"]`)), &out); err != nil ||
		!strings.Contains(out.String(), "PASS  "+item) {
		t.Fatalf("hardened: %v\n%s", err, out.String())
	}
	out.Reset()
	err := runCheckContainers([]string{"--exceptions", exceptions}, strings.NewReader(inspect(`["CAP_NET_BIND_SERVICE","CAP_NET_RAW"]`)), &out)
	if !errors.Is(err, errProdCheckFailed) || !strings.Contains(out.String(), "FAIL  "+item) || !strings.Contains(out.String(), "p-caddy-1") {
		t.Fatalf("added capability: %v\n%s", err, out.String())
	}
	if err := runCheckContainers([]string{"--exceptions", filepath.Join(dir, "missing.yaml")}, strings.NewReader("[]"), io.Discard); err == nil {
		t.Fatal("a missing exceptions file passed")
	}
	if err := runCheckContainers([]string{"extra"}, strings.NewReader("[]"), io.Discard); !errors.Is(err, errUsage) {
		t.Fatalf("positional argument: %v", err)
	}

	containers := filepath.Join(dir, "containers.json")
	if err := os.WriteFile(containers, []byte(inspect(`null`)), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	_ = runProdCheck(context.Background(), []string{"--online", "--containers", containers, "--hardening-exceptions", exceptions},
		strings.NewReader(`{}`), &out)
	if !strings.Contains(out.String(), "FAIL  "+item) || !strings.Contains(out.String(), "CapAdd [], the matrix allows [NET_BIND_SERVICE]") {
		t.Fatalf("prod-check --online --containers:\n%s", out.String())
	}
	out.Reset()
	_ = runProdCheck(context.Background(), []string{"--containers", containers, "--hardening-exceptions", exceptions}, strings.NewReader(`{}`), &out)
	if strings.Contains(out.String(), item) {
		t.Fatalf("offline with --containers:\n%s", out.String())
	}
}
