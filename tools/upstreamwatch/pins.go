package main

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

// Kind is where the latest upstream version of a pin comes from.
type Kind int

// Pin kinds (plan M8d decision 58).
const (
	KindImage Kind = iota
	KindHimmelblau
	KindNVD
)

// Gates a person runs before a bump (plan M8d decision 60).
const (
	gateAcceptance   = "make acceptance"
	gateRestoreDrill = "make restore-drill"
	gateWORM         = "make acceptance T=TestWORM (WORM gate, ADR 0017)"
	gateAuthentik    = "make acceptance T=TestIdentityLockAuthentik (gate I2)"
	gateFleet        = "inventory gates F0–F4 (make acceptance T='TestFleet|TestInventory')"
	gateGitleaks     = "update GITLEAKS_DEFAULT_CONFIG_BYTES and GITLEAKS_DEFAULT_CONFIG_SHA256 in versions.env (ADR 0026), then make scan-secrets"
	gateHimmelblau   = "make system-test VM=all T=TestIdentity"
)

// PinInfo is the table row of one pin: its reported name, the GitHub repository whose releases carry the release
// notes ("" when none), the line the pin stays on ("" when any newer tag counts; a tag prefix such as "8.4." when
// only that line is followed, plan M6d decision 10) and the gates to run before the bump.
type PinInfo struct {
	Name   string
	GitHub string
	Line   string
	Gates  []string
}

// imagePins maps every *_IMAGE variable of versions.env to its table row. TestEveryPinIsMapped fails when a variable
// has no row, so a new pin cannot slip past the watch.
func imagePins() map[string]PinInfo {
	acc := []string{gateAcceptance}
	return map[string]PinInfo{
		"CADDY_IMAGE":            {Name: "caddy", GitHub: "caddyserver/caddy", Gates: []string{gateRestoreDrill, gateAcceptance}},
		"POSTGRES_IMAGE":         {Name: "postgres", Gates: []string{gateRestoreDrill, gateAcceptance}},
		"RABBITMQ_IMAGE":         {Name: "rabbitmq", Gates: acc},
		"OPENBAO_IMAGE":          {Name: "openbao", GitHub: "openbao/openbao", Gates: acc},
		"AUTHENTIK_IMAGE":        {Name: "authentik", GitHub: "goauthentik/authentik", Gates: []string{gateAuthentik, gateAcceptance}},
		"RUSTFS_IMAGE":           {Name: "rustfs", GitHub: "rustfs/rustfs", Gates: []string{gateWORM, gateAcceptance}},
		"VALKEY_IMAGE":           {Name: "valkey", GitHub: "valkey-io/valkey", Gates: acc},
		"FLEET_IMAGE":            {Name: "fleet", GitHub: "fleetdm/fleet", Gates: []string{gateFleet}},
		"FLEETCTL_IMAGE":         {Name: "fleetctl", GitHub: "fleetdm/fleet", Gates: []string{gateFleet}},
		"FLEET_MYSQL_IMAGE":      {Name: "fleet_mysql", Line: "8.4.", Gates: []string{gateFleet}},
		"AWS_CLI_IMAGE":          {Name: "aws_cli", Gates: acc},
		"RC_IMAGE":               {Name: "rc", Gates: []string{gateWORM, gateAcceptance}},
		"PROMETHEUS_IMAGE":       {Name: "prometheus", GitHub: "prometheus/prometheus", Gates: acc},
		"GO_BUILD_IMAGE":         {Name: "go_build", Gates: acc},
		"RUNTIME_IMAGE":          {Name: "runtime", Gates: acc},
		"COMPILER_RUNTIME_IMAGE": {Name: "compiler_runtime", Gates: acc},
		"NODE_IMAGE":             {Name: "node", Gates: acc},
		"PLAYWRIGHT_IMAGE":       {Name: "playwright", Gates: acc},
		"GOLANGCI_LINT_IMAGE":    {Name: "golangci_lint", GitHub: "golangci/golangci-lint", Gates: acc},
		"NFPM_IMAGE":             {Name: "nfpm", GitHub: "goreleaser/nfpm", Gates: acc},
		"BINFMT_IMAGE":           {Name: "binfmt", GitHub: "tonistiigi/binfmt", Gates: acc},
		"BUILDKIT_IMAGE":         {Name: "buildkit", GitHub: "moby/buildkit", Gates: acc},
		"SYFT_IMAGE":             {Name: "syft", GitHub: "anchore/syft", Gates: acc},
		"COSIGN_IMAGE":           {Name: "cosign", GitHub: "sigstore/cosign", Gates: acc},
		"K6_IMAGE":               {Name: "k6", GitHub: "grafana/k6", Gates: acc},
		"GITLEAKS_IMAGE":         {Name: "gitleaks", GitHub: "gitleaks/gitleaks", Gates: []string{gateGitleaks}},
		"TRIVY_IMAGE":            {Name: "trivy", GitHub: "aquasecurity/trivy", Gates: acc},
		"NGINX_IMAGE":            {Name: "nginx", Gates: acc},
	}
}

// Pin is one pinned version the watch compares with upstream.
type Pin struct {
	Info   PinInfo
	Kind   Kind
	File   string // the file that pins it
	Line   string // the pinning line, verbatim
	Pinned string // tag or version
	Image  ImageRef
}

// ImageRef is a parsed image reference of versions.env.
type ImageRef struct {
	Registry string // docker.io, ghcr.io, gcr.io, mcr.microsoft.com
	Repo     string // library/caddy, goauthentik/server
	Tag      string
	Digest   string
}

// ParseImage splits a reference such as caddy:2.11.6@sha256:… into registry, repository, tag and digest.
func ParseImage(ref string) (ImageRef, error) {
	var r ImageRef
	name, digest, _ := strings.Cut(ref, "@")
	r.Digest = digest
	slash := strings.LastIndex(name, "/")
	colon := strings.LastIndex(name, ":")
	if colon <= slash {
		return r, fmt.Errorf("image %q has no tag", ref)
	}
	name, r.Tag = name[:colon], name[colon+1:]
	first, rest, hasSlash := strings.Cut(name, "/")
	switch {
	case hasSlash && (strings.ContainsAny(first, ".:") || first == "localhost"):
		r.Registry, r.Repo = first, rest
	case hasSlash:
		r.Registry, r.Repo = "docker.io", name
	default:
		r.Registry, r.Repo = "docker.io", "library/"+name
	}
	if r.Repo == "" || r.Tag == "" {
		return r, fmt.Errorf("image %q is incomplete", ref)
	}
	return r, nil
}

var nvdTagRE = regexp.MustCompile(`/fleetdm/nvd/releases/download/(\d{12})/`)

var himmelblauRE = regexp.MustCompile(`"PADDOCK_HIMMELBLAU_VERSION", "([0-9.]+)"`)

// ParseVersions reads versions.env and returns the image pins and the fleet_nvd pin in file order. An *_IMAGE
// variable without a table row is an error.
func ParseVersions(r io.Reader, file string) ([]Pin, error) {
	table := imagePins()
	var pins []Pin
	var unmapped []string
	nvd := false
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch {
		case strings.HasSuffix(key, "_IMAGE"):
			info, mapped := table[key]
			if !mapped {
				unmapped = append(unmapped, key)
				continue
			}
			ref, err := ParseImage(value)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", key, err)
			}
			pins = append(pins, Pin{Info: info, Kind: KindImage, File: file, Line: line, Pinned: ref.Tag, Image: ref})
		case key == "FLEET_CPE_DATABASE_URL" && !nvd:
			m := nvdTagRE.FindStringSubmatch(value)
			if m == nil {
				return nil, fmt.Errorf("%s: no fleetdm/nvd release tag in %q", key, value)
			}
			nvd = true
			pins = append(pins, Pin{
				Info: PinInfo{Name: "fleet_nvd", GitHub: "fleetdm/nvd", Gates: []string{gateFleet}},
				Kind: KindNVD, File: file, Line: line, Pinned: m[1],
			})
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(unmapped) > 0 {
		sort.Strings(unmapped)
		return nil, fmt.Errorf("pins without a table row in tools/upstreamwatch/pins.go: %s", strings.Join(unmapped, ", "))
	}
	return pins, nil
}

// ParseCompiler reads the PADDOCK_HIMMELBLAU_VERSION default of the compiler command.
func ParseCompiler(src, file string) (Pin, error) {
	for line := range strings.SplitSeq(src, "\n") {
		if m := himmelblauRE.FindStringSubmatch(line); m != nil {
			return Pin{
				Info: PinInfo{Name: "himmelblau", Gates: []string{gateHimmelblau}},
				Kind: KindHimmelblau, File: file, Line: strings.TrimSpace(line), Pinned: m[1],
			}, nil
		}
	}
	return Pin{}, fmt.Errorf("%s: no PADDOCK_HIMMELBLAU_VERSION default found", file)
}
