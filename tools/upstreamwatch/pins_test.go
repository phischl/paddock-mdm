package main

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// TestEveryPinIsMapped parses the real versions.env and the compiler command: every *_IMAGE needs a table row.
func TestEveryPinIsMapped(t *testing.T) {
	f, err := os.Open("../../deploy/compose/versions.env")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	pins, err := ParseVersions(f, "deploy/compose/versions.env")
	if err != nil {
		t.Fatalf("ParseVersions: %v", err)
	}
	images := 0
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, _, ok := strings.Cut(sc.Text(), "=")
		if ok && !strings.HasPrefix(key, "#") && strings.HasSuffix(key, "_IMAGE") {
			images++
		}
	}
	names := map[string]bool{}
	for _, p := range pins {
		if names[p.Info.Name] {
			t.Errorf("pin name %s reported twice", p.Info.Name)
		}
		names[p.Info.Name] = true
		if len(p.Info.Gates) == 0 {
			t.Errorf("pin %s has no gate", p.Info.Name)
		}
	}
	if got := len(pins) - 1; got != images {
		t.Errorf("image pins = %d, *_IMAGE lines = %d", got, images)
	}
	for _, want := range []string{"fleetctl", "fleet_nvd", "caddy", "runtime"} {
		if !names[want] {
			t.Errorf("pin %s missing", want)
		}
	}
	src, err := os.ReadFile("../../server/cmd/paddock-server/compiler.go")
	if err != nil {
		t.Fatal(err)
	}
	hb, err := ParseCompiler(string(src), "server/cmd/paddock-server/compiler.go")
	if err != nil || hb.Info.Name != "himmelblau" || hb.Pinned == "" {
		t.Fatalf("ParseCompiler = %+v, %v", hb, err)
	}
}

func TestParseVersionsRejectsUnmappedPin(t *testing.T) {
	f, err := os.Open("testdata/versions-unmapped.env")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	_, err = ParseVersions(f, "versions.env")
	if err == nil || !strings.Contains(err.Error(), "GRAFANA_IMAGE") {
		t.Fatalf("err = %v, want the unmapped GRAFANA_IMAGE", err)
	}
}

func TestParseVersionsFixture(t *testing.T) {
	f, err := os.Open("testdata/versions.env")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	pins, err := ParseVersions(f, "versions.env")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range pins {
		got = append(got, p.Info.Name+"="+p.Pinned)
	}
	want := "caddy=2.11.6 rabbitmq=4.3.6-management authentik=2026.8.3 runtime=nonroot fleet_nvd=202610120101"
	if strings.Join(got, " ") != want {
		t.Fatalf("pins = %v, want %s", got, want)
	}
	if pins[4].Kind != KindNVD || pins[3].Image.Digest != "sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab" {
		t.Fatalf("unexpected pins %+v", pins)
	}
}

func TestParseImage(t *testing.T) {
	cases := map[string]ImageRef{
		"caddy:2.11.6@sha256:aa":                         {Registry: "docker.io", Repo: "library/caddy", Tag: "2.11.6", Digest: "sha256:aa"},
		"amazon/aws-cli:2.37.9@sha256:bb":                {Registry: "docker.io", Repo: "amazon/aws-cli", Tag: "2.37.9", Digest: "sha256:bb"},
		"ghcr.io/goauthentik/server:2026.8.3":            {Registry: "ghcr.io", Repo: "goauthentik/server", Tag: "2026.8.3"},
		"ghcr.io/sigstore/cosign/cosign:v3.1.3@sha256:c": {Registry: "ghcr.io", Repo: "sigstore/cosign/cosign", Tag: "v3.1.3", Digest: "sha256:c"},
		"mcr.microsoft.com/playwright:v1.64.0-noble":     {Registry: "mcr.microsoft.com", Repo: "playwright", Tag: "v1.64.0-noble"},
		"localhost:5000/x/y:1.0":                         {Registry: "localhost:5000", Repo: "x/y", Tag: "1.0"},
	}
	for in, want := range cases {
		got, err := ParseImage(in)
		if err != nil || got != want {
			t.Errorf("ParseImage(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{"caddy", "localhost:5000/x", "caddy:"} {
		if _, err := ParseImage(bad); err == nil {
			t.Errorf("ParseImage(%q) accepted", bad)
		}
	}
}

func TestParseCompilerWithoutDefault(t *testing.T) {
	if _, err := ParseCompiler("package main\n", "compiler.go"); err == nil {
		t.Fatal("accepted a file without the default")
	}
}
