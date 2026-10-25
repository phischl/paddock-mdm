package agentrelease

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestValidateSourceVersion(t *testing.T) {
	for _, v := range []string{"0.1.0", "0.1.0-alpha.6", "1.2.3-rc.1", "10.0.0-beta.0"} {
		if err := ValidateSourceVersion(v); err != nil {
			t.Errorf("%s refused: %v", v, err)
		}
	}
	for _, v := range []string{"", "v0.1.0", "0.1.0-alpha", "0.1.0-alpha.01", "0.1.0-e2e", "0.1.0+build", "0.01.0",
		"0.0.1-gate1a2b", "0.1.0-alpha.1 ", "edge-20261025-abcdef0"} {
		if ValidateSourceVersion(v) == nil {
			t.Errorf("%q accepted", v)
		}
	}
}

func TestSourceAssets(t *testing.T) {
	got := SourceAssets("0.1.0-alpha.6")
	want := []SourceAsset{
		{Name: "paddockd_0.1.0-alpha.6_linux_amd64", Arch: "amd64", Required: true},
		{Name: "paddockd_0.1.0-alpha.6_linux_arm64", Arch: "arm64", Required: true},
		{Name: "paddock-agent_0.1.0-alpha.6_amd64.deb", Arch: "amd64", Package: PackageAgent, Required: true},
		{Name: "paddock-supervisor_0.1.0-alpha.6_amd64.deb", Arch: "amd64", Package: PackageSupervisor, Required: true},
		{Name: "paddock-agent_0.1.0-alpha.6_arm64.deb", Arch: "arm64", Package: PackageAgent},
		{Name: "paddock-supervisor_0.1.0-alpha.6_arm64.deb", Arch: "arm64", Package: PackageSupervisor},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("SourceAssets = %+v, want %+v", got, want)
	}
}

// TestSourceAssetsMatchTheSignJob holds the required set equal to the signed files packaging/release_test.sh expects
// from the sign job (ADR 0043 decision 4): a change to the release workflow's assets must change both.
func TestSourceAssetsMatchTheSignJob(t *testing.T) {
	b, err := os.ReadFile("../../../../packaging/release_test.sh")
	if err != nil {
		t.Fatal(err)
	}
	_, after, found := strings.Cut(string(b), `check "sign-release output"`)
	m := regexp.MustCompile(`\n\s*"([^"]+)"`).FindStringSubmatch(after)
	if !found || m == nil {
		t.Fatal("packaging/release_test.sh: the check \"sign-release output\" is missing")
	}
	const v = "1.2.3"
	var signed []string
	for _, f := range strings.Fields(strings.ReplaceAll(m[1], "${v}", v)) {
		if !strings.HasSuffix(f, ".minisig") {
			signed = append(signed, f)
		}
	}
	var required []string
	for _, a := range SourceAssets(v) {
		if a.Required {
			required = append(required, a.Name)
		}
	}
	slices.Sort(signed)
	slices.Sort(required)
	if !slices.Equal(required, signed) {
		t.Fatalf("required assets %v, the sign job signs %v", required, signed)
	}
}

func TestParseFleetdAsset(t *testing.T) {
	if v, arch, ok := ParseFleetdAsset("fleet-osquery_1.48.0_amd64.deb"); !ok || v != "1.48.0" || arch != "amd64" {
		t.Fatalf("fleet-osquery_1.48.0_amd64.deb = %q %q %v", v, arch, ok)
	}
	for _, name := range []string{"fleet-osquery_1.48.0_amd64.deb.minisig", "paddock-revoke_0.1.0_amd64.deb",
		"fleet-osquery_1.48.0_riscv64.deb", "fleet-osquery_latest_amd64.deb"} {
		if _, _, ok := ParseFleetdAsset(name); ok {
			t.Errorf("%s accepted", name)
		}
	}
}
