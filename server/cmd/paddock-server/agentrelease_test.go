package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseDebName(t *testing.T) {
	for _, c := range []struct {
		file, version, name, packageVersion, arch string
	}{
		{"paddock-agent_1.2.0_amd64.deb", "1.2.0", "paddock-agent", "", "amd64"},
		{"paddock-supervisor_0.1.0-alpha.1_amd64.deb", "0.1.0-alpha.1", "paddock-supervisor", "", "amd64"},
		{"paddock-revoke_0.1.0~alpha.1_arm64.deb", "0.1.0-alpha.1", "paddock-revoke", "", "arm64"},
		{"fleet-osquery_1.48.0_amd64.deb", "1.2.0", "fleet-osquery", "1.48.0", "amd64"},
	} {
		got, err := parseDebName(c.file, c.version)
		if err != nil || got.Name != c.name || got.PackageVersion != c.packageVersion || got.Arch != c.arch {
			t.Errorf("parseDebName(%q, %q) = %+v, %v", c.file, c.version, got, err)
		}
	}
	for _, c := range []struct{ file, version string }{
		{"paddock-agent_1.1.0_amd64.deb", "1.2.0"},
		{"paddock-agent_1.2.0_amd64-unsigned.deb", "1.2.0"},
		{"paddock-agent-1.2.0-amd64.deb", "1.2.0"},
		{"other_1.2.0_amd64.deb", "1.2.0"},
		{"paddock-agent_1.2.0_amd64.rpm", "1.2.0"},
	} {
		if _, err := parseDebName(c.file, c.version); err == nil {
			t.Errorf("parseDebName(%q, %q) accepted", c.file, c.version)
		}
	}
}

func TestReadReleaseDir(t *testing.T) {
	write := func(t *testing.T, dir string, files ...string) {
		t.Helper()
		for _, f := range files {
			path := filepath.Join(dir, f)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(f), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}

	dir := t.TempDir()
	write(t, dir, "amd64/paddockd", "amd64/paddockd.minisig", "arm64/paddockd", "arm64/paddockd.minisig",
		"paddock-agent_1.2.0_amd64.deb", "paddock-agent_1.2.0_amd64.deb.minisig",
		"fleet-osquery_1.48.0_amd64.deb", "fleet-osquery_1.48.0_amd64.deb.minisig", "SHA256SUMS")
	binaries, packages, err := readReleaseDir(dir, "1.2.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(binaries) != 2 || binaries[0].Arch != "amd64" || string(binaries[1].Minisig) != "arm64/paddockd.minisig" {
		t.Errorf("binaries = %+v", binaries)
	}
	if len(packages) != 2 || packages[0].Name != "fleet-osquery" || string(packages[1].Deb) != "paddock-agent_1.2.0_amd64.deb" {
		t.Errorf("packages = %+v", packages)
	}

	for name, files := range map[string][]string{
		"no binary":               {"paddock-agent_1.2.0_amd64.deb", "paddock-agent_1.2.0_amd64.deb.minisig"},
		"binary without .minisig": {"amd64/paddockd"},
		"deb without .minisig":    {"amd64/paddockd", "amd64/paddockd.minisig", "paddock-agent_1.2.0_amd64.deb"},
		"deb of another release":  {"amd64/paddockd", "amd64/paddockd.minisig", "paddock-agent_1.1.0_amd64.deb"},
	} {
		dir := t.TempDir()
		write(t, dir, files...)
		if _, _, err := readReleaseDir(dir, "1.2.0"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
