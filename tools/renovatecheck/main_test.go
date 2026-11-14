package main

import (
	"strings"
	"testing"
)

const testConfig = `{
  // comment with "quotes" and a , trailing
  "customManagers": [
    {
      "customType": "regex",
      "managerFilePatterns": ["/^deploy/compose/versions\\.env$/"],
      "matchStrings": ["^(?<depName>[A-Z0-9_]+)_IMAGE=(?<packageName>[^:@\\s]+):(?<currentValue>[^@\\s]+)@(?<currentDigest>sha256:[a-f0-9]{64})$"],
    },
    {
      "customType": "regex",
      "managerFilePatterns": ["/^compiler\\.go$/"],
      "matchStrings": ["\"PADDOCK_HIMMELBLAU_VERSION\", \"(?<currentValue>[0-9.]+)\""],
    },
  ],
}`

const compilerSrc = `l.String("PADDOCK_HIMMELBLAU_VERSION", "4.0.8")`

var digest = "sha256:" + strings.Repeat("a", 64)

func check(t *testing.T, versions, compiler string) ([]string, error) {
	t.Helper()
	cfg, err := parseConfig([]byte(testConfig))
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	return uncovered(cfg, "deploy/compose/versions.env", versions, "compiler.go", compiler)
}

func TestMatchedPinsPass(t *testing.T) {
	versions := "# comment\nPOSTGRES_IMAGE=postgres:18.6@" + digest + "\nGITLEAKS_DEFAULT_CONFIG_BYTES=1\n"
	missing, err := check(t, versions, compilerSrc)
	if err != nil || len(missing) != 0 {
		t.Fatalf("missing %v, err %v", missing, err)
	}
}

func TestUnmatchedVersionsLineFails(t *testing.T) {
	versions := "POSTGRES_IMAGE=postgres:18.6@" + digest + "\nNEWTOOL_VERSION=1.2.3\nBROKEN_IMAGE=x:1\n"
	missing, err := check(t, versions, compilerSrc)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 2 || !strings.Contains(missing[0], "NEWTOOL_VERSION") || !strings.Contains(missing[1], "BROKEN_IMAGE") {
		t.Fatalf("missing = %v", missing)
	}
}

func TestUnmatchedCompilerDefaultFails(t *testing.T) {
	missing, err := check(t, "", `l.String("PADDOCK_HIMMELBLAU_VERSION", "four")`)
	if err == nil {
		t.Fatalf("a changed constant shape must be an error, got missing %v", missing)
	}
	missing, err = check(t, "", `x := "PADDOCK_HIMMELBLAU_VERSION", "4.0.8"`+"\n")
	if err != nil || len(missing) != 0 {
		t.Fatalf("missing %v, err %v", missing, err)
	}
}

func TestManagerForOtherFileDoesNotCover(t *testing.T) {
	cfg, err := parseConfig([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := covered(cfg, "other/versions.env", "POSTGRES_IMAGE=postgres:18.6@"+digest)
	if err != nil || ok {
		t.Fatalf("ok %v err %v", ok, err)
	}
}

func TestParseRejectsUnquotedKeys(t *testing.T) {
	if _, err := parseConfig([]byte(`{ customManagers: [] }`)); err == nil {
		t.Fatal("unquoted keys are outside the supported subset")
	}
}

func TestRealRepositoryFilesAreCovered(t *testing.T) {
	t.Chdir("../..")
	if err := run("renovate.json5", "deploy/compose/versions.env", "server/cmd/paddock-server/compiler.go"); err != nil {
		t.Fatal(err)
	}
}
