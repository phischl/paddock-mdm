package cmd_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/cli/internal/cmd"
	"github.com/phischl/paddock-mdm/cli/internal/evidencetest"
)

// runOffline runs paddockctl with an empty HOME and no PADDOCK_* variables: the command must not need either.
func runOffline(t *testing.T, args ...string) run {
	t.Helper()
	home := t.TempDir()
	var out, errOut bytes.Buffer
	code := cmd.Main(context.Background(), cmd.Env{Args: args, Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errOut,
		Getenv: func(k string) string {
			if k == "HOME" {
				return home
			}
			return ""
		}, Version: "1.2.3"})
	return run{code, out.String(), errOut.String()}
}

func TestAuditVerifyExport(t *testing.T) {
	p := evidencetest.Assemble(t, [][]evidencetest.ObjSpec{{{Lines: evidencetest.GoodLines(2)}}, {{Lines: evidencetest.GoodLines(1)}}}, -1)
	path := p.File()

	r := runOffline(t, "audit", "verify-export", path, "--fingerprint", p.Fingerprint())
	if r.code != 0 || !strings.HasPrefix(r.stdout, "OK "+evidencetest.Org+" 2026-03-30..2026-03-31: 2 days, 2 objects, 3 events;") {
		t.Fatalf("valid: %+v", r)
	}
	if r := runOffline(t, "audit", "verify-export", "--fingerprint", p.Fingerprint(), path); r.code != 0 {
		t.Fatalf("flags before the file: %+v", r)
	}

	r = runOffline(t, "audit", "verify-export", path, "--fingerprint", strings.Repeat("0", 64))
	if r.code != cmd.ExitError || !strings.Contains(r.stdout, "FAIL signing key fingerprint differs from --fingerprint") {
		t.Fatalf("fingerprint: %+v", r)
	}

	r = runOffline(t, "audit", "verify-export", path, "-o", "json")
	var out struct {
		OK             bool   `json:"ok"`
		OrganizationID string `json:"organization_id"`
		Events         int    `json:"events"`
		KeyVersion     int    `json:"key_version"`
		Server         struct {
			OK bool `json:"ok"`
		} `json:"server_verification"`
		Problems []string `json:"problems"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &out); err != nil || r.code != 0 || !out.OK || out.Events != 3 || out.KeyVersion != 2 ||
		!out.Server.OK || out.Problems == nil {
		t.Fatalf("json: %v %+v", err, r)
	}

	p.Remove("manifests/2026-03-31.json")
	r = runOffline(t, "audit", "verify-export", p.File(), "-o", "json")
	if r.code != cmd.ExitError || json.Unmarshal([]byte(r.stdout), &out) != nil || out.OK || len(out.Problems) == 0 {
		t.Fatalf("tampered json: %+v", r)
	}
}

func TestAuditVerifyExportUsageErrors(t *testing.T) {
	notTar := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(notTar, []byte(strings.Repeat("plain text ", 100)), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"audit"}, {"audit", "verify-export"}, {"audit", "verify-export", "a", "b"},
		{"audit", "verify-export", notTar}, {"audit", "verify-export", filepath.Join(t.TempDir(), "missing")},
		{"audit", "verify-export", notTar, "-o", "yaml"}, {"audit", "verify-export", notTar, "--bogus"}} {
		if r := runOffline(t, args...); r.code != cmd.ExitUsage {
			t.Errorf("%q: %+v", args, r)
		}
	}
}
