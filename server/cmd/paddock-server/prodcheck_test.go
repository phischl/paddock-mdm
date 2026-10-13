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
