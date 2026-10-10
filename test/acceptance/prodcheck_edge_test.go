package acceptance

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// prodCheck renders the control plane's production configuration with env set and runs paddock-server prod-check
// over it, as `make prod-check HOST=controlplane` does; it returns the checklist whatever the exit code.
func prodCheck(t *testing.T, env ...string) string {
	t.Helper()
	ctx := testContext(t, 5*time.Minute)
	env = append(env, "PADDOCK_BACKUP_S3_ENDPOINT=https://backup-s3.example.org")
	cfg, err := stack.ComposeProductionHost(ctx, env, "controlplane", "--profile", "*", "config", "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
	files, err := stack.ProdFiles("controlplane")
	if err != nil {
		t.Fatal(err)
	}
	root, err := stack.RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "go", "run", "./server/cmd/paddock-server", "prod-check", "--host", "controlplane",
		"--compose-files", strings.Join(files, ",")) //nolint:gosec // test orchestration
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=auto")
	cmd.Stdin = strings.NewReader(cfg)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil && stdout.Len() == 0 {
		t.Fatalf("prod-check: %v: %s", err, stderr.String())
	}
	return stdout.String()
}

func expectItem(t *testing.T, out, status, item, detail string) {
	t.Helper()
	if !strings.Contains(out, status+"  "+item) {
		t.Fatalf("expected %s  %s:\n%s", status, item, out)
	}
	if detail != "" && !strings.Contains(out, detail) {
		t.Fatalf("expected the detail %q:\n%s", detail, out)
	}
}

// TestProdCheckEdgeClientIP is gate A4 (plan M7a step 3, AC5, AC6): prod-check refuses a /0 trusted proxy, a client
// address header without proxies and the api's allow list bypass, and passes a valid proxy configuration.
func TestProdCheckEdgeClientIP(t *testing.T) {
	out := prodCheck(t, "PADDOCK_EDGE_TRUSTED_PROXIES=0.0.0.0/0", "PADDOCK_EDGE_CLIENT_IP_HEADER=X-Forwarded-For")
	expectItem(t, out, "FAIL", "edge client address", "0.0.0.0/0")

	out = prodCheck(t, "PADDOCK_EDGE_TRUSTED_PROXIES=", "PADDOCK_EDGE_CLIENT_IP_HEADER=CF-Connecting-IP")
	expectItem(t, out, "FAIL", "edge client address", "PADDOCK_EDGE_TRUSTED_PROXIES is empty")

	out = prodCheck(t, "PADDOCK_EDGE_TRUSTED_PROXIES=203.0.113.0/24", "PADDOCK_EDGE_CLIENT_IP_HEADER=CF-Connecting-IP")
	expectItem(t, out, "PASS", "edge client address", "")
	expectItem(t, out, "PASS", "ip allow list bypass is off", "")

	out = prodCheck(t, "PADDOCK_IP_ALLOWLIST_BYPASS=true")
	expectItem(t, out, "FAIL", "ip allow list bypass is off", "PADDOCK_IP_ALLOWLIST_BYPASS is true")
}
