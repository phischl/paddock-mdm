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

// prodCheckHost renders the production configuration of host (plus the automatic-unseal overlay when overlay is set)
// from envFile with env and runs paddock-server prod-check over it, as `./paddock check` does; it returns the
// checklist and the exit code.
func prodCheckHost(t *testing.T, host, envFile string, overlay bool, env ...string) (string, int) {
	t.Helper()
	ctx := testContext(t, 5*time.Minute)
	env = append(env, "PADDOCK_BACKUP_S3_ENDPOINT=https://backup-s3.example.org")
	files, err := stack.ProdFiles(host)
	if err != nil {
		t.Fatal(err)
	}
	if overlay {
		files = append(files, "compose.auto-unseal.yaml")
	}
	cfg, err := stack.ComposeProductionFiles(ctx, env, envFile, files, "--profile", "*", "config", "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
	root, err := stack.RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "go", "run", "./server/cmd/paddock-server", "prod-check", "--host", host,
		"--compose-files", strings.Join(files, ",")) //nolint:gosec // test orchestration
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=auto")
	cmd.Stdin = strings.NewReader(cfg)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	if err != nil && stdout.Len() == 0 {
		t.Fatalf("prod-check: %v: %s", err, stderr.String())
	}
	return stdout.String(), cmd.ProcessState.ExitCode()
}

// TestProdCheckAutoUnseal is gate U5 (plan M8u §9): the item openbao auto-unseal warns on a production control plane
// with automatic unseal, fails for the overlay without the switch, passes by default and passes on a lab host with
// automatic unseal; the warning never decides the exit code.
func TestProdCheckAutoUnseal(t *testing.T) {
	out, _ := prodCheckHost(t, "controlplane", "prod.env.example", true, "PADDOCK_AUTO_UNSEAL=yes")
	expectItem(t, out, "WARN", "openbao auto-unseal", "RR-43")
	if strings.Contains(out, "FAIL  openbao auto-unseal") {
		t.Fatalf("the warning is also a failure:\n%s", out)
	}

	out, _ = prodCheckHost(t, "controlplane", "prod.env.example", true, "PADDOCK_AUTO_UNSEAL=no")
	expectItem(t, out, "FAIL", "openbao auto-unseal", "PADDOCK_AUTO_UNSEAL is not yes")

	out, _ = prodCheckHost(t, "controlplane", "prod.env.example", false)
	expectItem(t, out, "PASS", "openbao auto-unseal", "automatic unseal is off")

	out, _ = prodCheckHost(t, "lab", "lab.env.example", true, "PADDOCK_AUTO_UNSEAL=yes")
	expectItem(t, out, "PASS", "openbao auto-unseal", "RR-43")
}
