package prodcheck_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/prodcheck"
)

const mountedItem = "secrets the services reference are mounted"

// composeDir is deploy/compose of the repository.
func composeDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "..", "deploy", "compose"))
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// prodFiles reads the Compose files of a host from the Makefile (PROD_FILES_<host>), the list `make prod-check` uses.
func prodFiles(t *testing.T, host string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(composeDir(t), "..", "..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^PROD_FILES_` + host + `\s*:=\s*(.+)$`).FindSubmatch(b)
	if m == nil {
		t.Fatalf("no PROD_FILES_%s in the Makefile", host)
	}
	return strings.Fields(string(m[1]))
}

// renderConfig runs `docker compose config --format json` over files with the settings template prod.env.example.
func renderConfig(t *testing.T, files []string, envFiles ...string) prodcheck.Config {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	dir := composeDir(t)
	args := []string{"compose", "--project-directory", dir, "-p", "paddock", "--env-file", filepath.Join(dir, "versions.env")}
	for _, e := range envFiles {
		args = append(args, "--env-file", filepath.Join(dir, e))
	}
	for _, f := range files {
		args = append(args, "-f", filepath.Join(dir, f))
	}
	args = append(args, "--profile", "*", "config", "--format", "json")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...) //nolint:gosec // fixed arguments of the test
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Env = append(os.Environ(), "PADDOCK_BACKUP_S3_ENDPOINT=https://backup-s3.example.org")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("docker compose config %v: %v: %s", files, err, stderr.String())
	}
	cfg, err := prodcheck.Parse(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	// The check is about the configuration, not about the secret files of this checkout.
	for name, s := range cfg.Secrets {
		s.File = "/nonexistent/" + name
		cfg.Secrets[name] = s
	}
	return cfg
}

func mountedResult(t *testing.T, cfg prodcheck.Config) prodcheck.Result {
	t.Helper()
	for _, r := range prodcheck.Run(context.Background(), cfg, prodcheck.Options{}) {
		if r.Item == mountedItem {
			return r
		}
	}
	t.Fatalf("no item %q", mountedItem)
	return prodcheck.Result{}
}

// TestComposeConfigsMountEverySecretTheyName renders the real Compose configurations (both production hosts and the
// development stack with and without backups) and requires that every /run/secrets/ path a service names is mounted
// (regression of review 1 finding 1: the worker's backup secrets dropped by `secrets: !override`).
func TestComposeConfigsMountEverySecretTheyName(t *testing.T) {
	cases := map[string]struct {
		files    []string
		envFiles []string
	}{
		"production control plane": {prodFiles(t, "controlplane"), []string{"prod.env.example"}},
		"production audit host":    {prodFiles(t, "audit"), []string{"prod.env.example"}},
		"development":              {[]string{"compose.yaml", "compose.audit.yaml", "compose.dev.yaml"}, []string{".env.example"}},
		"development with backups": {[]string{"compose.yaml", "compose.audit.yaml", "compose.dev.yaml", "compose.backup.yaml",
			"compose.backup.dev.yaml"}, []string{".env.example"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := mountedResult(t, renderConfig(t, tc.files, tc.envFiles...))
			if !r.OK {
				t.Fatalf("%s:\n%s", r.Item, r.Detail)
			}
		})
	}
	t.Run("backup secrets reach the production worker", func(t *testing.T) {
		cfg := renderConfig(t, prodFiles(t, "controlplane"), "prod.env.example")
		mounted := map[string]bool{}
		for _, s := range cfg.Services["paddock-worker"].Secrets {
			mounted[s.Source] = true
		}
		for _, want := range []string{"backup_worker_access_key", "backup_worker_secret_key", "backup_encryption_key",
			"approle_backup_role_id", "approle_backup_secret_id", "internal_ca_bundle", "db_paddock_worker_url"} {
			if !mounted[want] {
				t.Errorf("paddock-worker does not mount %s", want)
			}
		}
	})
}
