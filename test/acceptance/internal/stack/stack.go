// Package stack locates the running development stack (endpoints and secrets) for the acceptance gates.
package stack

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// RepoRoot returns the repository root (the directory containing go.work).
func RepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("stack: go.work not found above the working directory")
		}
		dir = parent
	}
}

// SecretsDir returns the development secrets directory (PADDOCK_SECRETS_DIR overrides).
func SecretsDir() (string, error) {
	if d := os.Getenv("PADDOCK_SECRETS_DIR"); d != "" {
		return d, nil
	}
	root, err := RepoRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "deploy", "compose", ".secrets"), nil
}

// Secret reads one secret file from the secrets directory, trimmed.
func Secret(name string) (string, error) {
	dir, err := SecretsDir()
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name))) //nolint:gosec // test helper reading dev secrets
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// Env returns the environment variable or the default.
func Env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// AuditS3Endpoint is the host-reachable endpoint of audit-rustfs (compose.dev.yaml maps 127.0.0.1:9001).
func AuditS3Endpoint() string { return Env("PADDOCK_TEST_AUDIT_S3_ENDPOINT", "http://127.0.0.1:9001") }

// AuditBucket is the WORM audit bucket.
func AuditBucket() string { return Env("PADDOCK_TEST_AUDIT_S3_BUCKET", "paddock-audit") }

// AdminURL is the portal URL (PADDOCK_TEST_ADMIN_URL overrides).
func AdminURL() string { return Env("PADDOCK_TEST_ADMIN_URL", "https://admin.paddock.localhost:8443") }

// AuthURL is the Authentik URL (PADDOCK_TEST_AUTH_URL overrides).
func AuthURL() string { return Env("PADDOCK_TEST_AUTH_URL", "https://auth.paddock.localhost:8443") }

// Compose runs `docker compose` for the development stack (all three files) and returns the combined output.
func Compose(ctx context.Context, env []string, args ...string) (string, error) {
	root, err := RepoRoot()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, "deploy", "compose")
	base := []string{"compose", "--project-directory", dir, "-p", "paddock",
		"--env-file", filepath.Join(dir, "versions.env"), "--env-file", filepath.Join(dir, ".env"),
		"-f", filepath.Join(dir, "compose.yaml"), "-f", filepath.Join(dir, "compose.audit.yaml"),
		"-f", filepath.Join(dir, "compose.dev.yaml")}
	cmd := exec.CommandContext(ctx, "docker", append(base, args...)...) //nolint:gosec // test orchestration
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("docker compose %s: %w: %s", strings.Join(args, " "), err, out)
	}
	return string(out), nil
}

// WaitHealthy runs deploy/compose/scripts/wait-healthy.sh for the paddock profile.
func WaitHealthy(ctx context.Context) error {
	root, err := RepoRoot()
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, filepath.Join(root, "deploy", "compose", "scripts", "wait-healthy.sh"), "--profile", "paddock") //nolint:gosec // test orchestration
	cmd.Env = append(os.Environ(), "WAIT_TIMEOUT=300")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wait-healthy: %w: %s", err, out)
	}
	return nil
}

// PaddockServer runs a paddock-server subcommand inside the audit-writer container (writer credentials) and
// returns its exit code and output.
func PaddockServer(ctx context.Context, args ...string) (int, string, error) {
	out, err := Compose(ctx, nil, append([]string{"exec", "-T", "paddock-audit-writer", "/paddock-server"}, args...)...)
	if err == nil {
		return 0, out, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), out, nil
	}
	return -1, out, err
}

// AuditIndexDSN is the paddock_audit_reader DSN with the host rewritten to the development port mapping.
func AuditIndexDSN() (string, error) {
	raw, err := Secret("db_paddock_audit_reader_url")
	if err != nil {
		return "", err
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	u.Host = Env("PADDOCK_TEST_AUDIT_DB_HOST", "127.0.0.1:5433")
	return u.String(), nil
}
