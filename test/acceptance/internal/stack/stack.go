// Package stack locates the running development stack (endpoints and secrets) for the acceptance gates.
package stack

import (
	"errors"
	"os"
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
