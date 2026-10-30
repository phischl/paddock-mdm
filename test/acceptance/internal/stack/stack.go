// Package stack locates the running development stack (endpoints and secrets) for the acceptance gates.
package stack

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"aead.dev/minisign"
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

// Setting returns a setting of this checkout's stack: the environment variable, else its value in deploy/compose/.env,
// else def. A second development stack of the host runs from its own checkout, whose .env names its Compose project
// and host ports (docs/operations/local-dev.md, "Running a second dev stack"); the environment wins, as for Compose.
func Setting(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	if root, err := RepoRoot(); err == nil {
		if b, err := os.ReadFile(filepath.Join(root, "deploy", "compose", ".env")); err == nil { //nolint:gosec // dev settings
			v := ""
			for _, line := range strings.Split(string(b), "\n") {
				if after, ok := strings.CutPrefix(line, name+"="); ok {
					v = strings.TrimSpace(after)
				}
			}
			if v != "" {
				return v
			}
		}
	}
	return def
}

// Project is the Compose project of the development stack (PADDOCK_PROJECT, default paddock).
func Project() string { return Setting("PADDOCK_PROJECT", "paddock") }

// HTTPSPort is the host port of Caddy (PADDOCK_HTTPS_PORT, default 8443).
func HTTPSPort() string { return Setting("PADDOCK_HTTPS_PORT", "8443") }

// Network is the Compose network name of the development stack, e.g. Network("cp").
func Network(name string) string { return Project() + "_" + name }

// publicURL is https://<host>.<PADDOCK_DOMAIN>:<port of the setting portVar>.
func publicURL(host, portVar, defPort string) string {
	return "https://" + host + "." + Setting("PADDOCK_DOMAIN", "paddock.localhost") + ":" + Setting(portVar, defPort)
}

// LoopbackURL is http://127.0.0.1:<port of the setting portVar>, a development port mapping of compose.dev.yaml.
func LoopbackURL(portVar, defPort string) string { return "http://" + loopback(portVar, defPort) }

func loopback(portVar, defPort string) string { return "127.0.0.1:" + Setting(portVar, defPort) }

// AuditS3Endpoint is the host-reachable endpoint of audit-rustfs (compose.dev.yaml maps 127.0.0.1:PADDOCK_DEV_AUDIT_S3_PORT,
// default 9001).
func AuditS3Endpoint() string {
	return Env("PADDOCK_TEST_AUDIT_S3_ENDPOINT", LoopbackURL("PADDOCK_DEV_AUDIT_S3_PORT", "9001"))
}

// AuditBucket is the WORM audit bucket.
func AuditBucket() string { return Env("PADDOCK_TEST_AUDIT_S3_BUCKET", "paddock-audit") }

// AdminURL is the portal URL (PADDOCK_TEST_ADMIN_URL overrides).
func AdminURL() string {
	return Env("PADDOCK_TEST_ADMIN_URL", publicURL("admin", "PADDOCK_HTTPS_PORT", "8443"))
}

// AdminUntrustedURL is the portal on the development stack's untrusted listener, where Caddy ignores every client
// address header (plan M7a decision 9; PADDOCK_TEST_ADMIN_UNTRUSTED_URL overrides).
func AdminUntrustedURL() string {
	return Env("PADDOCK_TEST_ADMIN_UNTRUSTED_URL", publicURL("admin", "PADDOCK_HTTPS_UNTRUSTED_PORT", "8444"))
}

// BundlesURL is the public bundles host (PADDOCK_TEST_BUNDLES_URL overrides).
func BundlesURL() string {
	return Env("PADDOCK_TEST_BUNDLES_URL", publicURL("bundles", "PADDOCK_HTTPS_PORT", "8443"))
}

// FleetURL is Fleet's public device host (PADDOCK_TEST_FLEET_URL overrides).
func FleetURL() string {
	return Env("PADDOCK_TEST_FLEET_URL", publicURL("fleet", "PADDOCK_HTTPS_PORT", "8443"))
}

// FleetAdminURL is Fleet's API on the development host (compose.dev.yaml maps 127.0.0.1:PADDOCK_DEV_FLEET_PORT,
// default 8412).
func FleetAdminURL() string {
	return Env("PADDOCK_TEST_FLEET_ADMIN_URL", LoopbackURL("PADDOCK_DEV_FLEET_PORT", "8412"))
}

// AuthURL is the Authentik URL (PADDOCK_TEST_AUTH_URL overrides).
func AuthURL() string {
	return Env("PADDOCK_TEST_AUTH_URL", publicURL("auth", "PADDOCK_HTTPS_PORT", "8443"))
}

// Compose runs `docker compose` for the development stack (all three files) and returns the combined output.
func Compose(ctx context.Context, env []string, args ...string) (string, error) {
	return compose(ctx, env, nil, args)
}

// ComposeInput is Compose with stdin, e.g. for `exec -T` into a read-only container.
func ComposeInput(ctx context.Context, stdin io.Reader, args ...string) (string, error) {
	return compose(ctx, nil, stdin, args)
}

// ComposeProduction runs `docker compose` over the production files only (without compose.dev.yaml), e.g. to check
// the configuration a production deployment gets.
func ComposeProduction(ctx context.Context, env []string, args ...string) (string, error) {
	return composeFiles(ctx, env, nil, "paddock", ".env", []string{"compose.yaml", "compose.audit.yaml"}, args)
}

func compose(ctx context.Context, env []string, stdin io.Reader, args []string) (string, error) {
	return composeFiles(ctx, env, stdin, Project(), ".env", []string{"compose.yaml", "compose.audit.yaml", "compose.auto-unseal.yaml", "compose.dev.yaml"}, args)
}

// ProdFiles returns the Compose files of a production host from deploy/compose/scripts/lib.sh (PROD_FILES_<host>,
// the single list since plan M7b decision 18), the list `./paddock check` checks on a host.
func ProdFiles(host string) ([]string, error) {
	root, err := RepoRoot()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(root, "deploy", "compose", "scripts", "lib.sh"))
	if err != nil {
		return nil, err
	}
	m := regexp.MustCompile(`(?m)^PROD_FILES_` + host + `="(.+)"$`).FindSubmatch(b)
	if m == nil {
		return nil, fmt.Errorf("no PROD_FILES_%s in deploy/compose/scripts/lib.sh", host)
	}
	return strings.Fields(string(m[1])), nil
}

// ComposeProductionHost runs `docker compose` over the production files of host with the settings template
// prod.env.example (not the development .env), e.g. `config --format json` for prod-check (plan M7a gate A4).
func ComposeProductionHost(ctx context.Context, env []string, host string, args ...string) (string, error) {
	files, err := ProdFiles(host)
	if err != nil {
		return "", err
	}
	return composeFiles(ctx, env, nil, "paddock", "prod.env.example", files, args)
}

// ComposeProductionFiles runs `docker compose` over the given files of deploy/compose with the settings template
// envFile (prod.env.example or lab.env.example), e.g. a host's files plus an overlay (plan M8u gate U5).
func ComposeProductionFiles(ctx context.Context, env []string, envFile string, files []string, args ...string) (string, error) {
	return composeFiles(ctx, env, nil, "paddock", envFile, files, args)
}

// composeFiles runs `docker compose` for project; the production helpers only render configuration and keep the
// production project name paddock.
func composeFiles(ctx context.Context, env []string, stdin io.Reader, project, envFile string, files, args []string) (string, error) {
	root, err := RepoRoot()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, "deploy", "compose")
	base := []string{"compose", "--project-directory", dir, "-p", project,
		"--env-file", filepath.Join(dir, "versions.env"), "--env-file", filepath.Join(dir, envFile)}
	for _, f := range files {
		base = append(base, "-f", filepath.Join(dir, f))
	}
	cmd := exec.CommandContext(ctx, "docker", append(base, args...)...) //nolint:gosec // test orchestration
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin = stdin
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
	u.Host = Env("PADDOCK_TEST_AUDIT_DB_HOST", loopback("PADDOCK_DEV_AUDIT_POSTGRES_PORT", "5433"))
	return u.String(), nil
}

// AuditWriterDSN is the paddock_audit_writer DSN with the host rewritten to the development port mapping: the
// isolation gate finishes the evidence exports it requested itself with it (isolation_fixtures.go).
func AuditWriterDSN() (string, error) {
	raw, err := Secret("db_paddock_audit_writer_url")
	if err != nil {
		return "", err
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	u.Host = Env("PADDOCK_TEST_AUDIT_DB_HOST", loopback("PADDOCK_DEV_AUDIT_POSTGRES_PORT", "5433"))
	return u.String(), nil
}

// PaddockOwnerDSN is the paddock_owner DSN with the host rewritten to the development port mapping: the gates that
// play a compromised database (plan M4c gate R3) write with it.
func PaddockOwnerDSN() (string, error) {
	raw, err := Secret("db_paddock_owner_url")
	if err != nil {
		return "", err
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	u.Host = Env("PADDOCK_TEST_DB_HOST", loopback("PADDOCK_DEV_POSTGRES_PORT", "5432"))
	return u.String(), nil
}

// ReleaseKey loads a minisign secret key; empty path is the development release key (make dev-release-key), which
// is stored without a password.
func ReleaseKey(path string) (minisign.PrivateKey, error) {
	return releaseKey(path, "minisign.key")
}

// RevokeReleaseKey loads the minisign secret key of paddock-revoke packages; empty path is the development
// revocation release key (plan M4c decision 4).
func RevokeReleaseKey(path string) (minisign.PrivateKey, error) {
	return releaseKey(path, "revoke-minisign.key")
}

func releaseKey(path, devFile string) (minisign.PrivateKey, error) {
	if path == "" {
		dir, err := SecretsDir()
		if err != nil {
			return minisign.PrivateKey{}, err
		}
		path = filepath.Join(dir, "release", devFile)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return minisign.PrivateKey{}, fmt.Errorf("release key (run `make dev-release-key`): %w", err)
	}
	if minisign.IsEncrypted(data) {
		return minisign.DecryptKey("", data)
	}
	var k minisign.PrivateKey
	return k, k.UnmarshalText(data)
}

// Image returns a pinned image reference of deploy/compose/versions.env, e.g. GO_BUILD_IMAGE.
func Image(name string) (string, error) {
	root, err := RepoRoot()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(filepath.Join(root, "deploy", "compose", "versions.env")) //nolint:gosec // repository file
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, name+"="); ok {
			return strings.TrimSpace(v), nil
		}
	}
	return "", fmt.Errorf("stack: %s not in versions.env", name)
}

// Docker runs docker with stdin and returns its standard output; standard error is part of a failure only.
func Docker(ctx context.Context, stdin io.Reader, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...) //nolint:gosec // test orchestration
	cmd.Stdin = stdin
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return string(out), fmt.Errorf("docker %s: %w: %s", args[0], err, stderr.String())
	}
	return string(out), nil
}
