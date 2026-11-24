// Command loadenrol creates the enrollment tokens of the load test organization (`make load-enrol-configs`, docs/
// operations/capacity.md, "Method" step 1): it signs in as the platform admin exactly like `make dev-seed`, creates the
// organization if it is missing, signs in as a throw-away administrator of it, creates auto-approving enrollment
// tokens and writes their enrollment configurations to bin/load/token-<i>.json for `make load-identities`. The
// configurations are the only output; no credential is printed or written.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

const (
	orgsPath   = "/api/platform/v1/organizations"
	tokensPath = "/api/v1/enrollment-tokens"
	// maxUses is the API's limit of devices per enrollment token.
	maxUses = 1000
	// tokenLifetime covers a measurement run with its enrolment and retries.
	tokenLifetime = 24 * time.Hour
)

// slugPattern is the API's organization slug pattern.
var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$`)

// api is the part of an env.Portal the command uses.
type api interface {
	Do(ctx context.Context, method, path string, body any) (env.Response, error)
}

func main() {
	// An interrupted run still reaches the deferred deletion of the throw-away administrator.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stdout)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "load-enrol-configs:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("loadenrol", flag.ContinueOnError)
	org := fs.String("org", "load-enrol", "slug of the load organization, created if missing")
	tokens := fs.Int("tokens", 10, "number of enrollment tokens")
	uses := fs.Int("uses", maxUses, "devices per token (1 to 1000)")
	dir := fs.String("out-dir", "", "output directory, default bin/load of the repository")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := validate(*org, *tokens, *uses); err != nil {
		return err
	}
	if *dir == "" {
		root, err := stack.RepoRoot()
		if err != nil {
			return err
		}
		*dir = filepath.Join(root, "bin", "load")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	platform, err := env.Login(ctx, env.PlatformAdmin, "")
	if err != nil {
		return fmt.Errorf("login as %s: %w", env.PlatformAdmin, err)
	}
	if err := ensureOrg(ctx, platform, *org, out); err != nil {
		return err
	}
	admin, cleanup, err := orgAdmin(ctx, *org)
	if err != nil {
		return err
	}
	defer cleanup()

	cfgs, err := createTokens(ctx, admin, *org, *tokens, *uses)
	if err != nil {
		return err
	}
	if err := writeConfigs(*dir, cfgs); err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote %d enrollment configurations of organization %s (%d uses each) to %s\n", len(cfgs), *org, *uses, *dir)
	return nil
}

func validate(org string, tokens, uses int) error {
	switch {
	case !slugPattern.MatchString(org):
		return fmt.Errorf("organization %q does not match %s", org, slugPattern)
	case tokens < 1:
		return errors.New("tokens must be at least 1")
	case uses < 1 || uses > maxUses:
		return fmt.Errorf("uses must be between 1 and %d", maxUses)
	}
	return nil
}

// ensureOrg creates the organization; one that exists already is used as it is.
func ensureOrg(ctx context.Context, platform api, slug string, out io.Writer) error {
	res, err := platform.Do(ctx, http.MethodPost, orgsPath, map[string]string{"slug": slug, "name": "Load " + slug})
	if err != nil {
		return err
	}
	switch {
	case res.Status == http.StatusCreated || res.Status == http.StatusOK:
		fmt.Fprintf(out, "organization %s created\n", slug)
	case res.Status == http.StatusConflict && res.ProblemCode() == "slug_taken":
		fmt.Fprintf(out, "organization %s exists\n", slug)
	default:
		return fmt.Errorf("create organization %s: HTTP %d: %s", slug, res.Status, res.Body)
	}
	return nil
}

// orgAdmin signs in a throw-away administrator of the organization, so the load organization never shares an
// administrator with acme or globex; the returned function deletes the user again. Its password lives in memory only.
func orgAdmin(ctx context.Context, slug string) (*env.Portal, func(), error) {
	ak, err := env.NewAuthentik()
	if err != nil {
		return nil, nil, err
	}
	suffix, err := randomHex(6)
	if err != nil {
		return nil, nil, err
	}
	password, err := randomHex(24)
	if err != nil {
		return nil, nil, err
	}
	username := "load-enrol-" + suffix + "@acceptance.test"
	pk, err := ak.CreateUser(ctx, username, password, env.RoleGroup(slug, "admins"))
	cleanup := func() {
		if pk != 0 {
			dctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if err := ak.DeleteUser(dctx, pk); err != nil {
				fmt.Fprintf(os.Stderr, "load-enrol-configs: WARNING: delete the administrator %s by hand (Authentik user %d): %v\n", username, pk, err)
			}
		}
	}
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("create administrator of %s: %w", slug, err)
	}
	p, err := env.Login(ctx, username, password)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("login as administrator of %s: %w", slug, err)
	}
	return p, cleanup, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// createTokens creates n auto-approving tokens and returns their enrollment configurations.
func createTokens(ctx context.Context, admin api, slug string, n, uses int) ([]json.RawMessage, error) {
	stamp := time.Now().UTC().Format("20060102-150405")
	cfgs := make([]json.RawMessage, 0, n)
	for i := 1; i <= n; i++ {
		res, err := admin.Do(ctx, http.MethodPost, tokensPath, map[string]any{
			"name":         fmt.Sprintf("load %s %s #%d", slug, stamp, i),
			"expires_at":   time.Now().Add(tokenLifetime).UTC().Format(time.RFC3339),
			"max_uses":     uses,
			"auto_approve": true,
		})
		if err != nil {
			return nil, err
		}
		if res.Status != http.StatusCreated {
			// The body of a failed request names no secret; a created token's body is never printed.
			return nil, fmt.Errorf("create token %d: HTTP %d: %s", i, res.Status, res.ProblemCode())
		}
		var created struct {
			Config json.RawMessage `json:"enrollment_config"`
		}
		if err := res.JSON(&created); err != nil || len(created.Config) == 0 {
			return nil, fmt.Errorf("create token %d: no enrollment configuration in the answer", i)
		}
		cfgs = append(cfgs, created.Config)
	}
	return cfgs, nil
}

// writeConfigs writes token-1.json … token-N.json, readable by the owner only.
func writeConfigs(dir string, cfgs []json.RawMessage) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	// Configurations of an earlier, larger run would be taken for fresh tokens.
	old, err := filepath.Glob(filepath.Join(dir, "token-*.json"))
	if err != nil {
		return err
	}
	for _, f := range old {
		if err := os.Remove(f); err != nil {
			return fmt.Errorf("remove %s: %w", f, err)
		}
	}
	for i, c := range cfgs {
		f := filepath.Join(dir, fmt.Sprintf("token-%d.json", i+1))
		if err := os.WriteFile(f, c, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", f, err)
		}
	}
	return nil
}
