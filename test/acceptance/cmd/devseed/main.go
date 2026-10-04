// Command devseed prepares the development stack (`make dev-seed`): it signs in as the platform admin, creates
// the organizations acme and globex through the platform API and assigns the dev users to their Authentik groups.
// It waits until Authentik has applied the Paddock blueprints and the login flow is executable, and is idempotent.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/paddock-mdm/paddock/test/acceptance/internal/authflow"
	"github.com/paddock-mdm/paddock/test/acceptance/internal/env"
	"github.com/paddock-mdm/paddock/test/acceptance/internal/stack"
)

// blueprintDirs maps the Paddock blueprint directories of the repository to their mount points below /blueprints in
// the Authentik containers (compose.yaml, compose.dev.yaml).
var blueprintDirs = map[string]string{
	"deploy/compose/authentik/blueprints": "paddock",
	"deploy/compose/authentik/dev":        "paddock-dev",
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "dev-seed:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	ak, err := env.NewAuthentik()
	if err != nil {
		return err
	}
	// The worker applies the blueprints after start-up; the login flow can be executable before the last blueprint
	// (users, group memberships, the MFA-less dev login) has been applied.
	if err := waitBlueprints(ctx, ak, 300*time.Second, 3*time.Second); err != nil {
		return err
	}

	// A separate client, so the readiness probe leaves no flow state in the login session.
	probe, err := env.NewHTTPClient()
	if err != nil {
		return err
	}
	if err := authflow.WaitReady(ctx, probe, stack.AuthURL(), "paddock-admin-login", 180*time.Second, 3*time.Second); err != nil {
		return err
	}

	admin, err := env.Login(ctx, env.PlatformAdmin, "")
	if err != nil {
		return fmt.Errorf("login as %s: %w", env.PlatformAdmin, err)
	}
	for _, org := range []struct{ slug, name string }{{"acme", "Acme Corporation"}, {"globex", "Globex Corporation"}} {
		res, err := admin.Do(ctx, http.MethodPost, "/api/platform/v1/organizations", map[string]string{"slug": org.slug, "name": org.name})
		if err != nil {
			return err
		}
		switch {
		case res.Status == http.StatusCreated || res.Status == http.StatusOK:
			fmt.Printf("organization %s ready (HTTP %d)\n", org.slug, res.Status)
		case res.Status == http.StatusConflict && res.ProblemCode() == "slug_taken":
			fmt.Printf("organization %s exists\n", org.slug)
		default:
			return fmt.Errorf("create organization %s: HTTP %d: %s", org.slug, res.Status, res.Body)
		}
	}

	for _, m := range []struct{ user, group string }{
		{env.Alice, env.RoleGroup("acme", "admins")},
		{env.Bob, env.RoleGroup("acme", "auditors")},
		{env.Carol, env.RoleGroup("globex", "admins")},
	} {
		if err := ak.AddToGroup(ctx, m.user, m.group); err != nil {
			return err
		}
		fmt.Printf("%s is member of %s\n", m.user, m.group)
	}
	return nil
}

// blueprintSource is the part of the Authentik API the blueprint wait reads (env.Authentik).
type blueprintSource interface {
	Blueprint(ctx context.Context, path string) (env.Blueprint, bool, error)
}

// waitBlueprints waits until every Paddock blueprint file has been discovered and applied successfully by Authentik,
// polling every interval until timeout.
func waitBlueprints(ctx context.Context, ak blueprintSource, timeout, interval time.Duration) error {
	paths, err := paddockBlueprints()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	pending, lastErr := paths, error(nil)
	for {
		current, err := pendingBlueprints(ctx, ak, paths)
		if err == nil && len(current) == 0 {
			return nil
		}
		if err != nil {
			lastErr = err
		} else {
			pending = current
		}
		select {
		case <-ctx.Done():
			msg := fmt.Sprintf("authentik blueprints not applied after %s: %s", timeout, strings.Join(pending, "; "))
			if lastErr != nil {
				return fmt.Errorf("%s (last API error: %w)", msg, lastErr)
			}
			return errors.New(msg)
		case <-time.After(interval):
		}
	}
}

// paddockBlueprints returns the Paddock blueprint files as Authentik names them (paths relative to /blueprints).
func paddockBlueprints() ([]string, error) {
	root, err := stack.RepoRoot()
	if err != nil {
		return nil, err
	}
	var paths []string
	for dir, mount := range blueprintDirs {
		files, err := filepath.Glob(filepath.Join(root, dir, "*.yaml"))
		if err != nil {
			return nil, err
		}
		if len(files) == 0 {
			return nil, fmt.Errorf("no blueprints in %s", dir)
		}
		for _, f := range files {
			paths = append(paths, mount+"/"+filepath.Base(f))
		}
	}
	slices.Sort(paths)
	return paths, nil
}

// pendingBlueprints describes every blueprint that is not applied successfully yet as "<name> (<path>): <status>".
func pendingBlueprints(ctx context.Context, ak blueprintSource, paths []string) ([]string, error) {
	var pending []string
	for _, p := range paths {
		b, ok, err := ak.Blueprint(ctx, p)
		if err != nil {
			return nil, err
		}
		switch {
		case !ok:
			pending = append(pending, p+": not discovered")
		case b.Status != "successful":
			pending = append(pending, fmt.Sprintf("%s (%s): %s", b.Name, p, b.Status))
		}
	}
	return pending, nil
}
