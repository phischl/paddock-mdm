// Command devseed prepares the development stack (`make dev-seed`): it signs in as the platform admin, creates
// the organizations acme and globex through the platform API and assigns the dev users to their Authentik groups.
// It is idempotent.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/paddock-mdm/paddock/test/acceptance/internal/env"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "dev-seed:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

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

	ak, err := env.NewAuthentik()
	if err != nil {
		return err
	}
	for _, m := range []struct{ user, group string }{
		{env.Alice, "paddock:acme:admins"},
		{env.Bob, "paddock:acme:auditors"},
		{env.Carol, "paddock:globex:admins"},
	} {
		if err := ak.AddToGroup(ctx, m.user, m.group); err != nil {
			return err
		}
		fmt.Printf("%s is member of %s\n", m.user, m.group)
	}
	return nil
}
