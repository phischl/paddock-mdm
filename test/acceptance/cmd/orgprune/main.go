// Command orgprune deletes the leftover gate organizations of a development stack (`make dev-prune-gate-orgs`): it
// lists the organizations whose name starts with "Gate gate-" through the platform admin API and deletes each with
// grace_days 0. It refuses unless the api reports PADDOCK_ENV=development (GET /api/v1/me carries step_up only
// there), and it never touches the database (plan M17 §7 step 7).
package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

const (
	gateNamePrefix = "Gate gate-"
	orgPath        = "/api/platform/v1/organizations"
	pageSize       = 100
	deleteWait     = 5 * time.Minute
	// Below the admin API's step-up window of 5 minutes.
	stepUpAge = 3 * time.Minute
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "dev-prune-gate-orgs:", err)
		os.Exit(1)
	}
}

type org struct {
	ID       string `json:"id"`
	Slug     string `json:"slug"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	Deletion *struct {
		Step          *string `json:"step"`
		LastErrorCode *string `json:"last_error_code"`
	} `json:"deletion"`
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()

	admin, err := env.Login(ctx, env.PlatformAdmin, "")
	if err != nil {
		return fmt.Errorf("login as %s: %w (is the stack up and seeded?)", env.PlatformAdmin, err)
	}
	if err := requireDevelopment(ctx, admin); err != nil {
		return err
	}
	orgs, err := listGateOrgs(ctx, admin)
	if err != nil {
		return err
	}
	if len(orgs) == 0 {
		fmt.Println("no gate organizations to delete")
		return nil
	}
	fmt.Printf("%d gate organization(s) to delete\n", len(orgs))

	var steppedUp time.Time
	var pending []org
	failed := 0
	for _, o := range orgs {
		if steppedUp.IsZero() || time.Since(steppedUp) > stepUpAge {
			final, err := admin.StepUp(ctx, env.PlatformAdmin, "/")
			if err != nil || strings.Contains(final, "stepup=failed") {
				return fmt.Errorf("step-up of %s: %v (%s)", env.PlatformAdmin, err, final)
			}
			steppedUp = time.Now()
		}
		if o.Deletion != nil && o.Status != "deleting" {
			// A pending deletion with a grace period would only run later; cancelling lets grace_days 0 replace it.
			if res, err := admin.Do(ctx, http.MethodPost, orgPath+"/"+o.ID+"/cancel-deletion", nil); err != nil || (res.Status != http.StatusOK && res.Status != http.StatusConflict) {
				fmt.Printf("%s: cancel the pending deletion: %v HTTP %d\n", o.Slug, err, res.Status)
				failed++
				continue
			}
		}
		if o.Status == "deleting" {
			pending = append(pending, o)
			continue
		}
		res, err := admin.Do(ctx, http.MethodPost, orgPath+"/"+o.ID+"/delete",
			map[string]any{"confirm_slug": o.Slug, "reason": "make dev-prune-gate-orgs", "grace_days": 0})
		if err != nil || res.Status != http.StatusAccepted {
			fmt.Printf("%s (%s, status %s): delete: %v HTTP %d %s\n", o.Slug, o.ID, o.Status, err, res.Status, res.ProblemCode())
			failed++
			continue
		}
		pending = append(pending, o)
	}

	deadline := time.Now().Add(deleteWait)
	for _, o := range pending {
		last, err := await(ctx, admin, o.ID, deadline)
		if err != nil {
			fmt.Printf("%s (%s): %v\n", o.Slug, o.ID, err)
			failed++
			continue
		}
		fmt.Printf("%s: %s\n", o.Slug, last.Status)
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d gate organization(s) not deleted", failed, len(orgs))
	}
	fmt.Printf("deleted %d gate organization(s)\n", len(pending))
	return nil
}

func requireDevelopment(ctx context.Context, admin *env.Portal) error {
	res, err := admin.Do(ctx, http.MethodGet, "/api/v1/me", nil)
	if err != nil {
		return err
	}
	var me struct {
		StepUp *struct{} `json:"step_up"`
	}
	if res.Status != http.StatusOK || res.JSON(&me) != nil || me.StepUp == nil {
		return fmt.Errorf("refusing to run: the api does not report PADDOCK_ENV=development (GET /api/v1/me: HTTP %d); this target is for development stacks only", res.Status)
	}
	return nil
}

// listGateOrgs pages through the organizations that match the search; the list leaves out deleted ones.
func listGateOrgs(ctx context.Context, admin *env.Portal) ([]org, error) {
	var out []org
	for page := 1; ; page++ {
		q := url.Values{"q": {"gate-"}, "page": {fmt.Sprint(page)}, "page_size": {fmt.Sprint(pageSize)}, "sort": {"slug"}}
		res, err := admin.Do(ctx, http.MethodGet, orgPath+"?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		var body struct {
			Items []org `json:"items"`
		}
		if res.Status != http.StatusOK || res.JSON(&body) != nil {
			return nil, fmt.Errorf("list organizations: HTTP %d %s", res.Status, res.Body)
		}
		for _, o := range body.Items {
			if strings.HasPrefix(o.Name, gateNamePrefix) {
				out = append(out, o)
			}
		}
		if len(body.Items) < pageSize || page*pageSize >= 10000 {
			return out, nil
		}
	}
}

func await(ctx context.Context, admin *env.Portal, id string, deadline time.Time) (org, error) {
	var last org
	for {
		res, err := admin.Do(ctx, http.MethodGet, orgPath+"/"+id, nil)
		if err == nil && res.Status == http.StatusNotFound {
			return org{Status: "deleted"}, nil
		}
		if err == nil && res.Status == http.StatusOK && res.JSON(&last) == nil && last.Status == "deleted" {
			return last, nil
		}
		if time.Now().After(deadline) {
			detail := ""
			if last.Deletion != nil && last.Deletion.Step != nil {
				detail = ", step " + *last.Deletion.Step
			}
			if last.Deletion != nil && last.Deletion.LastErrorCode != nil {
				detail += ", last error " + *last.Deletion.LastErrorCode
			}
			return last, fmt.Errorf("not deleted within %s: status %q%s", deleteWait, last.Status, detail)
		}
		select {
		case <-ctx.Done():
			return last, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}
