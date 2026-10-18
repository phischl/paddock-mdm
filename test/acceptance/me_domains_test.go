package acceptance

import (
	"net/http"
	"slices"
	"testing"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// TestMeOrganizationDomains (plan M8x decision 15): GET /api/v1/me names the domains of the administrator's
// organization, the same list the platform administrator sees; a platform administrator has no organization.
func TestMeOrganizationDomains(t *testing.T) {
	root := login(t, env.PlatformAdmin)
	res := call(t, root, http.MethodGet, "/api/platform/v1/organizations?page_size=100&q=acme", nil)
	expectStatus(t, res, http.StatusOK, "")
	var page struct {
		Items []struct {
			Slug    string   `json:"slug"`
			Domains []string `json:"domains"`
		} `json:"items"`
	}
	if err := res.JSON(&page); err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, o := range page.Items {
		if o.Slug == "acme" {
			want = o.Domains
		}
	}
	if len(want) == 0 {
		t.Fatal("acme has no domains (run make dev-seed)")
	}

	var m struct {
		Organization *struct {
			Domains []string `json:"domains"`
		} `json:"organization"`
	}
	res = call(t, login(t, env.Alice), http.MethodGet, "/api/v1/me", nil)
	expectStatus(t, res, http.StatusOK, "")
	if err := res.JSON(&m); err != nil {
		t.Fatal(err)
	}
	if m.Organization == nil || !slices.Equal(m.Organization.Domains, want) {
		t.Fatalf("alice's organization %+v, want domains %v", m.Organization, want)
	}

	m.Organization = nil
	res = call(t, root, http.MethodGet, "/api/v1/me", nil)
	expectStatus(t, res, http.StatusOK, "")
	if err := res.JSON(&m); err != nil || m.Organization != nil {
		t.Fatalf("platform administrator's organization %+v, %v", m.Organization, err)
	}
}
