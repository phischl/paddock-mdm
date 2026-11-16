package authentik_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/adapters/authentik"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// recoveryLinkWorld is an organization with the users dave and erin, each with an open link (dave's created twice:
// Authentik keeps the one token and its key), and tokens of dave's that are no link: an API token, an app password, an
// unexpired verification flow token of another flow (an email stage's link) and a token with the recovery intent.
func recoveryLinkWorld(t *testing.T) (*fakeAuthentik, *authentik.Client, string, string) {
	t.Helper()
	f, srv := newFake(t)
	c := client(srv)
	ctx := context.Background()
	if _, err := c.EnsureOrganization(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	dave, err := c.CreateUser(ctx, "acme", ports.NewIdentityUser{Username: "dave@acme.test", Name: "Dave"})
	if err != nil {
		t.Fatal(err)
	}
	erin, err := c.CreateUser(ctx, "acme", ports.NewIdentityUser{Username: "erin@acme.test", Name: "Erin"})
	if err != nil {
		t.Fatal(err)
	}
	for _, pk := range []string{dave, dave, erin} {
		if _, err := c.RecoveryLink(ctx, pk); err != nil {
			t.Fatal(err)
		}
	}
	d := mustAtoi(t, dave)
	f.coreTokens = append(f.coreTokens,
		&fakeToken{identifier: "dave-api", intent: "api", user: d},
		&fakeToken{identifier: "dave-app-password", intent: "app_password", user: d, expires: time.Now().Add(time.Hour)},
		&fakeToken{identifier: "ak-email-stage-dave", intent: "verification", user: d, expires: time.Now().Add(time.Hour)},
		&fakeToken{identifier: "dave-other-recovery", intent: "recovery", user: d, expires: time.Now().Add(time.Hour)})
	return f, c, dave, erin
}

func (f *fakeAuthentik) tokenIDs() []string {
	var out []string
	for _, tok := range f.coreTokens {
		out = append(out, tok.identifier)
	}
	slices.Sort(out)
	return out
}

// others are dave's tokens that are no sign-in setup link.
var others = []string{"ak-email-stage-dave", "dave-api", "dave-app-password", "dave-other-recovery"}

func linkID(pk string) string { return "uid-" + pk + "-password-reset" }

func flowToken(t *testing.T, link string) string {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("flow_token")
}

// TestRevokeRecoveryLinks (plan M12h-2 amendment f): ending an account's links deletes exactly its link token
// (<uid>-password-reset) and leaves its other flow and verification tokens, its API token, its app password and every
// other account's link; a second run finds nothing.
func TestRevokeRecoveryLinks(t *testing.T) {
	f, c, dave, erin := recoveryLinkWorld(t)
	n, err := c.RevokeRecoveryLinks(context.Background(), dave)
	if err != nil || n != 1 {
		t.Fatalf("revoke: %d %v, want 1", n, err)
	}
	want := append([]string{linkID(erin)}, others...)
	slices.Sort(want)
	if got := f.tokenIDs(); !slices.Equal(got, want) {
		t.Fatalf("tokens left %v, want %v", got, want)
	}
	if n, err := c.RevokeRecoveryLinks(context.Background(), dave); err != nil || n != 0 {
		t.Fatalf("second revoke: %d %v, want 0", n, err)
	}
}

// TestRevokeRecoveryLinksNewKey: Authentik reuses the link token's key, so without ending the old link the new link
// is the old URL; after RevokeRecoveryLinks the new link carries a new key and the old key opens nothing.
func TestRevokeRecoveryLinksNewKey(t *testing.T) {
	f, c, dave, _ := recoveryLinkWorld(t)
	ctx := context.Background()
	first, err := c.RecoveryLink(ctx, dave)
	if err != nil {
		t.Fatal(err)
	}
	again, err := c.RecoveryLink(ctx, dave)
	if err != nil || flowToken(t, again) != flowToken(t, first) {
		t.Fatalf("link without revocation %q %v, want Authentik's reused key of %q", again, err, first)
	}
	if _, err := c.RevokeRecoveryLinks(ctx, dave); err != nil {
		t.Fatal(err)
	}
	second, err := c.RecoveryLink(ctx, dave)
	if err != nil || flowToken(t, second) == flowToken(t, first) {
		t.Fatalf("link after revocation %q %v, want a new key", second, err)
	}
	for _, tok := range f.coreTokens {
		if tok.key == flowToken(t, first) {
			t.Fatalf("the old key %s still opens token %s", tok.key, tok.identifier)
		}
	}
}

// TestRevokeRecoveryLinksExpired: Authentik does not see an expired link token when it creates the next link, so the
// create collides with the token's unique identifier and fails until Authentik's cleanup. RevokeRecoveryLinks deletes
// the expired token without counting it as an ended link, and the next link is created.
func TestRevokeRecoveryLinksExpired(t *testing.T) {
	f, c, dave, _ := recoveryLinkWorld(t)
	ctx := context.Background()
	for _, tok := range f.coreTokens {
		if tok.identifier == linkID(dave) {
			tok.expires = time.Now().Add(-time.Minute)
		}
	}
	if _, err := c.RecoveryLink(ctx, dave); err == nil {
		t.Fatal("link over an expired token: created, want Authentik's failure")
	}
	if n, err := c.RevokeRecoveryLinks(ctx, dave); err != nil || n != 0 {
		t.Fatalf("revoke: %d %v, want 0", n, err)
	}
	if slices.Contains(f.tokenIDs(), linkID(dave)) {
		t.Fatalf("expired link token kept: %v", f.tokenIDs())
	}
	if _, err := c.RecoveryLink(ctx, dave); err != nil {
		t.Fatalf("link after the expired token was deleted: %v", err)
	}
}

// TestRevokeRecoveryLinksIgnoredFilter: an Authentik that ignores the filters answers every token; the adapter still
// deletes only the account's own link token.
func TestRevokeRecoveryLinksIgnoredFilter(t *testing.T) {
	f, c, dave, erin := recoveryLinkWorld(t)
	f.ignoreFilters = true
	if n, err := c.RevokeRecoveryLinks(context.Background(), erin); err != nil || n != 1 {
		t.Fatalf("revoke: %d %v, want 1", n, err)
	}
	want := append([]string{linkID(dave)}, others...)
	slices.Sort(want)
	if got := f.tokenIDs(); !slices.Equal(got, want) {
		t.Fatalf("tokens left %v, want %v", got, want)
	}
}

// TestHasSourceConnection (plan M12h-2 amendment f addendum point 1): an account with an upstream source connection
// is reported, one without is not, also when Authentik ignores the user filter; a failed listing is an error.
func TestHasSourceConnection(t *testing.T) {
	f, c, dave, erin := recoveryLinkWorld(t)
	ctx := context.Background()
	f.sourceConnections = []int{mustAtoi(t, erin)}
	for _, ignore := range []bool{false, true} {
		f.ignoreFilters = ignore
		if got, err := c.HasSourceConnection(ctx, erin); err != nil || !got {
			t.Fatalf("erin (ignore filter %v): %v %v, want connected", ignore, got, err)
		}
		if got, err := c.HasSourceConnection(ctx, dave); err != nil || got {
			t.Fatalf("dave (ignore filter %v): %v %v, want not connected", ignore, got, err)
		}
	}
	f.failOnce = map[string]int{"GET /api/v3/sources/user_connections/all/": http.StatusForbidden}
	if _, err := c.HasSourceConnection(ctx, dave); !errors.Is(err, problem.UpstreamUnavailable) {
		t.Fatalf("listing fails: %v, want upstream_unavailable", err)
	}
}

// TestHasSourceConnectionSCIM (PDK-1055): an account a SCIM source provisioned or claimed has no user source
// connection in Authentik, only a SCIM source user; it is reported as connected all the same, also when Authentik
// ignores the user__id filter, and a failed SCIM listing is an error, never "not connected".
func TestHasSourceConnectionSCIM(t *testing.T) {
	f, c, dave, erin := recoveryLinkWorld(t)
	ctx := context.Background()
	f.scimUsers = []int{mustAtoi(t, erin)}
	for _, ignore := range []bool{false, true} {
		f.ignoreFilters = ignore
		if got, err := c.HasSourceConnection(ctx, erin); err != nil || !got {
			t.Fatalf("erin (ignore filter %v): %v %v, want connected through SCIM", ignore, got, err)
		}
		if got, err := c.HasSourceConnection(ctx, dave); err != nil || got {
			t.Fatalf("dave (ignore filter %v): %v %v, want not connected", ignore, got, err)
		}
	}
	f.ignoreFilters = false
	scim := 0
	for _, r := range f.served {
		if r.method == http.MethodGet && r.path == "/api/v3/sources/scim_users/" {
			scim++
			if r.query.Get("user__id") == "" {
				t.Fatalf("SCIM listing %v without the user__id filter", r.query)
			}
		}
	}
	if scim == 0 {
		t.Fatal("no SCIM source user listing")
	}
	f.failOnce = map[string]int{"GET /api/v3/sources/scim_users/": http.StatusForbidden}
	if _, err := c.HasSourceConnection(ctx, dave); !errors.Is(err, problem.UpstreamUnavailable) {
		t.Fatalf("SCIM listing fails: %v, want upstream_unavailable", err)
	}
}

// TestUserByUsername (PDK-1055): the host command finds the account by its exact username with its direct groups; an
// unknown name is not found, and a failed read is upstream_unavailable.
func TestUserByUsername(t *testing.T) {
	f, c, dave, _ := recoveryLinkWorld(t)
	ctx := context.Background()
	u, groups, found, err := c.UserByUsername(ctx, "dave@acme.test")
	if err != nil || !found || u.PK != dave || u.Username != "dave@acme.test" || !slices.Contains(groups, "paddock.acme") {
		t.Fatalf("UserByUsername: %+v %v %v %v", u, groups, found, err)
	}
	if _, _, found, err := c.UserByUsername(ctx, "nobody@acme.test"); err != nil || found {
		t.Fatalf("unknown name: %v %v, want not found", found, err)
	}
	f.failOnce = map[string]int{"GET /api/v3/core/users/": http.StatusForbidden}
	if _, _, _, err := c.UserByUsername(ctx, "dave@acme.test"); !errors.Is(err, problem.UpstreamUnavailable) {
		t.Fatalf("read fails: %v, want upstream_unavailable", err)
	}
}

// TestRevokeRecoveryLinksFailures: a failed listing or deletion is upstream_unavailable (the caller then issues no
// link); a token gone meanwhile is not counted and not an error; an unknown account fails.
func TestRevokeRecoveryLinksFailures(t *testing.T) {
	t.Run("listing fails", func(t *testing.T) {
		f, c, dave, _ := recoveryLinkWorld(t)
		before := f.tokenIDs()
		f.failOnce = map[string]int{"GET /api/v3/core/tokens/": http.StatusForbidden}
		if _, err := c.RevokeRecoveryLinks(context.Background(), dave); !errors.Is(err, problem.UpstreamUnavailable) {
			t.Fatalf("revoke: %v, want upstream_unavailable", err)
		}
		if got := f.tokenIDs(); !slices.Equal(got, before) {
			t.Fatalf("tokens %v after a failed listing, want %v", got, before)
		}
	})
	t.Run("Authentik unavailable", func(t *testing.T) {
		f, c, dave, _ := recoveryLinkWorld(t)
		before := f.tokenIDs()
		f.failNext, f.failStatus = 10, http.StatusServiceUnavailable
		if _, err := c.RevokeRecoveryLinks(context.Background(), dave); !errors.Is(err, problem.UpstreamUnavailable) {
			t.Fatalf("revoke: %v, want upstream_unavailable", err)
		}
		if got := f.tokenIDs(); !slices.Equal(got, before) {
			t.Fatalf("tokens %v while Authentik is down, want %v", got, before)
		}
	})
	t.Run("deletion fails", func(t *testing.T) {
		f, c, dave, _ := recoveryLinkWorld(t)
		f.failOnce = map[string]int{"DELETE /api/v3/core/tokens/" + linkID(dave) + "/": http.StatusForbidden}
		if _, err := c.RevokeRecoveryLinks(context.Background(), dave); !errors.Is(err, problem.UpstreamUnavailable) {
			t.Fatalf("revoke: %v, want upstream_unavailable", err)
		}
	})
	t.Run("token gone meanwhile", func(t *testing.T) {
		f, c, dave, _ := recoveryLinkWorld(t)
		f.failOnce = map[string]int{"DELETE /api/v3/core/tokens/" + linkID(dave) + "/": http.StatusNotFound}
		if n, err := c.RevokeRecoveryLinks(context.Background(), dave); err != nil || n != 0 {
			t.Fatalf("revoke: %d %v, want 0", n, err)
		}
	})
	t.Run("unknown account", func(t *testing.T) {
		_, c, _, _ := recoveryLinkWorld(t)
		if _, err := c.RevokeRecoveryLinks(context.Background(), strconv.Itoa(999)); !errors.Is(err, problem.UpstreamUnavailable) {
			t.Fatalf("revoke: %v, want upstream_unavailable", err)
		}
	})
}
