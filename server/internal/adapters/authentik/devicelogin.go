package authentik

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
)

// Platform-wide objects of blueprint paddock-device.yaml and of Authentik's defaults the device providers use. The
// authorization flow enforces MFA on every device approval (see the blueprint).
const (
	deviceAuthenticationFlow = "paddock-device-authentication"
	authorizationFlow        = "paddock-device-authorization"
	invalidationFlow         = "default-provider-invalidation-flow"
	signingKeyName           = "authentik Self-signed Certificate"
	// DeviceRedirectURI is registered for the authorization code grant; Himmelblau uses the device code and refresh
	// token grants (PoC M1).
	DeviceRedirectURI = "http://127.0.0.1:8765/callback"
)

// standardScopes are the managed scope mappings of the device provider. Himmelblau requests openid, profile, email
// and offline_access; Paddock's own mapping serves the scope profile (GroupsExpression).
var standardScopes = []string{
	"goauthentik.io/providers/oauth2/scope-openid", "goauthentik.io/providers/oauth2/scope-email",
	"goauthentik.io/providers/oauth2/scope-offline_access",
}

// GroupsMappingName is the name of an organization's groups claim mapping.
func GroupsMappingName(slug string) string { return "paddock-device-groups-" + slug }

// GroupsExpression is the mapping of scope profile: the standard profile claims and the groups claim with the
// user's paddock.<slug>.* groups and paddock.<slug> for members of the root group, never other organizations' or
// non-Paddock groups. It replaces Authentik's managed profile mapping, which emits every group of the user and would
// be merged into the claim. Himmelblau requests only openid, profile, email and offline_access and drops values
// containing ":" (PoC M1 C1).
func GroupsExpression(slug string) string {
	root := organization.RootGroup(slug)
	return fmt.Sprintf(`root = %q
names = {g.name for g in request.user.all_groups()}
return {
    "name": request.user.name,
    "given_name": request.user.name,
    "preferred_username": request.user.username,
    "nickname": request.user.username,
    "groups": sorted(n for n in names if n.startswith(root + ".")) + ([root] if root in names else []),
}
`, root)
}

// AccessPolicyName is the name of the expression policy bound to an organization's device application.
func AccessPolicyName(slug string) string { return organization.DeviceLoginApp(slug) + "-access" }

// AccessExpression admits members of paddock.<slug> that are not members of paddock.<slug>.locked.
func AccessExpression(slug string) string {
	return fmt.Sprintf(`names = {g.name for g in request.user.all_groups()}
return %q in names and %q not in names
`, organization.RootGroup(slug), organization.LockedGroup(slug))
}

type named struct {
	PK   any    `json:"pk"` // int for providers, string (uuid) for the other objects
	Name string `json:"name"`
}

func (n named) pk() string {
	switch v := n.PK.(type) {
	case float64:
		return strconv.FormatInt(int64(v), 10)
	case string:
		return v
	}
	return ""
}

// platformTTL is how long the pks of the platform-wide objects are reused. They are blueprint-managed or Authentik's
// defaults and change only when an object is deleted and recreated; a failed provider write forgets them earlier.
// Looking them up costs every create four flow lookups, the most expensive requests of a loaded Authentik, because
// Authentik computes each flow's cache count from its cache keys (PDK-392).
const platformTTL = time.Hour

// platformObjects are the pks of the platform-wide objects every device provider uses.
type platformObjects struct {
	authFlow, authzFlow, invalFlow, signing string
	mappings                                []string
}

// platform returns the platform-wide pks, looked up concurrently unless known for less than platformTTL; cached
// reports a reused answer. An answer without the optional invalidation flow or signing key is not kept, so the next
// call finds them once they exist.
func (c *Client) platform(ctx context.Context) (o platformObjects, cached bool, err error) {
	c.platformMu.Lock()
	known, at := c.platformCache, c.platformAt
	c.platformMu.Unlock()
	if known != nil && c.now().Sub(at) < platformTTL {
		return *known, true, nil
	}
	o = platformObjects{mappings: make([]string, len(standardScopes))}
	steps := []func(context.Context) error{
		c.lookup(&o.authFlow, "/api/v3/flows/instances/", url.Values{"slug": {deviceAuthenticationFlow}},
			"flow "+deviceAuthenticationFlow+" missing (blueprint paddock-device.yaml not applied)"),
		c.lookup(&o.authzFlow, "/api/v3/flows/instances/", url.Values{"slug": {authorizationFlow}},
			"flow "+authorizationFlow+" missing (blueprint paddock-device.yaml not applied)"),
		c.lookup(&o.invalFlow, "/api/v3/flows/instances/", url.Values{"slug": {invalidationFlow}}, ""),
		c.lookup(&o.signing, "/api/v3/crypto/certificatekeypairs/", url.Values{"name": {signingKeyName}}, ""),
	}
	for i, managed := range standardScopes {
		steps = append(steps, c.lookup(&o.mappings[i], "/api/v3/propertymappings/provider/scope/", url.Values{"managed": {managed}},
			"scope mapping "+managed+" missing"))
	}
	if err := parallel(ctx, steps...); err != nil {
		return platformObjects{}, false, err
	}
	if o.invalFlow != "" && o.signing != "" {
		c.platformMu.Lock()
		c.platformCache, c.platformAt = &o, c.now()
		c.platformMu.Unlock()
	}
	return o, false, nil
}

func (c *Client) forgetPlatform() {
	c.platformMu.Lock()
	c.platformCache = nil
	c.platformMu.Unlock()
}

// ensureDeviceLogin creates or corrects the organization's groups mapping, OAuth2 provider, application, access
// policy and its binding (plan M3a decision 5, settings of PoC M1). The objects without dependencies are handled
// concurrently. The application and its access policy binding are ensured before the provider is attached, so the
// application never admits users without the policy and the binding is off the critical path (PDK-392).
func (c *Client) ensureDeviceLogin(ctx context.Context, slug string) error {
	app := organization.DeviceLoginApp(slug)
	var platform platformObjects
	var cached bool
	var groups string
	err := parallel(ctx,
		func(ctx context.Context) (err error) {
			platform, cached, err = c.platform(ctx)
			return err
		},
		func(ctx context.Context) (err error) {
			groups, err = c.upsert(ctx, "/api/v3/propertymappings/provider/scope/", GroupsMappingName(slug), http.MethodPatch, map[string]any{
				"name": GroupsMappingName(slug), "scope_name": "profile", "description": "Paddock device groups",
				"expression": GroupsExpression(slug),
			})
			return err
		},
		func(ctx context.Context) error { return c.ensureAccess(ctx, slug, app) },
	)
	if err != nil {
		return err
	}
	provider, err := c.ensureProvider(ctx, app, platform, groups)
	if err != nil && cached {
		// An administrator may have changed a platform-wide object in Authentik; the next call looks them up again.
		c.forgetPlatform()
		// A 400 names an object recreated with a new pk within platformTTL: retry at once with fresh pks.
		var st *errStatus
		if errors.As(err, &st) && st.code == http.StatusBadRequest {
			if platform, _, err = c.platform(ctx); err != nil {
				return err
			}
			provider, err = c.ensureProvider(ctx, app, platform, groups)
		}
	}
	if err != nil {
		return err
	}
	providerPK, err := strconv.Atoi(provider)
	if err != nil {
		return fmt.Errorf("authentik: provider pk %q: %w", provider, err)
	}
	if err := c.do(ctx, http.MethodPatch, "/api/v3/core/applications/"+url.PathEscape(app)+"/",
		applicationBody(app, providerPK), nil); err != nil {
		return upstream(err)
	}
	return nil
}

// ensureProvider creates or corrects the organization's OAuth2 provider and returns its pk.
func (c *Client) ensureProvider(ctx context.Context, app string, platform platformObjects, groups string) (string, error) {
	return c.upsert(ctx, "/api/v3/providers/oauth2/", app, http.MethodPut, map[string]any{
		"name": app, "client_type": "public", "client_id": app,
		"grant_types":         []string{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token", "authorization_code"},
		"authentication_flow": platform.authFlow, "authorization_flow": platform.authzFlow, "invalidation_flow": platform.invalFlow,
		"redirect_uris": []map[string]string{{"matching_mode": "strict", "url": DeviceRedirectURI, "redirect_uri_type": "authorization"}},
		"signing_key":   platform.signing, "include_claims_in_id_token": true, "sub_mode": "hashed_user_id", "issuer_mode": "per_provider",
		"access_token_validity": "minutes=10", "refresh_token_validity": "days=30",
		// The device code lives ten minutes; Authentik's default access_code_validity of one minute let the code expire
		// before a user had signed in on the second device (lab finding L29). refresh_token_threshold is pinned to zero
		// and reset if changed by hand: with a threshold Authentik omits refresh_token from the refresh response, which
		// Himmelblau 4.0.x treats as an incomplete authentication and refuses every PIN login (RR-40).
		"access_code_validity": "minutes=10", "refresh_token_threshold": "seconds=0",
		"property_mappings": append(slices.Clone(platform.mappings), groups),
	})
}

// ensureAccess ensures the access policy, the application and the binding of the policy to the application.
func (c *Client) ensureAccess(ctx context.Context, slug, app string) error {
	var policy, appPK string
	err := parallel(ctx,
		func(ctx context.Context) (err error) {
			policy, err = c.upsert(ctx, "/api/v3/policies/expression/", AccessPolicyName(slug), http.MethodPatch, map[string]any{
				"name": AccessPolicyName(slug), "expression": AccessExpression(slug),
			})
			return err
		},
		func(ctx context.Context) (err error) {
			appPK, err = c.ensureApplication(ctx, app)
			return err
		},
	)
	if err != nil {
		return err
	}
	bindingQuery := url.Values{"target": {appPK}, "policy": {policy}}
	binding, err := c.findOne(ctx, "/api/v3/policies/bindings/", bindingQuery)
	if err != nil || binding != "" {
		return err
	}
	err = c.do(ctx, http.MethodPost, "/api/v3/policies/bindings/", map[string]any{
		"target": appPK, "policy": policy, "order": 0, "enabled": true, "timeout": 30,
	}, nil)
	if err != nil {
		// A retried POST whose answer was lost may have created it (policy, target and order are unique).
		if binding, ferr := c.findOne(ctx, "/api/v3/policies/bindings/", bindingQuery); ferr == nil && binding != "" {
			return nil
		}
		return upstream(err)
	}
	return nil
}

// lookup returns a step that stores the pk of the first match of a list query in pk; with missing set, no match is an
// error.
func (c *Client) lookup(pk *string, collection string, q url.Values, missing string) func(context.Context) error {
	return func(ctx context.Context) (err error) {
		if *pk, err = c.findOne(ctx, collection, q); err != nil {
			return err
		}
		if *pk == "" && missing != "" {
			return upstream(errors.New(missing))
		}
		return nil
	}
}

// applicationBody is the application app (slug = name); provider 0 leaves it without a provider.
func applicationBody(app string, provider int) map[string]any {
	body := map[string]any{"name": app, "slug": app, "policy_engine_mode": "all"}
	if provider != 0 {
		body["provider"] = provider
	}
	return body
}

// ensureApplication creates the application app without a provider if missing and returns its pk; ensureDeviceLogin
// attaches the provider.
func (c *Client) ensureApplication(ctx context.Context, app string) (string, error) {
	// The application list is filtered by the caller's own access (policies) for non-superusers, so the application is
	// looked up by slug.
	var existing named
	err := c.do(ctx, http.MethodGet, "/api/v3/core/applications/"+url.PathEscape(app)+"/", nil, &existing)
	var st *errStatus
	switch {
	case err == nil:
		return existing.pk(), nil
	case !errors.As(err, &st) || st.code != http.StatusNotFound:
		return "", upstream(err)
	}
	var created named
	if err := c.do(ctx, http.MethodPost, "/api/v3/core/applications/", applicationBody(app, 0), &created); err != nil {
		// A retried POST whose answer was lost may have created it (the slug is unique).
		if ferr := c.do(ctx, http.MethodGet, "/api/v3/core/applications/"+url.PathEscape(app)+"/", nil, &existing); ferr == nil {
			return existing.pk(), nil
		}
		return "", upstream(err)
	}
	return created.pk(), nil
}

// upsert finds the object name at collection and corrects it with method (PATCH, or PUT where the API needs the full
// object), or creates it; it returns the pk.
func (c *Client) upsert(ctx context.Context, collection, name, method string, body map[string]any) (string, error) {
	pk, err := c.findOne(ctx, collection, url.Values{"name": {name}})
	if err != nil {
		return "", err
	}
	if pk != "" {
		if err := c.do(ctx, method, collection+url.PathEscape(pk)+"/", body, nil); err != nil {
			return "", upstream(err)
		}
		return pk, nil
	}
	var created named
	if err := c.do(ctx, http.MethodPost, collection, body, &created); err != nil {
		// A concurrent request or a retried POST whose answer was lost may have created it (the name is unique).
		if pk, ferr := c.findOne(ctx, collection, url.Values{"name": {name}}); ferr == nil && pk != "" {
			return pk, nil
		}
		return "", upstream(err)
	}
	return created.pk(), nil
}

// findOne returns the pk of the first object of a list query, or "". Filters match exactly (name, slug, managed).
func (c *Client) findOne(ctx context.Context, collection string, q url.Values) (string, error) {
	var page struct {
		Results []named `json:"results"`
	}
	if err := c.do(ctx, http.MethodGet, collection+"?"+q.Encode(), nil, &page); err != nil {
		return "", upstream(err)
	}
	if len(page.Results) == 0 {
		return "", nil
	}
	return page.Results[0].pk(), nil
}
