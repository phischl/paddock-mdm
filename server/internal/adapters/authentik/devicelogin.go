package authentik

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/paddock-mdm/paddock/server/internal/domain/organization"
)

// Platform-wide objects of blueprint paddock-device.yaml and of Authentik's defaults the device providers use.
const (
	deviceAuthenticationFlow = "paddock-device-authentication"
	authorizationFlow        = "default-provider-authorization-implicit-consent"
	invalidationFlow         = "default-provider-invalidation-flow"
	signingKeyName           = "authentik Self-signed Certificate"
	// DeviceRedirectURI is registered for the authorization code grant; Himmelblau uses the device code and refresh
	// token grants (PoC M1).
	DeviceRedirectURI = "http://127.0.0.1:8765/callback"
)

// standardScopes are the managed scope mappings of the device provider; Himmelblau requests exactly these scopes.
var standardScopes = []string{
	"goauthentik.io/providers/oauth2/scope-openid", "goauthentik.io/providers/oauth2/scope-email",
	"goauthentik.io/providers/oauth2/scope-profile", "goauthentik.io/providers/oauth2/scope-offline_access",
}

// GroupsMappingName is the name of an organization's groups claim mapping.
func GroupsMappingName(slug string) string { return "paddock-device-groups-" + slug }

// GroupsExpression is the scope mapping on scope profile that emits the groups claim: the user's paddock.<slug>.*
// groups and paddock.<slug> for members of the root group, never other organizations' or non-Paddock groups.
// Himmelblau requests only openid, profile, email and offline_access and drops values containing ":" (PoC M1 C1).
func GroupsExpression(slug string) string {
	root := organization.RootGroup(slug)
	return fmt.Sprintf(`root = %q
names = {g.name for g in request.user.all_groups()}
return {"groups": sorted(n for n in names if n.startswith(root + ".")) + ([root] if root in names else [])}
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

// ensureDeviceLogin creates or corrects the organization's groups mapping, OAuth2 provider, application, access
// policy and its binding (plan M3a decision 5, settings of PoC M1).
func (c *Client) ensureDeviceLogin(ctx context.Context, slug string) error {
	app := organization.DeviceLoginApp(slug)
	authFlow, err := c.findOne(ctx, "/api/v3/flows/instances/", url.Values{"slug": {deviceAuthenticationFlow}})
	if err != nil {
		return err
	}
	if authFlow == "" {
		return upstream(fmt.Errorf("flow %s missing (blueprint paddock-device.yaml not applied)", deviceAuthenticationFlow))
	}
	authzFlow, err := c.findOne(ctx, "/api/v3/flows/instances/", url.Values{"slug": {authorizationFlow}})
	if err != nil {
		return err
	}
	invalFlow, err := c.findOne(ctx, "/api/v3/flows/instances/", url.Values{"slug": {invalidationFlow}})
	if err != nil {
		return err
	}
	signing, err := c.findOne(ctx, "/api/v3/crypto/certificatekeypairs/", url.Values{"name": {signingKeyName}})
	if err != nil {
		return err
	}
	var mappings []string
	for _, managed := range standardScopes {
		pk, err := c.findOne(ctx, "/api/v3/propertymappings/provider/scope/", url.Values{"managed": {managed}})
		if err != nil {
			return err
		}
		if pk == "" {
			return upstream(fmt.Errorf("scope mapping %s missing", managed))
		}
		mappings = append(mappings, pk)
	}
	groups, err := c.upsert(ctx, "/api/v3/propertymappings/provider/scope/", GroupsMappingName(slug), http.MethodPatch, map[string]any{
		"name": GroupsMappingName(slug), "scope_name": "profile", "description": "Paddock device groups",
		"expression": GroupsExpression(slug),
	})
	if err != nil {
		return err
	}
	provider, err := c.upsert(ctx, "/api/v3/providers/oauth2/", app, http.MethodPut, map[string]any{
		"name": app, "client_type": "public", "client_id": app,
		"grant_types":         []string{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token", "authorization_code"},
		"authentication_flow": authFlow, "authorization_flow": authzFlow, "invalidation_flow": invalFlow,
		"redirect_uris": []map[string]string{{"matching_mode": "strict", "url": DeviceRedirectURI, "redirect_uri_type": "authorization"}},
		"signing_key":   signing, "include_claims_in_id_token": true, "sub_mode": "hashed_user_id", "issuer_mode": "per_provider",
		"access_token_validity": "minutes=10", "refresh_token_validity": "days=30",
		"property_mappings": append(mappings, groups),
	})
	if err != nil {
		return err
	}
	appPK, err := c.ensureApplication(ctx, app, provider)
	if err != nil {
		return err
	}
	policy, err := c.upsert(ctx, "/api/v3/policies/expression/", AccessPolicyName(slug), http.MethodPatch, map[string]any{
		"name": AccessPolicyName(slug), "expression": AccessExpression(slug),
	})
	if err != nil {
		return err
	}
	binding, err := c.findOne(ctx, "/api/v3/policies/bindings/", url.Values{"target": {appPK}, "policy": {policy}})
	if err != nil || binding != "" {
		return err
	}
	err = c.do(ctx, http.MethodPost, "/api/v3/policies/bindings/", map[string]any{
		"target": appPK, "policy": policy, "order": 0, "enabled": true, "timeout": 30,
	}, nil)
	if err != nil {
		return upstream(err)
	}
	return nil
}

// ensureApplication creates or corrects the application app (slug = name) and returns its pk.
func (c *Client) ensureApplication(ctx context.Context, app, provider string) (string, error) {
	providerPK, err := strconv.Atoi(provider)
	if err != nil {
		return "", fmt.Errorf("authentik: provider pk %q: %w", provider, err)
	}
	body := map[string]any{"name": app, "slug": app, "provider": providerPK, "policy_engine_mode": "all"}
	// The application list is filtered by the caller's own access (policies) for non-superusers, so the application is
	// looked up by slug.
	var existing named
	err = c.do(ctx, http.MethodGet, "/api/v3/core/applications/"+url.PathEscape(app)+"/", nil, &existing)
	var st *errStatus
	switch {
	case err == nil:
		if err := c.do(ctx, http.MethodPatch, "/api/v3/core/applications/"+url.PathEscape(app)+"/", body, nil); err != nil {
			return "", upstream(err)
		}
		return existing.pk(), nil
	case !errors.As(err, &st) || st.code != http.StatusNotFound:
		return "", upstream(err)
	}
	var created named
	if err := c.do(ctx, http.MethodPost, "/api/v3/core/applications/", body, &created); err != nil {
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
