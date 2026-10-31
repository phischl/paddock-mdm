package acceptance

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// TestAuthenticatorClassMappingsWithoutToken (PDK-618): Authentik evaluates every scope mapping of a provider without
// a token when it answers the provider's discovery document (claims_supported), which the api fetches for the portal,
// step-up and MCP issuers. The authenticator classes mappings must evaluate there without error: an exception is a
// property_mapping_exception event in Authentik and drops paddock_mfa_classes from claims_supported.
func TestAuthenticatorClassMappingsWithoutToken(t *testing.T) {
	ctx := testContext(t, time.Minute)
	start := time.Now().Add(-time.Second)
	ak, err := env.NewAuthentik()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Paddock: sign-in authenticator classes", "Paddock: step-up authenticator classes"} {
		ok, result, err := ak.TestPropertyMapping(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		if !ok || strings.ReplaceAll(result, " ", "") != `{"paddock_mfa_classes":[]}` {
			t.Errorf("mapping %q without a token: successful %v, result %s", name, ok, result)
		}
	}

	hc, err := env.NewHTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	for _, app := range []string{"paddock-portal", "paddock-portal-stepup", "paddock-mcp"} {
		res, err := env.Call(ctx, hc, http.MethodGet, stack.AuthURL()+"/application/o/"+app+"/.well-known/openid-configuration",
			nil, false)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			ClaimsSupported []string `json:"claims_supported"`
		}
		if res.Status != http.StatusOK || json.Unmarshal(res.Body, &doc) != nil {
			t.Fatalf("discovery of %s: HTTP %d: %s", app, res.Status, res.Body)
		}
		if !slices.Contains(doc.ClaimsSupported, "paddock_mfa_classes") {
			t.Errorf("discovery of %s: claims_supported %v lacks paddock_mfa_classes", app, doc.ClaimsSupported)
		}
	}

	var events struct {
		Results []struct {
			Created time.Time      `json:"created"`
			Context map[string]any `json:"context"`
		} `json:"results"`
	}
	if err := ak.Get(ctx, "/events/events/?action=property_mapping_exception&ordering=-created&page_size=100", &events); err != nil {
		t.Fatal(err)
	}
	for _, e := range events.Results {
		if expr, _ := e.Context["expression"].(string); e.Created.After(start) && strings.Contains(expr, "paddock_mfa_classes") {
			t.Errorf("property_mapping_exception at %s: %v", e.Created, e.Context["message"])
		}
	}
}
