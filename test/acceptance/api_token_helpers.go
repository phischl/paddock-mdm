package acceptance

import (
	"net/http"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// bearerTransport sends every request with an API token instead of a session cookie.
type bearerTransport struct {
	base   http.RoundTripper
	secret string
}

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.secret)
	return b.base.RoundTrip(r)
}

// tokenPortal is an admin API client that authenticates with an API token secret (plan M6c decision 9).
func tokenPortal(t *testing.T, secret string) *env.Portal {
	t.Helper()
	client, err := env.NewHTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	client.Transport = bearerTransport{base: base, secret: secret}
	return &env.Portal{User: "api token", Client: client}
}

// apiTokenCreated is the 201 body of POST /api/v1/api-tokens.
type apiTokenCreated struct {
	Token struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Prefix string `json:"prefix"`
		Role   string `json:"role"`
		Status string `json:"status"`
	} `json:"token"`
	Secret string `json:"secret"`
}

// postAPIToken sends POST /api/v1/api-tokens as p (which must have a fresh step-up to succeed).
func postAPIToken(t *testing.T, p *env.Portal, name, role string, expiresIn time.Duration) env.Response {
	t.Helper()
	return call(t, p, http.MethodPost, "/api/v1/api-tokens", map[string]any{
		"name": name, "role": role, "expires_at": time.Now().Add(expiresIn).UTC().Format(time.RFC3339),
	})
}

// apiTokenName is a unique token name (the name pattern allows no '@' and at most 64 characters).
func apiTokenName(prefix string) string { return prefix + " " + uniqueSuffix() }
