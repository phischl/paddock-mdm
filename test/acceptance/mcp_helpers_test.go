package acceptance

import (
	"encoding/base64"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/authflow"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// mcpClientID is the public Authentik client of the MCP login (ADR 0044).
const mcpClientID = "paddock-mcp"

// mcpDeviceTokens runs the device authorization grant of `paddockctl mcp login` for a dev user and returns the tokens.
func mcpDeviceTokens(t *testing.T, user string) authflow.Tokens {
	t.Helper()
	ctx := testContext(t, 3*time.Minute)
	hc := authHTTP(t)
	da, err := authflow.StartDeviceScopes(ctx, hc, stack.AuthURL(), mcpClientID, authflow.MCPScopes)
	if err != nil {
		t.Fatalf("device authorization: %v", err)
	}
	secrets, err := stack.SecretsDir()
	if err != nil {
		t.Fatal(err)
	}
	password, err := env.Password(user)
	if err != nil {
		t.Fatal(err)
	}
	totp, err := env.TOTP(user)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authflow.ApproveDevice(ctx, filepath.Join(secrets, "caddy-root.crt"), da, user, password, totp); err != nil {
		t.Fatalf("approve device login of %s: %v", user, err)
	}
	tokens, err := authflow.PollDeviceToken(ctx, hc, stack.AuthURL(), mcpClientID, da, time.Minute)
	if err != nil {
		t.Fatalf("device token of %s: %v", user, err)
	}
	return tokens
}

// mcpSession presents an ID and access token pair to the MCP session call.
func mcpSession(t *testing.T, idToken, accessToken string) env.Response {
	t.Helper()
	res, err := env.Call(testContext(t, time.Minute), authHTTP(t), http.MethodPost, stack.AdminURL()+"/api/auth/mcp/session",
		map[string]string{"id_token": idToken, "access_token": accessToken}, false)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// mcpLogout ends the MCP session of an access token when the case ends.
func mcpLogout(t *testing.T, accessToken string) {
	t.Cleanup(func() {
		req, err := http.NewRequest(http.MethodPost, stack.AdminURL()+"/api/auth/mcp/logout", nil)
		if err != nil {
			return
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)
		if res, err := authHTTP(t).Do(req); err == nil {
			_ = res.Body.Close()
		}
	})
}

// forgedJWT is a canonical compact JWT whose signature no issuer made.
func forgedJWT() string {
	seg := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	return seg(`{"alg":"RS256","typ":"JWT","kid":"a3"}`) + "." + seg(`{"sub":"a3","aud":"paddock-mcp"}`) + "." + seg("a3-signature")
}
