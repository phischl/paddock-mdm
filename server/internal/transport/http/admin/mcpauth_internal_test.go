package admin

import (
	"strings"
	"testing"
)

// TestIsJWT keeps the bearer dispatch of plan M14 §3.3 item 14: only three non-empty segments in canonical base64url
// are MCP access tokens; API tokens, other encodings and anything else are not.
func TestIsJWT(t *testing.T) {
	for secret, want := range map[string]bool{
		"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln": true,
		"YQ.Yg.Yw-_":                     true,
		"YR.Yg.Yw":                       false, // spare bits set: not the canonical encoding
		"YQ.Yg.Y":                        false, // a single character is no base64
		"YQ.Yg.Yw\n":                     false,
		"YQ.Y\ng.Yw":                     false,
		"YQ.Yg.Yw==":                     false,
		"a.b":                            false,
		"YQ..Yw":                         false,
		"YQ.Yg.Yw.YQ":                    false,
		"YQ.Yg+.Yw":                      false,
		"YQ.Yg.Yw\t":                     false,
		"pdk_" + strings.Repeat("A", 43): false,
		"":                               false,
	} {
		if got := isJWT(secret); got != want {
			t.Errorf("isJWT(%q) = %v, want %v", secret, got, want)
		}
	}
}

// TestMCPSessionID: the session id is "mcp:" and the hex SHA-256 of the token, never the token.
func TestMCPSessionID(t *testing.T) {
	id := mcpSessionID("a.b.c")
	if id != "mcp:845e30448809e2bc8958eb025bfc795235d13b077a53d0c3abbd2385170dc9b8" {
		t.Fatalf("mcpSessionID = %q", id)
	}
	if strings.Contains(id, "a.b.c") || mcpSessionID("a.b.d") == id {
		t.Fatalf("mcpSessionID = %q", id)
	}
}
