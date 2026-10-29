package admin

import (
	"strings"
	"testing"
)

// TestSanitizeMCPClient: the client name keeps printable ASCII only, at most 64 characters (plan M14 §3.4 item 22).
func TestSanitizeMCPClient(t *testing.T) {
	for _, c := range []struct{ name, in, want string }{
		{"plain", "claude-code/2.1", "claude-code/2.1"},
		{"space kept", "Claude Desktop 1.0", "Claude Desktop 1.0"},
		{"empty", "", ""},
		{"control characters dropped", "claude\r\n-code\x00/\t2.1\x7f", "claude-code/2.1"},
		{"non-ASCII dropped", "clä🙂ude", "clude"},
		{"only dropped characters", "\x01\x1f\x7fé", ""},
		{"whitespace only", "   ", ""},
		{"whitespace after dropping", " \t\n ", ""},
		{"surrounding spaces trimmed", "  claude-code/2.1 ", "claude-code/2.1"},
		{"cut to 64", strings.Repeat("a", 100), strings.Repeat("a", 64)},
		{"cut after dropping", strings.Repeat("\n", 10) + strings.Repeat("b", 70), strings.Repeat("b", 64)},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := sanitizeMCPClient(c.in); got != c.want {
				t.Fatalf("sanitizeMCPClient(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
