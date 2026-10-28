package admin

import "strings"

// mcpClientMaxLen bounds the client name recorded as actor.client of the audit events of an MCP session.
const mcpClientMaxLen = 64

// sanitizeMCPClient keeps the printable ASCII characters (0x20 to 0x7E) of the X-Paddock-MCP-Client header (plan M14
// §3.4 item 22), at most 64 of them, without leading and trailing spaces; "" when none remain. The value ends up in
// immutable audit events, so nothing else may pass.
func sanitizeMCPClient(v string) string {
	out := make([]byte, 0, min(len(v), mcpClientMaxLen))
	for i := 0; i < len(v) && len(out) < mcpClientMaxLen; i++ {
		if c := v[i]; c >= 0x20 && c <= 0x7e {
			out = append(out, c)
		}
	}
	return strings.TrimSpace(string(out))
}
