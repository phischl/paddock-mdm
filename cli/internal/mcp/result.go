package mcp

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/phischl/paddock-mdm/pkg/mcpcatalog"
)

// Error codes paddockctl answers itself, next to the api's problem codes.
const (
	codeLoginRequired    = "login_required"
	codeUnreachable      = "unreachable"
	codeTooLarge         = "response_too_large"
	codeToolNotAllowed   = "mcp_tool_not_allowed"
	detailLoginRequired  = "run paddockctl mcp login"
	detailUnreachable    = "the Paddock admin API could not be reached"
	detailTooLarge       = "narrow the request (page_size, filters)"
	detailToolNotAllowed = "this tool is no longer allowed for your session; see paddockctl mcp tools"
)

// wrapper is every tool result (plan M14 §6.2): the data notice, the HTTP status and either the data or the error.
// Data is the raw JSON body, "null" for an empty one; Status is omitted when no HTTP answer exists.
type wrapper struct {
	Notice string          `json:"notice"`
	Status int             `json:"status,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
	Error  *toolError      `json:"error,omitempty"`
}

type toolError struct {
	Code       string `json:"code"`
	Detail     string `json:"detail,omitempty"`
	RequestID  string `json:"request_id,omitempty"`
	PortalPath string `json:"portal_path,omitempty"`
}

func success(status int, body []byte) *mcp.CallToolResult {
	data := json.RawMessage("null")
	if len(body) > 0 && json.Valid(body) {
		data = body
	}
	return result(wrapper{Notice: mcpcatalog.Notice, Status: status, Data: data}, false)
}

func failure(status int, e toolError) *mcp.CallToolResult {
	return result(wrapper{Notice: mcpcatalog.Notice, Status: status, Error: &e}, true)
}

// result carries the wrapper twice: as structured content and, for clients that read only text, as its JSON.
func result(w wrapper, isError bool) *mcp.CallToolResult {
	raw, err := json.Marshal(w)
	if err != nil {
		raw = fmt.Appendf(nil, `{"notice":%q,"error":{"code":"internal"}}`, mcpcatalog.Notice)
	}
	return &mcp.CallToolResult{
		Content:           []mcp.Content{&mcp.TextContent{Text: string(raw)}},
		StructuredContent: json.RawMessage(raw),
		IsError:           isError,
	}
}

// portalPath is the portal page of a refused request (plan M14 §3.5 item 27): the path without /api/v1, or
// /api/platform/v1 replaced by /platform, and without the verb of a POST /<collection>/{id}/<verb> action.
func portalPath(method, path string) string {
	var rest, prefix string
	switch {
	case strings.HasPrefix(path, "/api/platform/v1/"):
		rest, prefix = strings.TrimPrefix(path, "/api/platform/v1"), "/platform"
	case strings.HasPrefix(path, "/api/v1/"):
		rest = strings.TrimPrefix(path, "/api/v1")
	default:
		return ""
	}
	segments := strings.Split(strings.Trim(rest, "/"), "/")
	if method == "POST" && len(segments) >= 3 {
		segments = segments[:len(segments)-1]
	}
	return prefix + "/" + strings.Join(segments, "/")
}

// needsPortal reports the codes whose answer names the portal page: the step-up and every MCP refusal.
func needsPortal(code string) bool {
	return code == "step_up_required" || strings.HasPrefix(code, "mcp_")
}
