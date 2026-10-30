package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/phischl/paddock-mdm/pkg/mcpcatalog"
)

// ToolListEntry is one line of paddockctl mcp tools.
type ToolListEntry struct {
	Name        string           `json:"name"`
	Title       string           `json:"title"`
	Class       mcpcatalog.Class `json:"class"`
	Destructive bool             `json:"destructive"`
}

// toolFor maps a catalog entry to the MCP tool definition (plan M14 §3.5 item 26). The input schema is the
// catalog's JSON Schema, unmarshalled so the SDK serves it unchanged.
func toolFor(t mcpcatalog.Tool) (*mcp.Tool, error) {
	var schema jsonschema.Schema
	if err := json.Unmarshal(t.InputSchema, &schema); err != nil {
		return nil, fmt.Errorf("input schema of %s: %w", t.Name, err)
	}
	notOpenWorld, destructive := false, t.Destructive
	return &mcp.Tool{
		Name:        t.Name,
		Title:       titleOf(t),
		Description: t.Description,
		InputSchema: &schema,
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    t.Class == mcpcatalog.ClassRead,
			DestructiveHint: &destructive,
			IdempotentHint:  t.Idempotent,
			OpenWorldHint:   &notOpenWorld,
		},
	}, nil
}

// titleOf is the operation's summary or, as the contract gives most operations none, its operationId in words:
// "listDevices" → "List devices".
func titleOf(t mcpcatalog.Tool) string {
	if s := strings.TrimSpace(t.Summary); s != "" {
		return s
	}
	var b strings.Builder
	for i, r := range t.Name {
		switch {
		case i == 0:
			b.WriteRune(unicode.ToUpper(r))
		case unicode.IsUpper(r):
			b.WriteRune(' ')
			b.WriteRune(unicode.ToLower(r))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// resolve compiles a tool's input schema for argument validation.
func resolve(tool *mcp.Tool) (*jsonschema.Resolved, error) {
	schema, ok := tool.InputSchema.(*jsonschema.Schema)
	if !ok {
		return nil, fmt.Errorf("input schema of %s is not a JSON Schema", tool.Name)
	}
	rs, err := schema.Resolve(nil)
	if err != nil {
		return nil, fmt.Errorf("input schema of %s: %w", tool.Name, err)
	}
	return rs, nil
}
