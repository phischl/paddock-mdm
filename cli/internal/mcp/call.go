package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/phischl/paddock-mdm/cli/internal/client"
	"github.com/phischl/paddock-mdm/pkg/mcpcatalog"
)

// handle is the raw tool handler of every tool (plan M14 §3.5 item 27). Tool errors are results with isError; only
// invalid arguments are a protocol error (-32602).
func (s *Server) handle(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	reg, ok := s.tools[req.Params.Name]
	if !ok {
		return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: fmt.Sprintf("unknown tool %q", req.Params.Name)}
	}
	args, err := arguments(req.Params.Arguments)
	if err == nil {
		err = reg.schema.Validate(args)
	}
	if err == nil {
		err = knownArguments(reg.schema.Schema(), args)
	}
	if err != nil {
		return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: fmt.Sprintf("invalid arguments: %v", err)}
	}
	mcpClient := clientHeader(req.ClientInfo())
	allowed, err := s.allowed(ctx, reg.tool.Name, mcpClient)
	if err != nil {
		return refusal(err), nil
	}
	if !allowed {
		return failure(http.StatusForbidden, toolError{Code: codeToolNotAllowed, Detail: detailToolNotAllowed}), nil
	}
	hr, err := request(reg.tool, args)
	if err != nil {
		return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: err.Error()}
	}
	hr.Limit = maxToolResponse
	resp, err := s.send(ctx, hr, mcpClient)
	if err != nil {
		return refusal(err), nil
	}
	if resp.TooLarge {
		return failure(resp.Status, toolError{Code: codeTooLarge, Detail: detailTooLarge}), nil
	}
	if p := resp.Problem(); p != nil {
		e := toolError{Code: p.Code, Detail: p.Detail, RequestID: p.RequestID}
		if e.Code == "" {
			e.Code = "http_" + strconv.Itoa(p.Status)
		}
		if needsPortal(e.Code) {
			e.PortalPath = portalPath(hr.Method, hr.Path)
		}
		return failure(p.Status, e), nil
	}
	return success(resp.Status, resp.Body), nil
}

// refusal maps a failure without a usable answer to the tool result.
func refusal(err error) *mcp.CallToolResult {
	var p *client.Problem
	switch {
	case errors.Is(err, ErrLoginRequired):
		return failure(http.StatusUnauthorized, toolError{Code: codeLoginRequired, Detail: detailLoginRequired})
	case errors.As(err, &p):
		return failure(p.Status, toolError{Code: p.Code, Detail: p.Detail, RequestID: p.RequestID})
	default:
		return failure(0, toolError{Code: codeUnreachable, Detail: detailUnreachable})
	}
}

// knownArguments refuses names outside the schema's properties: the generated schemas leave the top level open, and
// an unknown name would otherwise reach the api as a query parameter.
func knownArguments(schema *jsonschema.Schema, args map[string]any) error {
	for name := range args {
		if _, ok := schema.Properties[name]; !ok {
			return fmt.Errorf("unknown argument %q", name)
		}
	}
	return nil
}

// arguments decodes the call's arguments as a JSON object; absent arguments are an empty object.
func arguments(raw json.RawMessage) (map[string]any, error) {
	args := map[string]any{}
	if len(raw) == 0 || string(raw) == "null" {
		return args, nil
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, errors.New("arguments must be a JSON object")
	}
	return args, nil
}

// request maps validated arguments to the admin API request: {name} segments of the path from the arguments of that
// name, the property body as the JSON body, every other argument as a query parameter (arrays repeated).
func request(t mcpcatalog.Tool, args map[string]any) (client.Request, error) {
	r := client.Request{Method: t.Method, Query: url.Values{}}
	path := t.Path
	used := map[string]bool{"body": true}
	for {
		start := strings.IndexByte(path, '{')
		if start < 0 {
			break
		}
		end := strings.IndexByte(path[start:], '}')
		if end < 0 {
			return client.Request{}, fmt.Errorf("malformed path %s", t.Path)
		}
		name := path[start+1 : start+end]
		v, ok := args[name]
		if !ok {
			return client.Request{}, fmt.Errorf("missing path parameter %s", name)
		}
		used[name] = true
		// PathEscape keeps dot segments, which would let a value such as ".." address another route.
		value := scalar(v)
		if value == "" || value == "." || value == ".." {
			return client.Request{}, fmt.Errorf("path parameter %s must not be %q", name, value)
		}
		path = path[:start] + url.PathEscape(value) + path[start+end+1:]
	}
	r.Path = path
	if b, ok := args["body"]; ok {
		raw, err := json.Marshal(b)
		if err != nil {
			return client.Request{}, err
		}
		r.Body = raw
	}
	for k, v := range args {
		if used[k] {
			continue
		}
		if list, ok := v.([]any); ok {
			for _, item := range list {
				r.Query.Add(k, scalar(item))
			}
			continue
		}
		r.Query.Set(k, scalar(v))
	}
	return r, nil
}

// scalar renders a JSON value as a path or query parameter; numbers keep their integer form.
func scalar(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	case nil:
		return ""
	default:
		raw, _ := json.Marshal(x)
		return string(raw)
	}
}

// clientHeader is X-Paddock-MCP-Client: name/version of the MCP client, printable ASCII, at most 64 characters (the
// api sanitises it the same way); unknown/0 when the client did not say.
func clientHeader(info *mcp.Implementation) string {
	v := "unknown/0"
	if info != nil && info.Name != "" {
		v = info.Name + "/" + info.Version
	}
	var b strings.Builder
	for _, r := range v {
		if r >= 0x20 && r <= 0x7e && b.Len() < 64 {
			b.WriteRune(r)
		}
	}
	return b.String()
}
