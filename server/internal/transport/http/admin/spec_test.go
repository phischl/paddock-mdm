package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/phischl/paddock-mdm/pkg/mcpcatalog"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/mcpgen"
)

func loadSpec(t *testing.T) *openapi3.T {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "..", "api", "openapi", "admin.yaml")
	doc, err := openapi3.NewLoader().LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// TestOpenAPISpec is the OpenAPI lint of `make lint`: the contract is valid OpenAPI, its audit and step-up
// annotations match the code registry and the server's table of privileged routes, and the MCP tool catalog
// matches both (ADR 0044 decision 4).
func TestOpenAPISpec(t *testing.T) {
	doc := loadSpec(t)
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatalf("api/openapi/admin.yaml is invalid: %v", err)
	}
	seen := map[string]bool{}
	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			code, ok := op.Extensions["x-paddock-audit"].(string)
			if !ok {
				continue
			}
			if !audit.Code(code).Registered() {
				t.Errorf("%s %s: x-paddock-audit %q is not in the code registry", method, path, code)
			}
			if strings.HasPrefix(path, "/api/auth/") {
				continue // the callback audits through the login use case
			}
			pattern := method + " " + path
			seen[pattern] = true
			op, ok := privileged[pattern]
			if !ok {
				t.Errorf("%s is privileged in the contract but missing from the privileged route table", pattern)
				continue
			}
			if string(op.spec.Code) != code {
				t.Errorf("%s: route table code %s, contract %s", pattern, op.spec.Code, code)
			}
		}
	}
	for pattern := range privileged {
		if !seen[pattern] {
			t.Errorf("privileged route %s has no x-paddock-audit in the contract", pattern)
		}
	}
	checkStepUpAnnotations(t, doc)
	checkMCPCatalog(t, doc)
}

// checkStepUpAnnotations keeps x-paddock-step-up equal to RequiresStepUp of the route table in both directions: the
// MCP catalog never exposes a step-up operation, so a missing flag would expose one.
func checkStepUpAnnotations(t *testing.T, doc *openapi3.T) {
	t.Helper()
	flagged := map[string]bool{}
	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			v, ok := op.Extensions["x-paddock-step-up"]
			if !ok {
				continue
			}
			pattern := method + " " + path
			if v != true {
				t.Errorf("%s: x-paddock-step-up must be true when present, got %v", pattern, v)
				continue
			}
			flagged[pattern] = true
			if route, ok := privileged[pattern]; !ok || !route.spec.RequiresStepUp {
				t.Errorf("%s carries x-paddock-step-up but its privileged route spec lacks RequiresStepUp", pattern)
			}
		}
	}
	for pattern, route := range privileged {
		if route.spec.RequiresStepUp && !flagged[pattern] {
			t.Errorf("privileged route %s requires a step-up but lacks x-paddock-step-up: true in the contract", pattern)
		}
	}
}

// checkMCPCatalog verifies the compiled catalog against the contract and the route table: the generator's table
// built from the contract equals mcpcatalog.Tools() field by field, so a stale catalog fails here; every
// exposed write tool is a privileged route so a refusal is audited, and no exposed tool needs a step-up.
func checkMCPCatalog(t *testing.T, doc *openapi3.T) {
	t.Helper()
	compareCatalog(t, doc)
	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			if slices.Contains(op.Tags, "auth") {
				continue
			}
			if tool, ok := mcpcatalog.ByName(op.OperationID); ok && tool.Pattern == method+" "+path {
				checkToolArguments(t, tool, slices.Concat(item.Parameters, op.Parameters))
			}
		}
	}
	for _, tool := range mcpcatalog.Exposed() {
		if tool.StepUp {
			t.Errorf("MCP tool %s is exposed but requires a step-up", tool.Name)
		}
		if tool.Class != mcpcatalog.ClassWrite {
			continue
		}
		if _, ok := privileged[tool.Pattern]; !ok {
			t.Errorf("exposed MCP write tool %s (%s) is not in the privileged route table", tool.Name, tool.Pattern)
		}
	}
}

// compareCatalog builds the tool table from the contract with the generator's own code and compares it with the
// compiled catalog field by field through the shared JSON encoding (the one Version hashes).
func compareCatalog(t *testing.T, doc *openapi3.T) {
	t.Helper()
	built, err := mcpgen.Build(doc)
	if err != nil {
		t.Fatalf("build the MCP catalog from the contract: %v", err)
	}
	compiled := map[string]mcpcatalog.Tool{}
	for _, tool := range mcpcatalog.Tools() {
		compiled[tool.Name] = tool
	}
	if len(built) != len(compiled) {
		t.Errorf("MCP catalog has %d tools, the contract %d non-auth operations: run make gen", len(compiled),
			len(built))
	}
	for _, want := range built {
		got, ok := compiled[want.Name]
		if !ok {
			t.Errorf("%s (%s) is missing from the MCP catalog: run make gen", want.Pattern, want.Name)
			continue
		}
		delete(compiled, want.Name)
		wantFields, gotFields := toolFields(t, want), toolFields(t, got)
		for field, w := range wantFields {
			if g := gotFields[field]; !bytes.Equal(g, w) {
				t.Errorf("%s: catalog %s is %s, the contract gives %s: run make gen", want.Name, field, g, w)
			}
		}
		if len(gotFields) != len(wantFields) {
			t.Errorf("%s: catalog has %d fields, the generator %d", want.Name, len(gotFields), len(wantFields))
		}
	}
	for name := range compiled {
		t.Errorf("MCP catalog tool %s has no operation in the contract: run make gen", name)
	}
}

func toolFields(t *testing.T, tool any) map[string]json.RawMessage {
	t.Helper()
	b, err := json.Marshal(tool)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	return fields
}

// checkToolArguments: every path and query parameter of the operation is a tool argument, path parameters required.
func checkToolArguments(t *testing.T, tool mcpcatalog.Tool, params openapi3.Parameters) {
	t.Helper()
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
		Required   []string                   `json:"required"`
	}
	if err := json.Unmarshal(tool.InputSchema, &schema); err != nil {
		t.Errorf("%s: input schema: %v", tool.Name, err)
		return
	}
	for _, ref := range params {
		p := ref.Value
		if p.In != openapi3.ParameterInPath && p.In != openapi3.ParameterInQuery {
			continue
		}
		if _, ok := schema.Properties[p.Name]; !ok {
			t.Errorf("%s: %s parameter %s is not a tool argument: run make gen", tool.Name, p.In, p.Name)
		}
		if p.In == openapi3.ParameterInPath && !slices.Contains(schema.Required, p.Name) {
			t.Errorf("%s: path parameter %s is not a required tool argument", tool.Name, p.Name)
		}
	}
}
