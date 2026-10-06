package admin

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
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

// TestOpenAPISpec is the OpenAPI lint of `make lint`: the contract is valid OpenAPI and its audit annotations
// match the code registry and the server's table of privileged routes.
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
}
