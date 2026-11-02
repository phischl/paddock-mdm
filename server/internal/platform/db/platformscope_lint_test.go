package db_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// platformScopeRefs lists the Go files under root that use the identifier InPlatformScope.
func platformScopeRefs(t *testing.T, root string) []string {
	t.Helper()
	var refs []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == "InPlatformScope" {
				refs = append(refs, fset.Position(id.Pos()).String())
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return refs
}

// TestPlatformScopeNotInTransport: AuditReader.InPlatformScope reads the platform pseudo-organization regardless of
// the principal, so no HTTP handler may reach it (plan M9 decision 5, amendment B1.5).
func TestPlatformScopeNotInTransport(t *testing.T) {
	root := filepath.Join("..", "..", "transport")
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("transport tree: %v", err)
	}
	if refs := platformScopeRefs(t, root); len(refs) > 0 {
		t.Errorf("InPlatformScope referenced under server/internal/transport/: %v", refs)
	}
}

func TestPlatformScopeLintDetectsReference(t *testing.T) {
	dir := t.TempDir()
	src := "package h\n\nfunc f(r interface{ InPlatformScope() }) { r.InPlatformScope() }\n"
	if err := os.WriteFile(filepath.Join(dir, "h.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if refs := platformScopeRefs(t, dir); len(refs) == 0 {
		t.Error("lint found no reference in a file that calls InPlatformScope")
	}
}
