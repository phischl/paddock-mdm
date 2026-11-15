package db_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// TestInDeletedOrgOnlyInDeletedOrgAudit enforces plan M17 decision 18: InDeletedOrg and InDeletedOrgWrite, the only
// functions that open an organization context from an ID that is not the principal's, are used by app.DeletedOrgAudit
// alone. Tests are exempt.
func TestInDeletedOrgOnlyInDeletedOrgAudit(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	fset := token.NewFileSet()
	var refs []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "web" || d.Name() == "node_modules" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		rel := filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator)))
		ast.Inspect(file, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && (id.Name == "InDeletedOrg" || id.Name == "InDeletedOrgWrite") {
				refs = append(refs, rel)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range refs {
		seen[r] = true
		if r != "internal/app/deletedorgaudit.go" && r != "internal/platform/db/db.go" {
			t.Errorf("InDeletedOrg referenced outside app.DeletedOrgAudit: %s", r)
		}
	}
	if !seen["internal/app/deletedorgaudit.go"] || !seen["internal/platform/db/db.go"] {
		t.Fatalf("the walk found %v; it no longer sees the definition and its user", refs)
	}
}
