package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestWorkerOpensNoAuditDatabase enforces the isolation of plan M17 amendment 2026-11-15 o: the worker learns the
// final audit verification from the audit writer's acknowledgement on paddock.offboarding, never from the audit
// database. No function of this package that serveWorker reaches names an audit database connection string
// (PADDOCK_AUDIT_DB_*) or opens an audit pool.
func TestWorkerOpensNoAuditDatabase(t *testing.T) {
	fset := token.NewFileSet()
	funcs := map[string]*ast.FuncDecl{}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil {
				funcs[fn.Name.Name] = fn
			}
		}
	}
	if funcs["serveWorker"] == nil || funcs["loadAuditDeps"] == nil {
		t.Fatal("serveWorker or loadAuditDeps not found; the test no longer sees the wiring")
	}
	forbiddenCalls := map[string]bool{"NewAuditReader": true, "NewAuditWriterPool": true, "loadAuditDeps": true}
	seen := map[string]bool{}
	queue := []string{"serveWorker"}
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if seen[name] {
			continue
		}
		seen[name] = true
		ast.Inspect(funcs[name], func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.BasicLit:
				if s, err := strconv.Unquote(n.Value); err == nil && n.Kind == token.STRING && strings.Contains(s, "PADDOCK_AUDIT_DB_") {
					t.Errorf("%s names the audit database connection string %s", name, s)
				}
			case *ast.CallExpr:
				var called string
				switch fn := n.Fun.(type) {
				case *ast.Ident:
					called = fn.Name
				case *ast.SelectorExpr:
					called = fn.Sel.Name
				}
				if forbiddenCalls[called] {
					t.Errorf("%s opens an audit database pool through %s", name, called)
				}
				if id, ok := n.Fun.(*ast.Ident); ok && funcs[id.Name] != nil {
					queue = append(queue, id.Name)
				}
			}
			return true
		})
	}
	if len(seen) < 3 {
		t.Fatalf("only %d functions reached from serveWorker; the walk no longer follows the wiring", len(seen))
	}
	// The walk itself must notice a violation: loadAuditDeps reads the writer's connection string.
	found := false
	ast.Inspect(funcs["loadAuditDeps"], func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && strings.Contains(lit.Value, "PADDOCK_AUDIT_DB_") {
			found = true
		}
		return true
	})
	if !found {
		t.Fatal("loadAuditDeps no longer names PADDOCK_AUDIT_DB_*; the probe of this test is stale")
	}
}
