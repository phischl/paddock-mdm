package main

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/config"
)

// TestOffboardingCredentialsOnlyForOffboarding enforces plan M17 amendment k point 2: the organization deletion's
// object-store credentials are read in loadOffboardingObjects only, its result goes to app.NewOffboarding and nowhere
// else, and no package but app's offboarding and this wiring names app.OffboardingObjects. A second consumer of the
// credentials, which may delete every organization's escrowed headers, fails here.
func TestOffboardingCredentialsOnlyForOffboarding(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	var credentialReads, loads, typeUses []string
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
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		rel := filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator)))
		// ./paddock check names the variables to verify the Compose configuration; it never opens their files.
		if strings.HasPrefix(rel, "internal/prodcheck/") {
			return nil
		}
		for _, decl := range f.Decls {
			fn, _ := decl.(*ast.FuncDecl)
			where := rel
			if fn != nil {
				where = rel + ":" + fn.Name.Name
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.BasicLit:
					if s, err := strconv.Unquote(n.Value); err == nil && n.Kind == token.STRING && strings.Contains(s, "PADDOCK_OFFBOARD_") {
						credentialReads = append(credentialReads, where)
					}
				case *ast.CallExpr:
					if id, ok := n.Fun.(*ast.Ident); ok && id.Name == "loadOffboardingObjects" {
						loads = append(loads, where)
					}
					if sel, ok := n.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "NewOffboarding" && len(n.Args) == 1 {
						if inner, ok := n.Args[0].(*ast.CallExpr); ok {
							if id, ok := inner.Fun.(*ast.Ident); ok && id.Name == "loadOffboardingObjects" {
								loads = append(loads, where+" (app.NewOffboarding)")
							}
						}
					}
				case *ast.Ident:
					if n.Name == "OffboardingObjects" {
						typeUses = append(typeUses, rel)
					}
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range credentialReads {
		if r != "cmd/paddock-server/worker.go:loadOffboardingObjects" {
			t.Errorf("an offboarding credential variable is read in %s", r)
		}
	}
	if len(credentialReads) != 4 {
		t.Errorf("the four PADDOCK_OFFBOARD_*_FILE variables are read %d times, want 4: %v", len(credentialReads), credentialReads)
	}
	// A call that is app.NewOffboarding's argument is seen twice: as that argument, then as a call of its own.
	want := []string{"cmd/paddock-server/worker.go:loadWorkerSettings (app.NewOffboarding)", "cmd/paddock-server/worker.go:loadWorkerSettings"}
	if strings.Join(loads, ",") != strings.Join(want, ",") {
		t.Errorf("loadOffboardingObjects is called in %v, want once as app.NewOffboarding's argument", loads)
	}
	for _, u := range typeUses {
		if u != "internal/app/offboarding.go" && u != "cmd/paddock-server/worker.go" {
			t.Errorf("%s names app.OffboardingObjects", u)
		}
	}
}

// TestLoadOffboardingObjectsFailsClosed: without the credential files the worker's configuration still loads, no
// client is built, and the step objects fails with object_store_unavailable; with them both clients exist.
func TestLoadOffboardingObjectsFailsClosed(t *testing.T) {
	dir := t.TempDir()
	env := map[string]string{
		"PADDOCK_BUNDLES_S3_ENDPOINT": "http://rustfs:9000", "PADDOCK_ESCROW_S3_ENDPOINT": "http://rustfs:9000",
		"PADDOCK_OFFBOARD_BUNDLES_S3_ACCESS_KEY_FILE": filepath.Join(dir, "missing"),
		"PADDOCK_OFFBOARD_BUNDLES_S3_SECRET_KEY_FILE": filepath.Join(dir, "missing"),
	}
	l := config.NewLoaderFrom(env)
	o := loadOffboardingObjects(l)
	if err := l.Err(); err != nil {
		t.Fatalf("missing offboarding credentials stop the worker: %v", err)
	}
	if o.Bundles != nil || o.Escrow != nil {
		t.Fatalf("clients without credentials: %+v", o)
	}
	var oe *app.OffboardingError
	if _, err := app.NewOffboarding(o).DeleteObjects(context.Background(), uuid.New(), time.Time{}); !errors.As(err, &oe) ||
		oe.Code != app.OffboardingObjectStoreUnavailable {
		t.Fatalf("DeleteObjects without credentials: %v", err)
	}

	for _, v := range []string{"PADDOCK_OFFBOARD_BUNDLES_S3_ACCESS_KEY_FILE", "PADDOCK_OFFBOARD_BUNDLES_S3_SECRET_KEY_FILE",
		"PADDOCK_OFFBOARD_ESCROW_S3_ACCESS_KEY_FILE", "PADDOCK_OFFBOARD_ESCROW_S3_SECRET_KEY_FILE"} {
		p := filepath.Join(dir, v)
		if err := os.WriteFile(p, []byte("k"), 0o600); err != nil {
			t.Fatal(err)
		}
		env[v] = p
	}
	l = config.NewLoaderFrom(env)
	if o = loadOffboardingObjects(l); o.Bundles == nil || o.Escrow == nil || l.Err() != nil {
		t.Fatalf("with credentials: %+v, %v", o, l.Err())
	}
}
