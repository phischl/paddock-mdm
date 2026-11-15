package db_test

import (
	"bufio"
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

// allowListedNames returns the names in the cases of ingestStatementCached (statementcache.go), read from the source,
// since the allow list is a switch and not a value a test could range over.
func allowListedNames(t *testing.T) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "statementcache.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "ingestStatementCached" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			clause, ok := n.(*ast.CaseClause)
			if !ok {
				return true
			}
			for _, expr := range clause.List {
				lit, ok := expr.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					t.Fatalf("ingestStatementCached: case %T is not a string literal", expr)
				}
				name, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatal(err)
				}
				names = append(names, name)
			}
			return true
		})
	}
	if len(names) == 0 {
		t.Fatal("statementcache.go: no cases in ingestStatementCached")
	}
	return names
}

// pgstoreQueries returns the SQL of every query in the sqlc query files, keyed by its name.
func pgstoreQueries(t *testing.T) map[string]string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", "adapters", "postgres", "queries", "*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("query files: %v (%d found)", err, len(files))
	}
	header := regexp.MustCompile(`^-- name: (\w+) :\w+`)
	queries := map[string]string{}
	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		var name string
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			if m := header.FindStringSubmatch(line); m != nil {
				name = m[1]
				continue
			}
			if name != "" && !strings.HasPrefix(strings.TrimSpace(line), "--") {
				queries[name] += line + "\n"
			}
		}
		_ = f.Close()
		if err := sc.Err(); err != nil {
			t.Fatal(err)
		}
	}
	return queries
}

// TestIngestStatementAllowList (ADR 0055 amendment 2, clarification of decisions 11 and 12): every name the
// statement-cache view caches is a generated query (a typo would silently run it per execution), and every listed name
// that is not a plain INSERT … VALUES has a case in TestIngestViewGenericPlans, which proves its plan.
func TestIngestStatementAllowList(t *testing.T) {
	queries := pgstoreQueries(t)
	planned := map[string]bool{}
	for _, c := range ingestPlanCases() {
		planned[c.name] = true
	}
	for _, name := range allowListedNames(t) {
		if !db.IngestStatementCached(name) {
			t.Errorf("%s: a case of ingestStatementCached that it does not accept", name)
		}
		sql, ok := queries[name]
		if !ok {
			t.Errorf("%s: listed, but no query of that name in server/internal/adapters/postgres/queries", name)
			continue
		}
		if planned[name] {
			continue
		}
		upper := strings.ToUpper(sql)
		if !strings.HasPrefix(strings.TrimSpace(upper), "INSERT INTO") || !strings.Contains(upper, "VALUES") ||
			strings.Contains(upper, "SELECT") || strings.Contains(upper, "DO UPDATE") {
			t.Errorf("%s: listed, not a plain INSERT … VALUES, and without a case in TestIngestViewGenericPlans", name)
		}
	}
	if db.IngestStatementCached("") || db.IngestStatementCached("ListDevices") {
		t.Error("the allow list accepts an empty or an unlisted name")
	}
}

// TestStatementName: the view reads the sqlc name from the first line of a statement; SQL without a "-- name:" line,
// such as the view's own or a raw statement, yields "" and is not cached.
func TestStatementName(t *testing.T) {
	for sql, want := range map[string]string{
		"-- name: GetDevice :one\nSELECT 1 FROM device WHERE id = $1\n": "GetDevice",
		"-- name: InsertOutbox :exec\nINSERT INTO outbox VALUES ($1)":   "InsertOutbox",
		"SELECT set_config('paddock.org_id', $1, true)":                 "",
		"SELECT 1 -- name: GetDevice :one":                              "",
		"\n-- name: GetDevice :one\nSELECT 1":                           "",
		"-- name: GetDevice":                                            "",
		"":                                                              "",
	} {
		if got := db.StatementName(sql); got != want {
			t.Errorf("StatementName(%q) = %q, want %q", sql, got, want)
		}
	}
}

// TestIngestViewCachesListedStatements: on a statement-cache view a listed statement is a named, cached statement of
// the connection after one execution; an unlisted one (ListDevices) stays unnamed, planned per execution.
func TestIngestViewCachesListedStatements(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	parent, err := db.NewOrgPool(ctx, sharedPaddock(t).API, db.Options{MaxConns: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(parent.Close)
	view := parent.WithStatementCache()
	err = view.InOrg(orgCtx(f.orgA), func(ctx context.Context, q *pgstore.Queries) error {
		if _, err := q.ListDevices(ctx, pgstore.ListDevicesParams{Sort: "hostname", MaxRows: 10}); err != nil {
			return err
		}
		if _, err := q.GetDevice(ctx, uuid.New()); !db.IsNoRows(err) {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := preparedStatements(t, view, f.orgA, "-- name: GetDevice %"); len(got) != 1 {
		t.Errorf("listed GetDevice: prepared as %v, want one named statement", got)
	}
	if got := preparedStatements(t, view, f.orgA, "-- name: ListDevices %"); len(got) != 0 {
		t.Errorf("unlisted ListDevices: prepared as %v, want none", got)
	}
}
