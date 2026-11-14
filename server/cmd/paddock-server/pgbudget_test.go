package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/worker"
)

// pgBudgetRoles maps each Compose service of the connection budget (PG_ROLE_MAX_CONNS in deploy/bundle/paddock) to
// the application names of the control-plane database pools its process opens.
var pgBudgetRoles = map[string][]string{
	"paddock-api":               {"paddock-api", "paddock-api-platform"},
	"paddock-worker":            {"paddock-worker", "paddock-worker-platform"},
	"paddock-worker-ingest":     {"paddock-worker-ingest", "paddock-worker-ingest-platform"},
	"paddock-notifier":          {"paddock-notifier", "paddock-notifier-lock"},
	"paddock-compiler":          {"paddock-compiler"},
	"paddock-backup":            {"paddock-backup", "paddock-backup-lock"},
	"paddock-escrow-reader":     {"paddock-escrow-reader"},
	"paddock-revocation-issuer": {"paddock-revocation-issuer"},
	"paddock-outbox-relay":      {"paddock-outbox-relay"},
	"paddock-unsealer":          {"paddock-unsealer"},
}

// pgBudgetOutside are the pools the budget does not count: operator commands and one-offs, which fall into the 12
// connections it keeps for pgBackRest and paddock-migrate or run one at a time (docs/operations/capacity.md), and the
// pools on the audit database.
var pgBudgetOutside = map[string]string{
	"paddock-admin":          "operator command",
	"paddock-admin-platform": "operator command",
	"paddock-restore":        "operator command",
	"paddock-restore-report": "operator command",
	"paddock-backup-targets": "operator command",
	"paddock-backup-now":     "operator command",
	"paddock-backup-status":  "operator command",
	"paddock-osv-import":     "operator command",
	"paddock-restore-escrow": "audit database",
	"paddock-api-audit":      "audit database",
	"paddock-audit-writer":   "audit database",
	"paddock-notifier-audit": "audit database",
}

// pgBudgetConsts resolves the named sizes the pools use; a new name fails the test until it is added here.
var pgBudgetConsts = map[string]int{
	"apiOrgConns":            apiOrgConns,
	"apiAuditConns":          apiAuditConns,
	"worker.LeaderLockConns": worker.LeaderLockConns,
}

// TestPGBudgetTableMatchesPools: the per-role maxima of ./paddock check's connection budget (plan M19 D1.4) equal the
// connections the role's pools open: MaxConns, plus LockConns and one readiness connection with HealthConn, of every
// db.Options in this package, summed per role. Every pool belongs to a role or is named as outside the budget.
func TestPGBudgetTableMatchesPools(t *testing.T) {
	table := readPGBudgetTable(t)
	pools := readPoolOptions(t)

	byApp := map[string]int{}
	for _, p := range pools {
		byApp[p.app] += p.conns
	}
	counted := map[string]bool{}
	for role, apps := range pgBudgetRoles {
		want, ok := table[role]
		if !ok {
			t.Errorf("deploy/bundle/paddock PG_ROLE_MAX_CONNS has no row for %s", role)
			continue
		}
		got := 0
		for _, app := range apps {
			n, ok := byApp[app]
			if !ok {
				t.Errorf("%s: no pool with ApplicationName %q in server/cmd/paddock-server", role, app)
			}
			got += n
			counted[app] = true
		}
		if got != want {
			t.Errorf("%s: the pools open at most %d connections, PG_ROLE_MAX_CONNS says %d: update the table and docs/operations/capacity.md", role, got, want)
		}
	}
	for role := range table {
		if _, ok := pgBudgetRoles[role]; !ok {
			t.Errorf("PG_ROLE_MAX_CONNS row %s has no role in this test", role)
		}
	}
	for app := range byApp {
		if !counted[app] && pgBudgetOutside[app] == "" {
			t.Errorf("pool %q belongs to no role of the connection budget: add it to a role or to pgBudgetOutside", app)
		}
	}
}

type poolOptions struct {
	app   string
	conns int
}

var pgBudgetRow = regexp.MustCompile(`^\s+(paddock-[a-z-]+)=([0-9]+)$`)

// readPGBudgetTable parses the PG_ROLE_MAX_CONNS array of deploy/bundle/paddock.
func readPGBudgetTable(t *testing.T) map[string]int {
	t.Helper()
	raw, err := os.ReadFile("../../../deploy/bundle/paddock")
	if err != nil {
		t.Fatal(err)
	}
	table := map[string]int{}
	in := false
	for _, line := range strings.Split(string(raw), "\n") {
		switch {
		case line == "PG_ROLE_MAX_CONNS=(":
			in = true
		case in && line == ")":
			in = false
		case in:
			m := pgBudgetRow.FindStringSubmatch(line)
			if m == nil {
				t.Fatalf("unexpected PG_ROLE_MAX_CONNS line %q", line)
			}
			n, _ := strconv.Atoi(m[2])
			table[m[1]] = n
		}
	}
	if len(table) == 0 {
		t.Fatal("deploy/bundle/paddock has no PG_ROLE_MAX_CONNS table")
	}
	return table
}

// readPoolOptions returns every db.Options literal with an ApplicationName in the package's non-test files.
func readPoolOptions(t *testing.T) []poolOptions {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	var pools []poolOptions
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || exprString(lit.Type) != "db.Options" {
				return true
			}
			p := poolOptions{}
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					t.Fatalf("%s: db.Options without field names", fset.Position(lit.Pos()))
				}
				switch exprString(kv.Key) {
				case "ApplicationName":
					s, ok := kv.Value.(*ast.BasicLit)
					if !ok || s.Kind != token.STRING {
						t.Fatalf("%s: ApplicationName is not a string literal", fset.Position(kv.Pos()))
					}
					p.app, _ = strconv.Unquote(s.Value)
				case "MaxConns", "LockConns":
					p.conns += intValue(t, fset, kv.Value)
				case "HealthConn":
					if exprString(kv.Value) == "true" {
						p.conns++
					}
				}
			}
			if p.app == "" {
				t.Fatalf("%s: db.Options without ApplicationName", fset.Position(lit.Pos()))
			}
			pools = append(pools, p)
			return true
		})
	}
	if len(pools) == 0 {
		t.Fatal("no db.Options in server/cmd/paddock-server")
	}
	return pools
}

func intValue(t *testing.T, fset *token.FileSet, e ast.Expr) int {
	t.Helper()
	if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.INT {
		n, err := strconv.Atoi(lit.Value)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	n, ok := pgBudgetConsts[exprString(e)]
	if !ok {
		t.Fatalf("%s: pool size %s is unknown to pgBudgetConsts", fset.Position(e.Pos()), exprString(e))
	}
	return n
}

func exprString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprString(v.X) + "." + v.Sel.Name
	}
	return ""
}
