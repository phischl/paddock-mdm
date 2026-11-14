package system

import (
	"bufio"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// suite is one line of suites.txt.
type suite struct {
	name    string
	timeout time.Duration
	run     *regexp.Regexp
}

func readSuites(t *testing.T) []suite {
	t.Helper()
	f, err := os.Open("suites.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var suites []suite
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		if len(parts) != 3 {
			t.Fatalf("suites.txt: %q is not name|timeout|regex", line)
		}
		d, err := time.ParseDuration(parts[1])
		if err != nil {
			t.Fatalf("suites.txt: %s: %v", parts[0], err)
		}
		suites = append(suites, suite{parts[0], d, regexp.MustCompile(parts[2])})
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return suites
}

// topLevelTests lists the Test functions of the package the way `go test` finds them.
func topLevelTests(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var names []string
	for _, path := range paths {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Test") && fn.Type.Params.NumFields() == 1 {
				names = append(names, fn.Name.Name)
			}
		}
	}
	return names
}

func TestSuitesComplete(t *testing.T) {
	suites := readSuites(t)
	if len(suites) == 0 {
		t.Fatal("suites.txt lists no suite")
	}
	names := topLevelTests(t)
	if len(names) == 0 {
		t.Fatal("found no test to assign")
	}
	for _, name := range names {
		var in []string
		for _, s := range suites {
			if s.run.MatchString(name) {
				in = append(in, s.name)
			}
		}
		if len(in) != 1 {
			t.Errorf("%s is in %d suites %v, want exactly one (suites.txt)", name, len(in), in)
		}
	}
}
