// Command compatfixtures regenerates pkg/compat/testdata/<release>/ from the current tree and deletes the fixture
// directories older than the two newest releases (plan M16 decision 2; `make compat-fixtures RELEASE=<version>`).
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/phischl/paddock-mdm/pkg/compat"
	"github.com/phischl/paddock-mdm/pkg/semver"
)

// keep is the number of releases whose fixtures stay: the compatibility window of ADR 0047 is the previous release
// and the one before.
const keep = 2

// auditWriterQueries is the sqlc output holding the statement the audit writer runs; the fixture keeps the
// positional form that reaches PostgreSQL.
const auditWriterQueries = "server/internal/adapters/auditpg/auditstore/audit.sql.go"

// versionName is the release grammar of release-check: a dev suffix in testdata/ would count in the two-release window
// and push the real previous release out.
var versionName = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(alpha|beta|rc)\.(0|[1-9][0-9]*))?$`)

var insertStatement = regexp.MustCompile("(?s)const insertAuditEvent = `-- name: InsertAuditEvent :one\n(.*?)`")

func main() {
	root := flag.String("root", ".", "repository root")
	release := flag.String("release", "", "release the fixtures describe, without the v")
	flag.Parse()
	if err := run(*root, *release); err != nil {
		fmt.Fprintln(os.Stderr, "compatfixtures:", err)
		os.Exit(1)
	}
}

func run(root, release string) error {
	if !versionName.MatchString(release) {
		return fmt.Errorf("release %q is not a version without v (x.y.z or x.y.z-alpha|beta|rc.N)", release)
	}
	src, err := os.ReadFile(filepath.Join(root, auditWriterQueries)) //nolint:gosec // fixed path below the root
	if err != nil {
		return err
	}
	m := insertStatement.FindSubmatch(src)
	if m == nil {
		return errors.New("the audit writer's insert statement is not in " + auditWriterQueries)
	}
	base := filepath.Join(root, "pkg", "compat", "testdata")
	if err := compat.Generate(filepath.Join(base, release), release, strings.TrimSpace(string(m[1]))+"\n"); err != nil {
		return err
	}
	removed, err := prune(base)
	for _, r := range removed {
		fmt.Println("removed fixtures of", r)
	}
	if err != nil {
		return err
	}
	fmt.Println("fixtures of", release, "written to", filepath.Join(base, release))
	return nil
}

// prune deletes the release directories below base except the keep newest by SemVer precedence and returns their names.
func prune(base string) ([]string, error) {
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() && versionName.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	slices.SortFunc(names, semver.Compare)
	var removed []string
	for len(names) > keep {
		if err := os.RemoveAll(filepath.Join(base, names[0])); err != nil {
			return removed, err
		}
		removed = append(removed, names[0])
		names = names[1:]
	}
	return removed, nil
}
