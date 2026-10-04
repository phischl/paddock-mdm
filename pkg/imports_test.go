package pkg_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestImportAllowList enforces plan M2a decision 5: code in pkg depends only on the standard library, other pkg
// packages and github.com/gowebpki/jcs, and never on server code.
func TestImportAllowList(t *testing.T) {
	const self = "github.com/paddock-mdm/paddock/pkg"
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			first := strings.SplitN(p, "/", 2)[0]
			switch {
			case !strings.Contains(first, "."): // standard library
			case p == self || strings.HasPrefix(p, self+"/"):
			case p == "github.com/gowebpki/jcs":
			default:
				t.Errorf("%s imports %s, which is not allowed in pkg", path, p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
