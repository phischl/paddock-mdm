package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixture = "../../internal/mcpgen/testdata/admin.yaml"

func TestRunWritesFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "catalog.gen.go")
	if err := run([]string{"-spec", fixture, "-out", out}); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(out); err != nil || !strings.Contains(string(b), `"listThings"`) {
		t.Fatalf("output not written as expected (err %v)", err)
	}
	if err := run([]string{"-spec", fixture}); err == nil {
		t.Error("missing -out was accepted")
	}
}
