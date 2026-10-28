// Command mcpgen writes pkg/mcpcatalog/catalog.gen.go, the MCP tool catalog, from the admin API contract
// api/openapi/admin.yaml (ADR 0044 decision 4, plan M14 §3.1).
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/phischl/paddock-mdm/server/internal/mcpgen"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "mcpgen:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("mcpgen", flag.ContinueOnError)
	spec := fs.String("spec", "", "path of the OpenAPI contract (api/openapi/admin.yaml)")
	out := fs.String("out", "", "path of the generated Go file (pkg/mcpcatalog/catalog.gen.go)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *spec == "" || *out == "" {
		return errors.New("usage: mcpgen -spec <admin.yaml> -out <catalog.gen.go>")
	}
	src, err := mcpgen.Generate(*spec)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, src, 0o644); err != nil { //nolint:gosec // generated source
		return fmt.Errorf("write %s: %w", *out, err)
	}
	return nil
}
