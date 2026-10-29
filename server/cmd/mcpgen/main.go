// Command mcpgen writes pkg/mcpcatalog/catalog.gen.go, the MCP tool catalog, from the admin API contract
// api/openapi/admin.yaml (ADR 0044 decision 4, plan M14 §3.1), and with -skill the tool reference of the Claude skill,
// skills/operate-paddock/references/tools.md (ADR 0044 decision 9, plan M14 §3.8).
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
	skill := fs.String("skill", "", "path of the generated skill reference (skills/operate-paddock/references/tools.md)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *spec == "" || (*out == "" && *skill == "") {
		return errors.New("usage: mcpgen -spec <admin.yaml> [-out <catalog.gen.go>] [-skill <tools.md>]")
	}
	if *out != "" {
		if err := write(*out, mcpgen.Generate, *spec); err != nil {
			return err
		}
	}
	if *skill != "" {
		if err := write(*skill, mcpgen.Skill, *spec); err != nil {
			return err
		}
	}
	return nil
}

func write(path string, gen func(string) ([]byte, error), spec string) error {
	src, err := gen(spec)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, src, 0o644); err != nil { //nolint:gosec // generated source
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
