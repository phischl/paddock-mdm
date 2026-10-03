// Command gendoc writes docs/compliance/audit-codes.md from the audit code registry.
package main

import (
	"fmt"
	"os"

	"github.com/paddock-mdm/paddock/server/internal/domain/audit"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: gendoc <output.md>")
		os.Exit(2)
	}
	if err := os.WriteFile(os.Args[1], []byte(audit.RenderMarkdown()), 0o644); err != nil { //nolint:gosec // documentation file
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
