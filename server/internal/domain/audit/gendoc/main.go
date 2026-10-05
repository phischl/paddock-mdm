// Command gendoc writes docs/compliance/audit-codes.md (output *.md) or the portal's code list
// server/web/src/lib/auditCodes.gen.ts (output *.ts) from the audit code registry.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/paddock-mdm/paddock/server/internal/domain/audit"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: gendoc <output.md|output.ts>")
		os.Exit(2)
	}
	out := audit.RenderMarkdown()
	if strings.HasSuffix(os.Args[1], ".ts") {
		out = audit.RenderTypeScript()
	}
	if err := os.WriteFile(os.Args[1], []byte(out), 0o644); err != nil { //nolint:gosec // generated source and documentation
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
