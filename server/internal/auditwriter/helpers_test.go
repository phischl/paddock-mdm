package auditwriter_test

import (
	"io"
	"strings"
)

func stringsReader(s string) io.Reader { return strings.NewReader(s) }

func contains(s, sub string) bool { return strings.Contains(s, sub) }
