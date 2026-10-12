//go:build ignore

// Command gitleaks-patterns checks the allowlist patterns of the repository's .gitleaks.toml with Go's regexp, the
// engine gitleaks uses (ADR 0026, amendment 2026-10-12). It reads a JSON array of patterns on stdin and writes one
// JSON verdict per pattern, in order: a pattern that does not compile, or that matches the empty string and therefore
// everything, is refused. Run with `go run`; it uses the standard library only and needs no module.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

type verdict struct {
	Index   int    `json:"index"`
	Pattern string `json:"pattern"`
	OK      bool   `json:"ok"`
	Why     string `json:"why,omitempty"`
}

func main() {
	var patterns []string
	if err := json.NewDecoder(os.Stdin).Decode(&patterns); err != nil {
		fmt.Fprintln(os.Stderr, "gitleaks-patterns: cannot read the patterns:", err)
		os.Exit(1)
	}
	out := json.NewEncoder(os.Stdout)
	for i, p := range patterns {
		v := verdict{Index: i, Pattern: p, OK: true}
		re, err := regexp.Compile(p)
		switch {
		case err != nil:
			v.OK, v.Why = false, "does not compile in Go's regexp: "+err.Error()
		case re.MatchString(""):
			v.OK, v.Why = false, "is empty or matches the empty string, so it would match everything"
		}
		if err := out.Encode(v); err != nil {
			fmt.Fprintln(os.Stderr, "gitleaks-patterns: cannot write a verdict:", err)
			os.Exit(1)
		}
	}
}
