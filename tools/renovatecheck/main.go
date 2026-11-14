// Command renovatecheck fails when a pin of deploy/compose/versions.env or the compiler's Himmelblau default is not
// matched by a customManagers pattern of renovate.json5, which would leave it silently outdated (plan M12h-2
// decision 3). renovate.json5 must stay within JSON with comments and trailing commas.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
)

type config struct {
	CustomManagers []manager `json:"customManagers"`
}

type manager struct {
	CustomType         string   `json:"customType"`
	ManagerFilePattern []string `json:"managerFilePatterns"`
	MatchStrings       []string `json:"matchStrings"`
}

// unmanagedPrefixes follow GITLEAKS_IMAGE through an existing make target, so the gitleaks pull request fails
// make scan-secrets-check until they are regenerated (plan M12h-2 decision 2).
var unmanagedPrefixes = []string{"GITLEAKS_DEFAULT_CONFIG_"}

var himmelblauLine = regexp.MustCompile(`"PADDOCK_HIMMELBLAU_VERSION", "[0-9.]+"`)

func main() {
	renovate := flag.String("renovate", "renovate.json5", "Renovate configuration")
	versions := flag.String("versions", "deploy/compose/versions.env", "pinned images")
	compiler := flag.String("compiler", "server/cmd/paddock-server/compiler.go", "file holding the Himmelblau default")
	flag.Parse()

	if err := run(*renovate, *versions, *compiler); err != nil {
		fmt.Fprintln(os.Stderr, "renovatecheck:", err)
		os.Exit(1)
	}
}

func run(renovatePath, versionsPath, compilerPath string) error {
	raw, err := os.ReadFile(renovatePath)
	if err != nil {
		return err
	}
	cfg, err := parseConfig(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", renovatePath, err)
	}
	vers, err := os.ReadFile(versionsPath)
	if err != nil {
		return err
	}
	comp, err := os.ReadFile(compilerPath)
	if err != nil {
		return err
	}
	missing, err := uncovered(cfg, versionsPath, string(vers), compilerPath, string(comp))
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		return fmt.Errorf("not matched by a customManagers pattern of %s:\n  %s", renovatePath, strings.Join(missing, "\n  "))
	}
	return nil
}

// stripJSON5 removes comments and trailing commas outside strings.
func stripJSON5(src []byte) []byte {
	var out []byte
	inString := false
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case inString:
			out = append(out, c)
			if c == '\\' && i+1 < len(src) {
				i++
				out = append(out, src[i])
			} else if c == '"' {
				inString = false
			}
		case c == '"':
			inString = true
			out = append(out, c)
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				i++
			}
			out = append(out, '\n')
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			i += 2
			for i+1 < len(src) && (src[i] != '*' || src[i+1] != '/') {
				i++
			}
			i++
		default:
			out = append(out, c)
		}
	}
	return trailingComma.ReplaceAll(out, []byte("$1"))
}

var trailingComma = regexp.MustCompile(`,(\s*[}\]])`)

func parseConfig(raw []byte) (config, error) {
	var cfg config
	if err := json.Unmarshal(stripJSON5(raw), &cfg); err != nil {
		return cfg, fmt.Errorf("parse (the file must stay within JSON with comments and trailing commas): %w", err)
	}
	return cfg, nil
}

// patternMatches reports whether Renovate's "/regex/" file pattern matches path.
func patternMatches(pattern, path string) (bool, error) {
	if len(pattern) < 2 || pattern[0] != '/' || pattern[len(pattern)-1] != '/' {
		return false, fmt.Errorf("managerFilePatterns entry %q is not a /regex/", pattern)
	}
	re, err := regexp.Compile(pattern[1 : len(pattern)-1])
	if err != nil {
		return false, fmt.Errorf("managerFilePatterns %q: %w", pattern, err)
	}
	return re.MatchString(path), nil
}

// covered reports whether a regex manager of cfg that applies to file matches the line.
func covered(cfg config, file, line string) (bool, error) {
	for _, m := range cfg.CustomManagers {
		if m.CustomType != "regex" {
			continue
		}
		applies := false
		for _, p := range m.ManagerFilePattern {
			ok, err := patternMatches(p, file)
			if err != nil {
				return false, err
			}
			applies = applies || ok
		}
		if !applies {
			continue
		}
		for _, s := range m.MatchStrings {
			re, err := regexp.Compile("(?m)" + s)
			if err != nil {
				return false, fmt.Errorf("matchStrings %q: %w", s, err)
			}
			if re.MatchString(line) {
				return true, nil
			}
		}
	}
	return false, nil
}

func uncovered(cfg config, versionsPath, versions, compilerPath, compiler string) ([]string, error) {
	var missing []string
	for _, line := range strings.Split(versions, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") || isUnmanaged(line) {
			continue
		}
		ok, err := covered(cfg, versionsPath, line)
		if err != nil {
			return nil, err
		}
		if !ok {
			missing = append(missing, versionsPath+": "+line)
		}
	}
	found := false
	for _, line := range strings.Split(compiler, "\n") {
		if !himmelblauLine.MatchString(line) {
			continue
		}
		found = true
		ok, err := covered(cfg, compilerPath, line)
		if err != nil {
			return nil, err
		}
		if !ok {
			missing = append(missing, compilerPath+": "+strings.TrimSpace(line))
		}
	}
	if !found {
		return nil, fmt.Errorf("%s: no PADDOCK_HIMMELBLAU_VERSION default found", compilerPath)
	}
	return missing, nil
}

func isUnmanaged(line string) bool {
	for _, p := range unmanagedPrefixes {
		if strings.HasPrefix(line, p) {
			return true
		}
	}
	return false
}
