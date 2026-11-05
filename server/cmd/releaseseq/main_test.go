package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const changelog = `# Changelog

## [Unreleased]

## [0.1.0-alpha.10] - 2026-12-01

## [0.1.0-alpha.2] - 2026-10-13

### Added
## [not a section]
`

func TestReleasesAndSequence(t *testing.T) {
	rel, err := Releases(strings.NewReader(changelog))
	if err != nil {
		t.Fatal(err)
	}
	seq, err := Sequence(rel, "0.1.0-alpha.11")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"0.1.0-alpha.2", "0.1.0-alpha.10", "0.1.0-alpha.11"}; !slices.Equal(seq, want) {
		t.Fatalf("sequence %v, want %v", seq, want)
	}
	if seq, err := Sequence(rel, "0.1.0-alpha.10"); err != nil || len(seq) != 2 {
		t.Errorf("a released current is not deduplicated: %v %v", seq, err)
	}
	if _, err := Sequence(rel, "0.1.0-alpha.3"); err == nil {
		t.Error("a current older than a release was accepted")
	}
	if _, err := Sequence(rel, "0.0.0-dev"); err == nil {
		t.Error("a development version was accepted as current")
	}
	if _, err := Releases(strings.NewReader("## [banana] - 2026-01-01\n")); err == nil {
		t.Error("a section without a release version was accepted")
	}
}

func TestRunWritesFile(t *testing.T) {
	dir := t.TempDir()
	in, out := filepath.Join(dir, "CHANGELOG.md"), filepath.Join(dir, "releases.gen.go")
	if err := os.WriteFile(in, []byte(changelog), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-changelog", in, "-current", "0.1.0-alpha.11", "-out", out}); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(out); err != nil || !strings.Contains(string(b), `"0.1.0-alpha.11",`) {
		t.Fatalf("output not written as expected (err %v)", err)
	}
	if err := run([]string{"-changelog", in, "-out", out}); err == nil {
		t.Error("missing -current was accepted")
	}
}
