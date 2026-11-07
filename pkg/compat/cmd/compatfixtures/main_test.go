package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func scratchRoot(t *testing.T, releases ...string) string {
	t.Helper()
	root := t.TempDir()
	src := filepath.Join(root, auditWriterQueries)
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatal(err)
	}
	const body = "package auditstore\n\nconst insertAuditEvent = `-- name: InsertAuditEvent :one\nINSERT INTO audit_event (event_id)\nVALUES ($1)\nRETURNING event_id\n`\n"
	if err := os.WriteFile(src, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, r := range releases {
		if err := os.MkdirAll(filepath.Join(root, "pkg", "compat", "testdata", r), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func dirs(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, "pkg", "compat", "testdata"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestRunWritesTheReleaseAndDeletesDirectoriesOlderThanTwoReleases(t *testing.T) {
	root := scratchRoot(t, "0.1.0-alpha.7", "0.1.0-alpha.8")
	if err := run(root, "0.1.0-alpha.10"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(dirs(t, root), " "); got != "0.1.0-alpha.10 0.1.0-alpha.8" {
		t.Fatalf("directories after the run: %s (alpha.10 sorts after alpha.8 by SemVer, alpha.7 is out of the window)", got)
	}
	sql, err := os.ReadFile(filepath.Join(root, "pkg", "compat", "testdata", "0.1.0-alpha.10", "audit-insert.sql"))
	if err != nil || !strings.HasPrefix(string(sql), "INSERT INTO audit_event (event_id)\nVALUES ($1)\nRETURNING event_id") {
		t.Fatalf("audit insert: %q %v", sql, err)
	}
}

func TestRunRegeneratingTheCurrentReleaseKeepsTheOtherOne(t *testing.T) {
	root := scratchRoot(t, "0.1.0-alpha.8")
	if err := run(root, "0.1.0-alpha.9"); err != nil {
		t.Fatal(err)
	}
	if err := run(root, "0.1.0-alpha.9"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(dirs(t, root), " "); got != "0.1.0-alpha.8 0.1.0-alpha.9" {
		t.Fatalf("directories: %s", got)
	}
}

func TestRunRefusesAVersionOutsideTheReleaseGrammar(t *testing.T) {
	if err := run(scratchRoot(t), "0.1.0-alpha.9-dev"); err == nil {
		t.Fatal("accepted a dev suffix")
	}
}

func TestRunRefusesAVersionWithAV(t *testing.T) {
	if err := run(scratchRoot(t), "v0.1.0"); err == nil {
		t.Fatal("accepted v0.1.0")
	}
}
