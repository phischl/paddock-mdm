package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitIn(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.org", "-c", "tag.gpgsign=false", "-c", "commit.gpgsign=false"}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// release returns a repository whose first commit is tagged v0.1.0 and holds one migration per database; HEAD is an
// empty commit after the tag.
func release(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	gitIn(t, dir, "init", "-q")
	write(t, dir, "server/migrations/paddock/00001_init.sql", "-- init\n")
	write(t, dir, "server/migrations/audit/00001_init.sql", "-- audit init\n")
	write(t, dir, "server/migrations/migrations.go", "package migrations\n")
	gitIn(t, dir, "add", "-A")
	gitIn(t, dir, "commit", "-qm", "release")
	gitIn(t, dir, "tag", "v0.1.0")
	gitIn(t, dir, "commit", "-q", "--allow-empty", "-m", "work after the release")
	return dir
}

func check(t *testing.T, dir string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(context.Background(), append([]string{"--repo", dir}, args...), &out, &errb)
	return code, out.String(), errb.String()
}

func TestUntouchedTreeAndNewMigrationsPass(t *testing.T) {
	dir := release(t)
	if code, out, errs := check(t, dir); code != 0 || !strings.Contains(out, "2 migrations of v0.1.0 unchanged") {
		t.Fatalf("untouched: %d %q %q", code, out, errs)
	}
	write(t, dir, "server/migrations/paddock/00002_new.sql", "-- new\n")
	write(t, dir, "server/migrations/audit/00002_new.sql", "-- new\n")
	gitIn(t, dir, "add", "-A")
	gitIn(t, dir, "commit", "-qm", "new migrations")
	if code, _, errs := check(t, dir); code != 0 {
		t.Fatalf("new migrations: %d %q", code, errs)
	}
}

func TestEditedMigrationFailsWithItsName(t *testing.T) {
	dir := release(t)
	write(t, dir, "server/migrations/paddock/00001_init.sql", "-- init\n-- edited\n")
	code, _, errs := check(t, dir)
	if code != 1 || !strings.Contains(errs, "server/migrations/paddock/00001_init.sql (modified)") {
		t.Fatalf("edited: %d %q", code, errs)
	}
	if strings.Contains(errs, "audit") {
		t.Fatalf("an untouched file is named: %q", errs)
	}
}

func TestDeletedMigrationFails(t *testing.T) {
	dir := release(t)
	if err := os.Remove(filepath.Join(dir, "server/migrations/audit/00001_init.sql")); err != nil {
		t.Fatal(err)
	}
	code, _, errs := check(t, dir)
	if code != 1 || !strings.Contains(errs, "server/migrations/audit/00001_init.sql (deleted)") {
		t.Fatalf("deleted: %d %q", code, errs)
	}
}

func TestEditCommittedAfterTheTagStillFails(t *testing.T) {
	dir := release(t)
	write(t, dir, "server/migrations/paddock/00001_init.sql", "-- rewritten\n")
	gitIn(t, dir, "commit", "-qam", "edit a released migration")
	if code, _, _ := check(t, dir); code != 1 {
		t.Fatalf("a committed edit passed: %d", code)
	}
}

func TestNoTagPasses(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	dir := t.TempDir()
	gitIn(t, dir, "init", "-q")
	write(t, dir, "server/migrations/paddock/00001_init.sql", "-- init\n")
	gitIn(t, dir, "add", "-A")
	gitIn(t, dir, "commit", "-qm", "first")
	write(t, dir, "server/migrations/paddock/00001_init.sql", "-- edited\n")
	if code, out, errs := check(t, dir); code != 0 || !strings.Contains(out, "no v* tag") {
		t.Fatalf("no tag: %d %q %q", code, out, errs)
	}
}

func TestTaggedHeadComparesWithThePreviousTag(t *testing.T) {
	dir := release(t)
	write(t, dir, "server/migrations/paddock/00002_new.sql", "-- new in this release\n")
	gitIn(t, dir, "add", "-A")
	gitIn(t, dir, "commit", "-qm", "next release")
	gitIn(t, dir, "tag", "v0.2.0")
	// On the release commit its own new migrations are not frozen yet: the baseline is v0.1.0.
	write(t, dir, "server/migrations/paddock/00002_new.sql", "-- fixed before the tag moved\n")
	if code, out, errs := check(t, dir); code != 0 || !strings.Contains(out, "of v0.1.0") {
		t.Fatalf("tagged HEAD: %d %q %q", code, out, errs)
	}
	// Once a commit follows, v0.2.0 is the baseline.
	gitIn(t, dir, "commit", "-qam", "after the release")
	if code, _, errs := check(t, dir); code != 1 || !strings.Contains(errs, "00002_new.sql") {
		t.Fatalf("after the release: %d %q", code, errs)
	}
}

func TestSinceAndUnknownTag(t *testing.T) {
	dir := release(t)
	write(t, dir, "server/migrations/paddock/00001_init.sql", "-- edited\n")
	if code, _, _ := check(t, dir, "--since", "v0.1.0"); code != 1 {
		t.Fatalf("--since: %d", code)
	}
	if code, _, errs := check(t, dir, "--since", "v9.9.9"); code != 2 || !strings.Contains(errs, "v9.9.9") {
		t.Fatalf("unknown tag: %d %q", code, errs)
	}
}

func TestNoTagInCIFails(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	dir := t.TempDir()
	gitIn(t, dir, "init", "-q")
	write(t, dir, "server/migrations/paddock/00001_init.sql", "-- init\n")
	gitIn(t, dir, "add", "-A")
	gitIn(t, dir, "commit", "-qm", "first")
	if code, _, errs := check(t, dir); code != 2 || !strings.Contains(errs, "fetch the tags") {
		t.Fatalf("no tag in CI: %d %q", code, errs)
	}
}

func TestNotAGitRepositoryFails(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	if code, out, _ := check(t, t.TempDir()); code != 2 {
		t.Fatalf("not a repository: %d %q", code, out)
	}
}
