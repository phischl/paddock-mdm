// Command migrationsfrozen fails when a migration of an earlier release changed or disappeared (ADR 0047 decision 2,
// plan M16 decision 1): a historical migration is never edited, because an operator's database applied it as it was.
// It compares server/migrations/paddock and server/migrations/audit in the working tree with the nearest v* tag
// before HEAD (PADDOCK_PREVIOUS_TAG or --since name another one). Migrations the tag does not have pass. Without any
// v* tag (a fresh fork) it passes and says so, except in CI (CI or GITHUB_ACTIONS set), where a clone without tags
// would silently disable the guard and fails instead. Any other git failure fails too.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"sort"
	"strings"
)

// defaultDirs are the migration directories of the two databases.
var defaultDirs = []string{"server/migrations/paddock", "server/migrations/audit"}

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("migrationsfrozen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	repo := fs.String("repo", ".", "repository root")
	since := fs.String("since", os.Getenv("PADDOCK_PREVIOUS_TAG"), "tag to compare with (default: the nearest v* tag before HEAD)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	tag := *since
	if tag == "" {
		var err error
		if tag, err = previousTag(ctx, *repo); err != nil {
			fmt.Fprintln(stderr, "migrationsfrozen:", err)
			return 2
		}
	}
	if tag == "" {
		if os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != "" {
			fmt.Fprintln(stderr, "migrationsfrozen: no v* tag in this clone; fetch the tags (checkout with fetch-depth: 0)")
			return 2
		}
		fmt.Fprintln(stdout, "migrationsfrozen: no v* tag in this clone, nothing to compare with")
		return 0
	}
	changed, checked, err := frozenViolations(ctx, *repo, tag, defaultDirs)
	if err != nil {
		fmt.Fprintln(stderr, "migrationsfrozen:", err)
		return 2
	}
	if len(changed) > 0 {
		fmt.Fprintf(stderr, "migrationsfrozen: %d migration(s) of %s changed or are gone; a released migration is never edited, add a new one:\n", len(changed), tag)
		for _, c := range changed {
			fmt.Fprintln(stderr, "  "+c)
		}
		return 1
	}
	fmt.Fprintf(stdout, "migrationsfrozen: %d migrations of %s unchanged\n", checked, tag)
	return 0
}

// previousTag returns the nearest v* tag reachable from HEAD that does not point at HEAD itself: on the commit that
// is tagged as a release, the migrations of that release are still new. It returns "" when there is none.
func previousTag(ctx context.Context, repo string) (string, error) {
	at, err := git(ctx, repo, nil, "tag", "--points-at", "HEAD", "--list", "v*")
	if err != nil {
		return "", err
	}
	args := []string{"describe", "--tags", "--abbrev=0", "--match", "v*"}
	for _, t := range strings.Fields(string(at)) {
		args = append(args, "--exclude", t)
	}
	out, err := git(ctx, repo, nil, args...)
	if err != nil {
		// Exit 128 is also "not a git repository" or a broken repository: only git's own "nothing to describe" is no tag.
		var ee *exec.ExitError
		if errors.As(err, &ee) && (strings.Contains(err.Error(), "No names found") || strings.Contains(err.Error(), "No tags can describe")) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// frozenViolations lists the files below dirs that tag has and the working tree changed or lacks, and how many files
// it compared. It compares git blob hashes, so line-ending conversion of the checkout does not matter.
func frozenViolations(ctx context.Context, repo, tag string, dirs []string) (changed []string, checked int, err error) {
	args := append([]string{"ls-tree", "-r", "-z", tag, "--"}, dirs...)
	out, err := git(ctx, repo, nil, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list %s: %w", tag, err)
	}
	want := map[string]string{}
	var paths []string
	for _, rec := range strings.Split(string(out), "\x00") {
		meta, name, ok := strings.Cut(rec, "\t")
		if !ok {
			continue
		}
		fields := strings.Fields(meta) // mode type hash
		if len(fields) != 3 || fields[1] != "blob" {
			continue
		}
		want[name] = fields[2]
		paths = append(paths, name)
	}
	sort.Strings(paths)
	var present []string
	for _, p := range paths {
		if _, statErr := os.Stat(path.Join(repo, p)); statErr != nil {
			changed = append(changed, p+" (deleted)")
			continue
		}
		present = append(present, p)
	}
	if len(present) > 0 {
		hashes, err := git(ctx, repo, strings.NewReader(strings.Join(present, "\n")+"\n"), "hash-object", "--stdin-paths")
		if err != nil {
			return nil, 0, fmt.Errorf("hash working tree: %w", err)
		}
		got := strings.Fields(string(hashes))
		if len(got) != len(present) {
			return nil, 0, fmt.Errorf("hash working tree: %d hashes for %d files", len(got), len(present))
		}
		for i, p := range present {
			if got[i] != want[p] {
				changed = append(changed, p+" (modified)")
			}
		}
	}
	sort.Strings(changed)
	return changed, len(paths), nil
}

func git(ctx context.Context, repo string, stdin io.Reader, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", repo}, args...)...)
	cmd.Stdin = stdin
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}
