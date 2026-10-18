// Command upstreamwatch compares the pins Dependabot cannot see — the images of deploy/compose/versions.env, the
// Himmelblau version of the compiler, the fleetd build version and the Fleet NVD release — with upstream, and keeps
// one GitHub issue per outdated pin (ADR 0037 amendment 2026-10-17, plan M8d decisions 57–62).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"time"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	gh := &GH{}
	httpClient := &http.Client{Timeout: 30 * time.Second}
	up := &Upstream{
		Registries: NewRegistries(httpClient), HTTP: httpClient, HimmelblauIndex: HimmelblauIndex,
		LatestRelease: gh.LatestRelease,
	}
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr, up, gh)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, up *Upstream, gh GitHub) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "usage: upstreamwatch check|issues [flags]")
		return 2
	}
	fs := flag.NewFlagSet("upstreamwatch "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	versions := fs.String("versions", "deploy/compose/versions.env", "the pinned images")
	compiler := fs.String("compiler", "server/cmd/paddock-server/compiler.go", "the compiler command with the Himmelblau default")
	asJSON := fs.Bool("json", false, "print JSON (check)")
	repo := fs.String("repo", "", "owner/repo whose issues are reconciled (issues)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	pins, err := loadPins(*versions, *compiler)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "upstreamwatch:", err)
		return 1
	}
	switch args[0] {
	case "check":
		results := up.Check(ctx, pins)
		if *asJSON {
			if err := WriteJSON(stdout, results); err != nil {
				return 1
			}
			return 0
		}
		WriteText(stdout, stderr, results)
		return 0
	case "issues":
		if *repo == "" {
			_, _ = fmt.Fprintln(stderr, "upstreamwatch issues: --repo is required")
			return 2
		}
		results := up.Check(ctx, pins)
		WriteText(stdout, stderr, results)
		// GitHub failures fail the job so that a broken reconciliation is visible; outdated pins never do.
		if err := Reconcile(ctx, gh, *repo, results); err != nil {
			_, _ = fmt.Fprintln(stderr, "upstreamwatch:", err)
			return 1
		}
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "upstreamwatch: unknown command %q\n", args[0])
		return 2
	}
}

func loadPins(versionsPath, compilerPath string) ([]Pin, error) {
	f, err := os.Open(versionsPath) //nolint:gosec // the operator names the file to read
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	pins, err := ParseVersions(f, versionsPath)
	if err != nil {
		return nil, err
	}
	src, err := os.ReadFile(compilerPath) //nolint:gosec // the operator names the file to read
	if err != nil {
		return nil, err
	}
	hb, err := ParseCompiler(string(src), compilerPath)
	if err != nil {
		return nil, err
	}
	if len(pins) == 0 {
		return nil, errors.New("no pins found")
	}
	return append(pins, hb), nil
}
