// Package cmd implements the paddockctl commands (plan M6c decision 26).
package cmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/phischl/paddock-mdm/cli/internal/cfg"
	"github.com/phischl/paddock-mdm/cli/internal/client"
)

// Exit codes.
const (
	ExitOK      = 0
	ExitError   = 1 // API or network error
	ExitUsage   = 2 // usage or configuration error
	ExitRefused = 3 // apply refused: the plan deletes resources and --yes is missing
)

// Env is what a run of paddockctl sees of its process.
type Env struct {
	Args           []string
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	Getenv         func(string) string
	Version        string
}

const usage = `usage: paddockctl <command> [flags]

commands:
  version                       print the version
  whoami                        show the organization, role and token of the API token
  schema                        print the JSON Schema of paddock.yml (paddock.v1)
  get config [-o yaml|json]     export the organization's configuration
  apply -f <file|-> [--dry-run] [--yes] [-o text|json]
                                show the plan of a configuration and apply it; deletions need --yes
  devices list [--page N] [--page-size 10|25|50|100] [--sort <field>] [-q <text>] [--state <s>]...
               [--device-group-id <uuid>] [--disk-state <s>]... [-o table|json]

global flags (after the command):
  --url <url>          admin API base URL (PADDOCK_URL, config file url)
  --token-file <path>  file holding the API token, mode 0600 (PADDOCK_TOKEN_FILE, config file token_file)
  --ca-file <path>     PEM bundle added to the system roots (PADDOCK_CA_FILE, config file ca_file)
  --config <path>      config file (default $XDG_CONFIG_HOME/paddockctl/config.yaml)
  -o, --output <fmt>   output format of the command

exit codes: 0 success, 1 API or network error, 2 usage or configuration error, 3 apply refused (deletions without --yes)
`

// usageError is a wrong command line (exit 2).
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

func usagef(format string, a ...any) error { return &usageError{msg: fmt.Sprintf(format, a...)} }

// refusedError is an apply refused because of deletions (exit 3).
type refusedError struct{ msg string }

func (e *refusedError) Error() string { return e.msg }

// globals are the flags every API command accepts.
type globals struct {
	output, url, tokenFile, caFile, config string
}

func (g *globals) register(fs *flag.FlagSet, defaultOutput string) {
	g.output = defaultOutput
	fs.StringVar(&g.output, "o", defaultOutput, "")
	fs.StringVar(&g.output, "output", defaultOutput, "")
	fs.StringVar(&g.url, "url", "", "")
	fs.StringVar(&g.tokenFile, "token-file", "", "")
	fs.StringVar(&g.caFile, "ca-file", "", "")
	fs.StringVar(&g.config, "config", "", "")
}

func (g *globals) requireOutput(allowed ...string) error {
	if !slices.Contains(allowed, g.output) {
		return usagef("-o must be one of %s", strings.Join(allowed, ", "))
	}
	return nil
}

// connect resolves the configuration, reads the token and creates the client.
func (g *globals) connect(e Env) (*client.Client, error) {
	c, err := cfg.Resolve(cfg.Sources{URL: g.url, TokenFile: g.tokenFile, CAFile: g.caFile, ConfigFile: g.config, Getenv: e.Getenv})
	if err != nil {
		return nil, err
	}
	secret, err := cfg.ReadToken(c.TokenFile)
	if err != nil {
		return nil, err
	}
	cl, err := client.New(c.URL, secret, c.CAFile, e.Version)
	if err != nil {
		return nil, cfg.Errorf("%v", err)
	}
	return cl, nil
}

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return usagef("%v", err)
	}
	if fs.NArg() > 0 {
		return usagef("unexpected argument %q", fs.Arg(0))
	}
	return nil
}

// Main runs paddockctl and returns its exit code.
func Main(ctx context.Context, e Env) int {
	err := dispatch(ctx, e)
	return report(e, err)
}

func dispatch(ctx context.Context, e Env) error {
	args := e.Args
	if len(args) == 0 {
		return usagef("no command")
	}
	switch args[0] {
	case "version":
		if len(args) != 1 {
			return usagef("version takes no arguments")
		}
		_, err := fmt.Fprintf(e.Stdout, "paddockctl %s\n", e.Version)
		return err
	case "help", "-h", "--help":
		_, err := io.WriteString(e.Stdout, usage)
		return err
	case "schema":
		return runSchema(e, args[1:])
	case "whoami":
		return runWhoami(ctx, e, args[1:])
	case "get":
		if len(args) < 2 || args[1] != "config" {
			return usagef("usage: paddockctl get config [-o yaml|json]")
		}
		return runGetConfig(ctx, e, args[2:])
	case "apply":
		return runApply(ctx, e, args[1:])
	case "devices":
		if len(args) < 2 || args[1] != "list" {
			return usagef("usage: paddockctl devices list [flags]")
		}
		return runDevicesList(ctx, e, args[2:])
	}
	return usagef("unknown command %q", args[0])
}

// report prints err on stderr and maps it to the exit code; secrets never appear in errors.
func report(e Env, err error) int {
	var uerr *usageError
	var cerr *cfg.Error
	var refused *refusedError
	var problem *client.Problem
	switch {
	case err == nil:
		return ExitOK
	case errors.As(err, &uerr):
		fmt.Fprintf(e.Stderr, "error: %s\n\n%s", uerr.msg, usage)
		return ExitUsage
	case errors.As(err, &cerr):
		fmt.Fprintf(e.Stderr, "error: %s\n", cerr.Error())
		return ExitUsage
	case errors.As(err, &refused):
		fmt.Fprintf(e.Stderr, "%s\n", refused.msg)
		return ExitRefused
	case errors.As(err, &problem):
		fmt.Fprintf(e.Stderr, "error: %s\n", problem.Error())
		if problem.Code == "step_up_required" {
			fmt.Fprintln(e.Stderr, "this change needs a step-up authentication, which an API token never has; make it in the portal")
		}
		return ExitError
	default:
		fmt.Fprintf(e.Stderr, "error: %v\n", err)
		return ExitError
	}
}
