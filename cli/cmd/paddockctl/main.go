// Command paddockctl manages a Paddock organization as code with an API token: export its configuration, preview a
// change as a plan and apply it (plan M6c §3.4).
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/phischl/paddock-mdm/cli/internal/cmd"
)

// version is set at build time (-ldflags "-X main.version=…").
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := cmd.Main(ctx, cmd.Env{Args: os.Args[1:], Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Getenv: os.Getenv, Version: version})
	stop()
	os.Exit(code)
}
