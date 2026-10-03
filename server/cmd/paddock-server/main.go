// Command paddock-server is the single Paddock server binary. Roles are selected by subcommand.
package main

import (
	"fmt"
	"os"
)

const usage = `usage: paddock-server <command> [arguments]

commands:
  serve api|outbox-relay|audit-writer
  migrate paddock|audit
  provision rabbitmq
  healthcheck
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	switch args[0] {
	case "serve", "migrate", "provision", "healthcheck":
		fmt.Fprintf(os.Stderr, "paddock-server %s: not implemented\n", args[0])
		return 1
	default:
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
}
