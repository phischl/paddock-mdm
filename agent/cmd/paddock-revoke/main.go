// Command paddock-revoke executes revocation tokens (architecture §12.3, plan M4c decisions 11–13). paddockd hands it
// every revocation envelope of a check-in on stdin without interpreting it; paddock-revoke verifies the token against
// the trust anchor pinned at enrollment and only then erases the keyslots of the root volume and reboots.
//
// Two-person rule (design contract 10): every change to this command and to agent/internal/revoke needs the review
// of a second person and a passed test on real hardware (docs/operations/revocation-acceptance.md).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/buildinfo"
	"github.com/phischl/paddock-mdm/agent/internal/client"
	"github.com/phischl/paddock-mdm/agent/internal/config"
	"github.com/phischl/paddock-mdm/agent/internal/identity"
	"github.com/phischl/paddock-mdm/agent/internal/paths"
	"github.com/phischl/paddock-mdm/agent/internal/revoke"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/pkg/revocation"
)

const usage = `usage: paddock-revoke <command> [flags]

commands:
  execute [--elapsed-seconds N]   verify the revocation token on stdin and execute it; JSON on stdout,
                                  exit 0 executed, 2 refused (nothing changed), 1 error
  version                         print the version
`

// Exit codes of execute.
const (
	exitExecuted = 0
	exitError    = 1
	exitRefused  = 2
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout))
}

func run(args []string, stdin io.Reader, stdout io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return exitError
	}
	switch args[0] {
	case "version":
		_, _ = fmt.Fprintln(stdout, buildinfo.Version)
		return 0
	case "execute":
		fs := flag.NewFlagSet("execute", flag.ContinueOnError)
		elapsed := fs.Int64("elapsed-seconds", 0, "uptime without contact counted by the dead man's switch (self-lock tokens)")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || *elapsed < 0 {
			fmt.Fprint(os.Stderr, usage)
			return exitError
		}
		return execute(stdin, stdout, time.Duration(*elapsed)*time.Second)
	}
	fmt.Fprint(os.Stderr, usage)
	return exitError
}

// execute reads the envelope, builds the revoker of this device and runs it. Every refusal is printed as
// {"refused": "<reason>"} for paddockd, which reports it as revocation.refused.
func execute(stdin io.Reader, stdout io.Writer, elapsed time.Duration) int {
	envelope, err := io.ReadAll(io.LimitReader(stdin, revocation.MaxEnvelopeSize+1))
	if err != nil {
		slog.Error("reading the revocation token failed", "error", err)
		return exitError
	}
	r := revoke.Revoker{Sys: revoke.OS{}, Now: time.Now}
	// The enrolled identity and the device key sign the confirmation (plan M4c decision 12). Without them the
	// token is refused before anything happens (the device ID check fails).
	if st, err := state.Load(paths.Default.State()); err == nil && st.Status == state.StatusActive {
		r.DeviceID = st.DeviceID
		r.Confirm = newConfirmer(st)
	}
	out := json.NewEncoder(stdout)
	erasure, err := r.Execute(context.Background(), envelope, elapsed)
	var refusal *revoke.Refusal
	switch {
	case errors.As(err, &refusal):
		slog.Warn("revocation refused", "reason", refusal.Reason)
		_ = out.Encode(map[string]string{"refused": refusal.Reason})
		return exitRefused
	case err != nil:
		slog.Error("revocation failed after the erasure", "error", err)
		_ = out.Encode(erasure)
		return exitError
	}
	_ = out.Encode(erasure)
	return exitExecuted
}

// confirmer posts the confirmation with the device's identity and the last sequence number paddockd received.
type confirmer struct {
	st     state.State
	client *client.Client
	err    error
}

func newConfirmer(st state.State) *confirmer {
	c := &confirmer{st: st}
	cfg, err := config.LoadAgent(paths.Default.AgentConfig())
	if err != nil {
		c.err = err
		return c
	}
	key, err := identity.Load(paths.Default.IdentityKey())
	if err != nil {
		c.err = err
		return c
	}
	c.client, c.err = client.New(cfg.ServerURL, cfg.Proxy, key)
	return c
}

// Confirm implements revoke.Confirmer.
func (c *confirmer) Confirm(ctx context.Context, commandID string, res protocol.CommandResult) error {
	if c.err != nil {
		return c.err
	}
	return c.client.CommandResult(ctx, c.st.DeviceID, c.st.Seq, commandID, res)
}
