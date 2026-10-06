// Command paddock-supervisor starts, monitors and updates the Paddock agent (plan M2b decision 15). It runs as the
// systemd unit paddock-supervisor.service (Type=notify, WatchdogSec=60) and verifies agent releases with the
// release public key compiled into it.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"aead.dev/minisign"

	"github.com/phischl/paddock-mdm/agent/internal/buildinfo"
	"github.com/phischl/paddock-mdm/agent/internal/paths"
	"github.com/phischl/paddock-mdm/agent/internal/supervisor"
)

// releasePublicKey is the minisign public key of agent releases, set at build time with
// -ldflags "-X main.releasePublicKey=<base64 key>".
var releasePublicKey string

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if len(os.Args) == 2 && os.Args[1] == "version" {
		_, _ = os.Stdout.WriteString(buildinfo.Version + "\n")
		return
	}
	var key *minisign.PublicKey
	var k minisign.PublicKey
	if err := k.UnmarshalText([]byte(releasePublicKey)); err == nil {
		key = &k
	} else {
		// Fail safe: the agent keeps running; only updates are refused.
		slog.Error("no valid release public key compiled in; agent updates will be refused", "error", err)
	}
	probation := 10 * time.Minute
	if buildinfo.Dev {
		probation = 2 * time.Minute
	}
	l := paths.Default
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	usr1 := make(chan os.Signal, 1)
	signal.Notify(usr1, syscall.SIGUSR1)
	s := supervisor.New(supervisor.Config{
		Slots: l.Slots(), Staging: l.Staging(), Result: l.UpdateResult(), ProbationLog: l.Probation(),
		LastCheckin: l.LastCheckin(), PublicKey: key, Probation: probation, SelfTest: 120 * time.Second,
		Tick: 10 * time.Second, MaxBackoff: time.Minute, Notify: supervisor.SdNotify,
	})
	slog.Info("supervisor started", "version", buildinfo.Version, "probation", probation)
	s.Run(ctx, usr1)
}
