// Command paddockd is the Paddock agent (plan M2b §3.1). `paddockd run` is started only by paddock-supervisor;
// `paddockd enroll` is run once by an operator; `paddockd self-test` is run by the supervisor before it switches to
// a new version; `paddockd disk-setup` is run once at the first boot by paddock-disk-setup.service (plan M4b).
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
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/agent"
	"github.com/phischl/paddock-mdm/agent/internal/buildinfo"
	"github.com/phischl/paddock-mdm/agent/internal/disksetup"
	"github.com/phischl/paddock-mdm/agent/internal/enroll"
	"github.com/phischl/paddock-mdm/agent/internal/luks"
	"github.com/phischl/paddock-mdm/agent/internal/osupdates"
	"github.com/phischl/paddock-mdm/agent/internal/paths"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/agent/internal/selftest"
	"github.com/phischl/paddock-mdm/agent/internal/triggers"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

const usage = `usage: paddockd [--root DIR] <command> [flags]

commands:
  enroll --config FILE [--remove-config] [--no-wait] [--proxy URL]
                 enroll this device (root only); exit 0 active, 2 pending, 3 rejected, 1 error
  run            run the agent (started by paddock-supervisor)
  self-test      check this binary against the device's configuration; JSON report, exit 0 or 1
  plan           show what applying the last applied bundle again would change (read-only); JSON report
  updates run    install the regular updates and record the result for the agent (paddock-updates.timer)
  disk-setup     ask for the boot PIN on the console and enroll TPM2+PIN (first boot, paddock-disk-setup.service)
  version        print the version
`

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	os.Exit(run(os.Args[1:], os.Stdout))
}

func run(args []string, stdout io.Writer) int {
	global := flag.NewFlagSet("paddockd", flag.ContinueOnError)
	global.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	root := global.String("root", "/", "resolve all device paths below DIR (tests only)")
	if err := global.Parse(args); err != nil || global.NArg() == 0 {
		global.Usage()
		return 1
	}
	layout := paths.Layout{Root: *root}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cmd, rest := global.Arg(0), global.Args()[1:]
	switch cmd {
	case "version":
		_, _ = fmt.Fprintln(stdout, buildinfo.Version)
		return 0
	case "enroll":
		return runEnroll(ctx, layout, rest)
	case "run":
		return runAgent(ctx, layout)
	case "plan":
		return runPlan(ctx, layout, stdout)
	case "disk-setup":
		return runDiskSetup(ctx, layout)
	case "updates":
		return runUpdates(ctx, layout, rest)
	case "self-test":
		r := selftest.Run(ctx, layout)
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r)
		if !r.OK {
			return 1
		}
		return 0
	default:
		global.Usage()
		return 1
	}
}

func runEnroll(ctx context.Context, layout paths.Layout, args []string) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	cfg := fs.String("config", "", "enrollment configuration (JSON from the portal)")
	remove := fs.Bool("remove-config", false, "delete the enrollment configuration once the device is enrolled or pending")
	noWait := fs.Bool("no-wait", false, "return with exit code 2 while the enrollment waits for approval")
	proxy := fs.String("proxy", "", "HTTP(S) proxy for the device API")
	if err := fs.Parse(args); err != nil {
		return enroll.ExitError
	}
	if layout.Root == "/" && os.Geteuid() != 0 {
		slog.Error("paddockd enroll must run as root")
		return enroll.ExitError
	}
	code, err := enroll.Run(ctx, enroll.Options{
		Layout: layout, ConfigPath: *cfg, RemoveConfig: *remove, NoWait: *noWait, Proxy: *proxy,
	})
	if err != nil {
		slog.Error("enrollment failed", "error", err)
	}
	return code
}

// runAgent enrolls a device installed with the Paddock autoinstall (plan M4b decision 7) and waits until the
// configuration is readable (fail safe: a device that is not enrolled yet, or whose configuration is broken, keeps
// working and the supervisor does not restart in a loop), then runs the agent.
func runAgent(ctx context.Context, layout paths.Layout) int {
	if buildinfo.BrokenProbation {
		go func() {
			time.Sleep(20 * time.Second)
			slog.Error("paddock_testbroken_probation build: exiting")
			os.Exit(1)
		}()
	}
	var deps agent.Deps
	for logged := false; ; {
		var err error
		enrolled := enroll.Autoinstalled(ctx, enroll.Options{Layout: layout, ConfigPath: layout.EnrollConfig()})
		if deps, err = agent.Load(layout); err == nil && enrolled {
			break
		}
		if !logged {
			slog.WarnContext(ctx, "agent not configured yet; waiting", "error", err)
			logged = true
		}
		select {
		case <-ctx.Done():
			return 0
		case <-time.After(30 * time.Second):
		}
	}
	trig := make(chan struct{}, 1)
	deps.Triggers = trig
	go triggers.Watch(ctx, trig)
	go forwardHangup(ctx, trig)
	a, err := agent.New(deps)
	if err != nil {
		slog.ErrorContext(ctx, "agent start failed", "error", err)
		return 1
	}
	slog.InfoContext(ctx, "agent started", "version", buildinfo.Version, "server_url", deps.Config.ServerURL)
	if err := a.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		slog.ErrorContext(ctx, "agent stopped", "error", err)
		return 1
	}
	return 0
}

// runPlan prints the plan of the cached, verified bundle: the "second run" of plan M2b gate S2 without changing
// anything.
func runPlan(ctx context.Context, layout paths.Layout, stdout io.Writer) int {
	plan, version, err := agent.PlanCurrent(ctx, layout)
	if err != nil {
		slog.ErrorContext(ctx, "plan failed", "error", err)
		return 1
	}
	changes := 0
	for _, p := range plan {
		changes += len(p.Changes)
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(map[string]any{"bundle_version": version, "changes": changes, "resources": plan})
	return 0
}

// runUpdates runs the regular updates (`updates run`, plan M5b decision 6) and stores the result, which the agent
// reports; it exits 1 when the run did not succeed.
func runUpdates(ctx context.Context, layout paths.Layout, args []string) int {
	if len(args) != 1 || args[0] != "run" {
		fmt.Fprint(os.Stderr, usage)
		return 1
	}
	if layout.Root == "/" && os.Geteuid() != 0 {
		slog.Error("paddockd updates run must run as root")
		return 1
	}
	sys := reconcile.OS{Root: layout.Root}
	r := osupdates.RunRegular(ctx, sys.AptGetWithin, sys.DpkgWithin, time.Now, func() bool { return osupdates.RebootRequired(layout) })
	if err := osupdates.WriteResult(layout, r); err != nil {
		slog.ErrorContext(ctx, "storing the update result failed", "error", err)
		return 1
	}
	slog.InfoContext(ctx, "regular updates finished", "result", r.Result, "upgraded", r.Upgraded, "held_back", len(r.HeldBack),
		"reboot_required", r.RebootRequired, "error", r.Error)
	if r.Result != protocol.UpdatesResultOK {
		return 1
	}
	return 0
}

// runDiskSetup runs the first-boot disk setup on the console (stdin and stdout are the TTY of the unit). It always
// exits 0 unless the console is unusable, so the boot continues (fail safe).
func runDiskSetup(ctx context.Context, layout paths.Layout) int {
	if layout.Root == "/" && os.Geteuid() != 0 {
		slog.Error("paddockd disk-setup must run as root")
		return 1
	}
	err := disksetup.Run(ctx, disksetup.Options{Layout: layout, Tools: luks.OS{}, In: os.Stdin, Out: os.Stdout, Echo: ttyEcho})
	if err != nil {
		slog.ErrorContext(ctx, "disk setup failed", "error", err)
		return 1
	}
	return 0
}

// ttyEcho turns the echo of the terminal on stdin on or off.
func ttyEcho(on bool) error {
	cmd := exec.Command("stty", "-echo")
	if on {
		cmd = exec.Command("stty", "echo")
	}
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

// forwardHangup turns SIGHUP (sent by the supervisor after an update result) into an immediate check-in.
func forwardHangup(ctx context.Context, out chan<- struct{}) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
			select {
			case out <- struct{}{}:
			default:
			}
		}
	}
}
