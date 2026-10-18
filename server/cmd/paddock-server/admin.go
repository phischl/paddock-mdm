package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/allowlistcache"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/config"
	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	"github.com/phischl/paddock-mdm/server/internal/domain/autounseal"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/valkey"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/sessions"
	"github.com/phischl/paddock-mdm/server/internal/worker"
)

// adminCommand is a parsed paddock-server admin command line (plan M6c decision 20; allowlist: plan M7a decision 21;
// agent-release: plan M7b decision 31; auto-unseal: plan M8u decision 8).
type adminCommand struct {
	name    string // bump-bundle-seq | recompile | rebuild-cache | allowlist | agent-release | security-review | end-sessions | auto-unseal
	by      int64  // bump-bundle-seq only
	sub     string // allowlist: show | disable | add; auto-unseal: show | verify | disable
	cidr    string // allowlist add
	label   string // allowlist add
	version string // agent-release
	dir     string // agent-release
}

// parseAdmin parses the arguments after "admin"; every error is a usage error.
func parseAdmin(args []string) (adminCommand, error) {
	if len(args) == 0 {
		return adminCommand{}, errUsage
	}
	cmd := adminCommand{name: args[0]}
	fs := flag.NewFlagSet("admin "+args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	switch cmd.name {
	case "bump-bundle-seq":
		by := fs.String("by", "", "")
		if fs.Parse(args[1:]) != nil || fs.NArg() != 0 || *by == "" {
			return adminCommand{}, errUsage
		}
		n, err := strconv.ParseInt(*by, 10, 64)
		if err != nil || n < app.MinBundleSeqBump || n > app.MaxBundleSeqBump {
			return adminCommand{}, errUsage
		}
		cmd.by = n
	case "recompile":
		all := fs.Bool("all", false, "")
		if fs.Parse(args[1:]) != nil || fs.NArg() != 0 || !*all {
			return adminCommand{}, errUsage
		}
	case "rebuild-cache", "security-review", "end-sessions":
		if len(args) != 1 {
			return adminCommand{}, errUsage
		}
	case "allowlist":
		if len(args) < 2 {
			return adminCommand{}, errUsage
		}
		cmd.sub = args[1]
		switch cmd.sub {
		case "show", "disable":
			if len(args) != 2 {
				return adminCommand{}, errUsage
			}
		case "add":
			fs := flag.NewFlagSet("admin allowlist add", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			cidr := fs.String("cidr", "", "")
			label := fs.String("label", "", "")
			if fs.Parse(args[2:]) != nil || fs.NArg() != 0 || *cidr == "" || *label == "" {
				return adminCommand{}, errUsage
			}
			cmd.cidr, cmd.label = *cidr, *label
		default:
			return adminCommand{}, errUsage
		}
	case "auto-unseal":
		if len(args) != 2 {
			return adminCommand{}, errUsage
		}
		cmd.sub = args[1]
		switch cmd.sub {
		case "show", "verify", "disable":
		default:
			return adminCommand{}, errUsage
		}
	case "agent-release":
		version := fs.String("version", "", "")
		dir := fs.String("dir", "", "")
		if fs.Parse(args[1:]) != nil || fs.NArg() != 0 || *version == "" || *dir == "" {
			return adminCommand{}, errUsage
		}
		cmd.version, cmd.dir = *version, *dir
	default:
		return adminCommand{}, errUsage
	}
	return cmd, nil
}

// runAdmin runs a restore command with the worker's configuration (plan M6c decisions 20–22): in the Compose stack as
// docker compose … run --rm --no-deps paddock-worker admin <command>. It prints one line on stdout.
func runAdmin(ctx context.Context, l *config.Loader, args []string) error {
	cmd, err := parseAdmin(args)
	if err != nil {
		return err
	}
	if cmd.name == "agent-release" {
		return runAgentRelease(ctx, l, cmd, os.Stdout)
	}
	dsn := l.SecretFile("PADDOCK_DB_WORKER_URL_FILE")
	platformDSN := l.SecretFile("PADDOCK_DB_PLATFORM_URL_FILE")
	var vkCfg config.Valkey
	if cmd.name == "rebuild-cache" || cmd.name == "allowlist" || cmd.name == "end-sessions" {
		vkCfg = config.LoadValkey(l)
	}
	if err := l.Err(); err != nil {
		return err
	}
	pool, err := db.NewOrgPool(ctx, dsn, db.Options{ApplicationName: "paddock-admin", MaxConns: 2})
	if err != nil {
		return err
	}
	defer pool.Close()
	platformPool, err := db.NewPlatformPool(ctx, platformDSN, db.Options{ApplicationName: "paddock-admin-platform", MaxConns: 2})
	if err != nil {
		return err
	}
	defer platformPool.Close()
	correlation := "admin-" + uuid.NewString()
	admin := app.NewAdmin(app.NewActionRunner(pool, platformPool, func(context.Context) string { return correlation }), pool)

	switch cmd.name {
	case "bump-bundle-seq":
		n, err := admin.BumpBundleSeq(ctx, cmd.by)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "bumped bundle_seq of %d devices by %d\n", n, cmd.by)
	case "recompile":
		n, err := admin.RecompileAll(ctx)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "recompile requested for %d organizations\n", n)
	case "rebuild-cache":
		vk, err := valkey.New(valkey.Config{Addr: vkCfg.Addr, Password: vkCfg.Password})
		if err != nil {
			return err
		}
		defer vk.Close()
		sync := worker.NewCacheSync(pool, devicecache.New(vk))
		n, err := admin.RebuildCache(ctx, sync.ReconcileAll)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "cache rebuilt for %d organizations\n", n)
	case "allowlist":
		return runAllowlist(ctx, cmd, admin.Runner(), platformPool, vkCfg)
	case "security-review":
		reviews, err := admin.SecurityReviewAll(ctx)
		for _, r := range reviews {
			fmt.Fprintf(os.Stdout, "%s: root_grants=%d sensitive_files=%d denied_files=%d\n", r.Slug, r.Counts.RootGrants,
				r.Counts.SensitiveFiles, r.Counts.DeniedFiles)
		}
		return err
	case "end-sessions":
		vk, err := valkey.New(valkey.Config{Addr: vkCfg.Addr, Password: vkCfg.Password})
		if err != nil {
			return err
		}
		defer vk.Close()
		gen, err := app.NewSessions(admin.Runner(), sessions.NewStore(vk)).EndAllCLI(ctx)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "every portal session ended (generation %d)\n", gen)
	case "auto-unseal":
		return runAutoUnsealCLI(ctx, cmd.sub, app.NewAutoUnseal(admin.Runner(), platformPool, nil), os.Stdout)
	}
	return nil
}

// errAutoUnsealNotEnabled ends admin auto-unseal verify with exit code 1 after the message is printed.
var errAutoUnsealNotEnabled = errors.New("automatic unseal is not enabled")

// autoUnsealCLI is the part of app.AutoUnseal the host commands use.
type autoUnsealCLI interface {
	Load(ctx context.Context) (autounseal.Setting, error)
	DisableCLI(ctx context.Context) (autounseal.Setting, error)
}

// runAutoUnsealCLI is paddock-server admin auto-unseal show|verify|disable (plan M8u decision 8). There is no enable:
// enabling is a platform administrator's acknowledgement in the portal. The row holds no share, so nothing printed
// here can be one.
func runAutoUnsealCLI(ctx context.Context, sub string, uc autoUnsealCLI, out io.Writer) error {
	switch sub {
	case "verify":
		s, err := uc.Load(ctx)
		if err != nil {
			return err
		}
		if s.State != autounseal.StateEnabled {
			fmt.Fprintln(out, "automatic unseal is not enabled: a platform administrator enables it in the portal first (Platform → OpenBao)")
			return errAutoUnsealNotEnabled
		}
		fmt.Fprintf(out, "automatic unseal acknowledged by %s on %s (disclaimer %s)\n", s.AcknowledgedBy,
			s.AcknowledgedAt.UTC().Format(time.RFC3339), s.DisclaimerVersion)
	case "show":
		s, err := uc.Load(ctx)
		if err != nil {
			return err
		}
		writeAutoUnseal(out, s)
	case "disable":
		s, err := uc.DisableCLI(ctx)
		if err != nil {
			return err
		}
		fmt.Fprintln(out, "automatic unseal disabled in the platform setting; run ./paddock auto-unseal disable to remove the shares from the host")
		writeAutoUnseal(out, s)
	}
	return nil
}

func writeAutoUnseal(out io.Writer, s autounseal.Setting) {
	ts := func(t time.Time) string {
		if t.IsZero() {
			return "-"
		}
		return t.UTC().Format(time.RFC3339)
	}
	str := func(v string) string {
		if v == "" {
			return "-"
		}
		return v
	}
	r := s.Report
	for _, kv := range [][2]string{
		{"state", string(s.State)},
		{"disclaimer_version", str(s.DisclaimerVersion)},
		{"current_disclaimer_version", autounseal.DisclaimerVersion},
		{"acknowledgement", str(s.Acknowledgement)},
		{"acknowledged_by", str(s.AcknowledgedBy)},
		{"acknowledged_by_subject", str(s.AcknowledgedBySubject)},
		{"acknowledged_at", ts(s.AcknowledgedAt)},
		{"disabled_by", str(s.DisabledBy)},
		{"disabled_at", ts(s.DisabledAt)},
		{"unsealer_seen_at", ts(r.SeenAt)},
		{"unsealer_running", strconv.FormatBool(r.UnsealerRunning(time.Now()))},
		{"unsealer_shares_present", strconv.FormatBool(r.SharesPresent)},
		{"unseal_count", strconv.FormatInt(r.UnsealCount, 10)},
		{"last_unseal_at", ts(r.LastUnsealAt)},
		{"failure_count", strconv.FormatInt(r.FailureCount, 10)},
		{"last_failure_at", ts(r.LastFailureAt)},
		{"last_failure_reason", str(r.LastFailureReason)},
	} {
		fmt.Fprintf(out, "%s: %s\n", kv[0], kv[1])
	}
}

// runAllowlist is the break-glass of the IP allow list (plan M7a decision 21): show, disable and add run with a system
// principal, without step-up or consequence check, and are audited. The api replicas follow a change through the
// version in Valkey; when Valkey is unreachable they reload within 60 s anyway.
func runAllowlist(ctx context.Context, cmd adminCommand, runner *app.ActionRunner, platformPool *db.PlatformPool, vkCfg config.Valkey) error {
	var version app.Version
	vk, err := valkey.New(valkey.Config{Addr: vkCfg.Addr, Password: vkCfg.Password})
	if err == nil {
		defer vk.Close()
		version = allowlistcache.NewVersion(vk)
	}
	list := app.NewIPAllowlist(runner, platformPool, version)
	note := func() {
		if version == nil {
			fmt.Fprintln(os.Stdout, "note: api replicas reload within 60 s")
			return
		}
		if _, err := version.Get(ctx); err != nil {
			fmt.Fprintln(os.Stdout, "note: api replicas reload within 60 s")
		}
	}
	switch cmd.sub {
	case "show":
		entries, err := list.Entries(ctx)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			fmt.Fprintln(os.Stdout, "ip allowlist: off (no entries)")
			return nil
		}
		for _, e := range entries {
			fmt.Fprintf(os.Stdout, "%s\t%s\t%s\t%s\n", e.CIDR, e.Label, e.CreatedBy, e.CreatedAt.UTC().Format(time.RFC3339))
		}
	case "disable":
		removed, err := list.DisableAll(ctx)
		if err != nil {
			return err
		}
		if len(removed) == 0 {
			fmt.Fprintln(os.Stdout, "ip allowlist: already off")
			return nil
		}
		fmt.Fprintf(os.Stdout, "ip allowlist disabled: %d entries removed\n", len(removed))
		note()
	case "add":
		item, err := list.AddBreakGlass(ctx, cmd.cidr, cmd.label)
		if errors.Is(err, problem.AlreadyExists) {
			return fmt.Errorf("ip allowlist: %s already exists", cmd.cidr)
		}
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "ip allowlist: added %s\n", item.CIDR)
		note()
	}
	return nil
}
