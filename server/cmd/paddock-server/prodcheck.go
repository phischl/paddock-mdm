package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/phischl/paddock-mdm/server/internal/platform/objectstore"
	"github.com/phischl/paddock-mdm/server/internal/prodcheck"
)

// errProdCheckFailed marks a checklist with at least one FAIL (exit 1); the checklist itself is the report.
var errProdCheckFailed = errors.New("prod-check: at least one item failed")

// runProdCheck reads `docker compose config --format json` from stdin and prints the production checklist (plan M6a
// decision 2). `make prod-check` runs it with the host's Compose files.
func runProdCheck(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("prod-check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	host := fs.String("host", prodcheck.HostControlPlane, "controlplane or audit")
	files := fs.String("compose-files", "", "comma-separated Compose files of the configuration")
	online := fs.Bool("online", false, "also read the audit bucket's Object Lock configuration (audit host)")
	var devKeys multiFlag
	fs.Var(&devKeys, "dev-release-key", "public key written by make dev-release-key (repeatable)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return errUsage
	}
	if *host != prodcheck.HostControlPlane && *host != prodcheck.HostAudit {
		return errUsage
	}
	cfg, err := prodcheck.Parse(stdin)
	if err != nil {
		return err
	}
	opts := prodcheck.Options{Host: *host, DevReleaseKeys: devKeys}
	if *files != "" {
		opts.ComposeFiles = strings.Split(*files, ",")
	}
	if *online && *host == prodcheck.HostAudit {
		store, err := auditBucket(cfg)
		if err != nil {
			return err
		}
		opts.ObjectLock = objectLock{store}
	}
	if !prodcheck.Write(stdout, prodcheck.Run(ctx, cfg, opts)) {
		return errProdCheckFailed
	}
	return nil
}

// auditBucket builds the audit writer's S3 client from its service in the configuration; the secret files are read on
// the host paths Compose resolved.
func auditBucket(cfg prodcheck.Config) (*objectstore.Store, error) {
	s, ok := cfg.Services["paddock-audit-writer"]
	if !ok {
		return nil, errors.New("prod-check --online: no service paddock-audit-writer in the configuration")
	}
	get := func(name string) string {
		if v := s.Environment[name]; v != nil {
			return *v
		}
		return ""
	}
	read := func(name string) (string, error) {
		path := get(name)
		for _, sec := range s.Secrets {
			if "/run/secrets/"+sec.Source == path {
				b, err := os.ReadFile(cfg.Secrets[sec.Source].File)
				return strings.TrimSpace(string(b)), err
			}
		}
		return "", fmt.Errorf("prod-check --online: %s is not a mounted secret", name)
	}
	access, err := read("PADDOCK_AUDIT_S3_ACCESS_KEY_FILE")
	if err != nil {
		return nil, err
	}
	secret, err := read("PADDOCK_AUDIT_S3_SECRET_KEY_FILE")
	if err != nil {
		return nil, err
	}
	return objectstore.New(get("PADDOCK_AUDIT_S3_ENDPOINT"), access, secret, get("PADDOCK_AUDIT_S3_BUCKET")), nil
}

type objectLock struct{ store *objectstore.Store }

func (o objectLock) DefaultRetention(ctx context.Context) (bool, string, int32, error) {
	enabled, mode, days, err := o.store.DefaultRetention(ctx)
	return enabled, string(mode), days, err
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}
