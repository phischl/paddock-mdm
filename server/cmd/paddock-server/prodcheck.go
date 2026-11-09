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
// decision 2). `./paddock check` runs it with the host's Compose files.
func runProdCheck(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("prod-check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	host := fs.String("host", prodcheck.HostControlPlane, "controlplane, audit or lab")
	files := fs.String("compose-files", "", "comma-separated Compose files of the configuration")
	online := fs.Bool("online", false, "also read the audit bucket's Object Lock configuration (audit or lab host)")
	revFile := fs.String("backup-revisions-file", "", "revisions in compose.backup-targets.yaml (with --online)")
	revDB := fs.String("backup-revisions-db", "", "revisions in the database (with --online)")
	var devKeys, dockerNets multiFlag
	fs.Var(&devKeys, "dev-release-key", "public key written by make dev-release-key (repeatable)")
	checkNets := fs.Bool("docker-networks", false, "check the edge subnet against the --docker-network list")
	fs.Var(&dockerNets, "docker-network", "an existing Docker network as name=subnet[,subnet...] (repeatable)")
	containers := fs.String("containers", "", "docker inspect output of the project's running containers (with --online)")
	exceptions := fs.String("hardening-exceptions", "hardening-exceptions.yaml", "the container hardening exceptions file")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return errUsage
	}
	if *host != prodcheck.HostControlPlane && *host != prodcheck.HostAudit && *host != prodcheck.HostLab {
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
	if *checkNets {
		opts.DockerNetworks = []prodcheck.DockerNetwork{}
		for _, n := range dockerNets {
			name, subnets, _ := strings.Cut(n, "=")
			opts.DockerNetworks = append(opts.DockerNetworks, prodcheck.DockerNetwork{Name: name,
				Subnets: strings.FieldsFunc(subnets, func(r rune) bool { return r == ',' })})
		}
	}
	if *online && *containers != "" {
		m, err := readContainerMatrix(*containers, *exceptions)
		if err != nil {
			return err
		}
		opts.Containers = &m
	}
	if *online && *revFile != "" {
		opts.BackupRevisions = &prodcheck.BackupRevisions{File: *revFile, Database: *revDB}
	}
	if *online && (*host == prodcheck.HostAudit || *host == prodcheck.HostLab) {
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

// runCheckContainers reads `docker inspect` of a project's containers from stdin and checks them against the hardening
// matrix, the item `./paddock check --online` prints (deploy/bundle/ci/assert-hardening.sh runs it on the smoke
// stacks).
func runCheckContainers(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("check-containers", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	exceptions := fs.String("exceptions", "hardening-exceptions.yaml", "the container hardening exceptions file")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return errUsage
	}
	m, err := containerMatrix(stdin, *exceptions)
	if err != nil {
		return err
	}
	if !prodcheck.Write(stdout, []prodcheck.Result{prodcheck.CheckContainerMatrix(m)}) {
		return errProdCheckFailed
	}
	return nil
}

func readContainerMatrix(inspectPath, exceptionsPath string) (prodcheck.ContainerMatrix, error) {
	f, err := os.Open(inspectPath) //nolint:gosec // G304: ./paddock check names the file it wrote
	if err != nil {
		return prodcheck.ContainerMatrix{}, fmt.Errorf("prod-check --containers: %w", err)
	}
	defer f.Close()
	return containerMatrix(f, exceptionsPath)
}

func containerMatrix(inspect io.Reader, exceptionsPath string) (prodcheck.ContainerMatrix, error) {
	containers, err := prodcheck.ParseInspect(inspect)
	if err != nil {
		return prodcheck.ContainerMatrix{}, err
	}
	f, err := os.Open(exceptionsPath) //nolint:gosec // G304: the bundle's exceptions file, named by the operator
	if err != nil {
		return prodcheck.ContainerMatrix{}, fmt.Errorf("hardening exceptions: %w", err)
	}
	defer f.Close()
	exceptions, err := prodcheck.ParseHardeningExceptions(f)
	if err != nil {
		return prodcheck.ContainerMatrix{}, err
	}
	return prodcheck.ContainerMatrix{Containers: containers, Exceptions: exceptions}, nil
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
