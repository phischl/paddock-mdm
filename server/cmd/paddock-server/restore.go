package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/backuprole"
	"github.com/phischl/paddock-mdm/server/internal/config"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/objectstore"
)

// The restore's one-off commands of the backup role's image (plan M15 decisions 23–24, amendment 2026-11-05 A5),
// run by deploy/compose/scripts/restore.sh in a one-off paddock-backup container. None prints a key or a credential,
// except backup target-export, whose output the host script writes into a 0600 file.

// backupManifest prints what a restore needs of the set in dir as name=value lines (validated values only, so the
// host script reads them without a JSON parser): the key, the schema versions, the stanzas and the newest snapshot
// and dump at or before --at.
func backupManifest(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("backup manifest", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	atText := fs.String("at", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		return errUsage
	}
	var at time.Time
	if *atText != "" {
		t, err := time.Parse(time.RFC3339, *atText)
		if err != nil {
			return fmt.Errorf("--at: %w", err)
		}
		at = t.UTC()
	}
	root, err := os.OpenRoot(fs.Arg(0))
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	info, err := backuprole.InspectSet(root, at)
	if err != nil {
		return err
	}
	return printSetInfo(out, info)
}

func printSetInfo(out io.Writer, info backuprole.SetInfo) error {
	m := info.Manifest
	lines := []string{
		"installation_id=" + m.InstallationID,
		"generated_at=" + m.GeneratedAt.UTC().Format(time.RFC3339),
		"key_id=" + m.KeyID,
		"key_fingerprint=" + m.KeyFingerprint,
		"repo_path=" + m.Contents.PgBackRest.Path,
		"stanzas=" + strings.Join(info.Stanzas, ","),
	}
	for _, stanza := range info.Stanzas {
		lines = append(lines, "oldest."+stanza+"="+info.Oldest[stanza].UTC().Format(time.RFC3339))
	}
	lines = append(lines,
		"openbao="+info.OpenBao,
		"fleet="+info.Fleet,
		fmt.Sprintf("escrow=%d", len(m.Contents.Escrow)),
	)
	for _, name := range slices.Sorted(maps.Keys(m.SchemaVersions)) {
		lines = append(lines, fmt.Sprintf("schema.%s=%d", name, m.SchemaVersions[name]))
	}
	_, err := fmt.Fprintln(out, strings.Join(lines, "\n"))
	return err
}

// setSource is where a restore reads a backup set from: exactly one of a set directory, a target the database knows
// (by name or ID) or a target file, which is read from stdin ("--target-file -") so that its credentials never need
// a file the container's user can read.
type setSource struct {
	dir, target, targetFile string
}

func (s *setSource) register(fs *flag.FlagSet) {
	fs.StringVar(&s.dir, "dir", "", "")
	fs.StringVar(&s.target, "target", "", "")
	fs.StringVar(&s.targetFile, "target-file", "", "")
}

func (s *setSource) valid() bool {
	n := 0
	for _, v := range []string{s.dir, s.target, s.targetFile} {
		if v != "" {
			n++
		}
	}
	return n == 1 && (s.targetFile == "" || s.targetFile == "-")
}

// open returns the set; a target the database knows needs the backup role's database and OpenBao credentials.
func (s *setSource) open(ctx context.Context, l *config.Loader, in io.Reader) (backuprole.SetReader, error) {
	switch {
	case s.dir != "":
		return backuprole.NewSetDir(s.dir), nil
	case s.targetFile != "":
		raw, err := io.ReadAll(io.LimitReader(in, 1<<20))
		if err != nil {
			return nil, err
		}
		f, err := backuprole.ParseTargetFile(raw)
		if err != nil {
			return nil, err
		}
		return backuprole.OpenTargetFile(f)
	default:
		t, keys, closeDB, err := lookupTarget(ctx, l, s.target)
		if err != nil {
			return nil, err
		}
		defer closeDB()
		target, err := backuprole.NewTargetFactory(keys, l.String("PADDOCK_BACKUP_TARGETS_DIR", "/backup-targets")).Open(ctx, t)
		if err != nil {
			return nil, err
		}
		return backuprole.AsSetReader(target)
	}
}

// lookupTarget finds a target by name or ID through the backup role's database role and opens OpenBao with its
// AppRole, which decrypts the target's credentials.
func lookupTarget(ctx context.Context, l *config.Loader, nameOrID string) (backuprole.TargetRecord, *bao.Client, func(), error) {
	pool, err := backupPool(ctx, l)
	if err != nil {
		return backuprole.TargetRecord{}, nil, nil, err
	}
	targets, err := backuprole.NewPGStore(pool, nil, nil).Targets(ctx)
	if err != nil {
		pool.Close()
		return backuprole.TargetRecord{}, nil, nil, err
	}
	i := slices.IndexFunc(targets, func(t backuprole.TargetRecord) bool {
		return t.Name == nameOrID || t.ID.String() == nameOrID
	})
	if i < 0 {
		pool.Close()
		return backuprole.TargetRecord{}, nil, nil, fmt.Errorf("no backup target %q", nameOrID)
	}
	baoCfg := config.LoadOpenBao(l)
	if err := l.Err(); err != nil {
		pool.Close()
		return backuprole.TargetRecord{}, nil, nil, err
	}
	keys, err := bao.New(baoCfg.Addr, baoCfg.RoleID, baoCfg.SecretID)
	if err != nil {
		pool.Close()
		return backuprole.TargetRecord{}, nil, nil, err
	}
	return targets[i], keys, pool.Close, nil
}

func backupPool(ctx context.Context, l *config.Loader) (*db.BackupPool, error) {
	dsn := l.SecretFile("PADDOCK_DB_BACKUP_URL_FILE")
	if err := l.Err(); err != nil {
		return nil, err
	}
	return db.NewBackupPool(ctx, dsn, db.Options{ApplicationName: "paddock-restore", MaxConns: 2})
}

// backupFetchSet copies a backup set, or the part below --path, into the directory dest (a staging directory or the
// repository); --no-clobber keeps every file dest holds.
func backupFetchSet(ctx context.Context, l *config.Loader, args []string, in io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("backup fetch-set", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var src setSource
	src.register(fs)
	prefix := fs.String("path", "", "")
	noClobber := fs.Bool("no-clobber", false, "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 || !src.valid() {
		return errUsage
	}
	set, err := src.open(ctx, l, in)
	if err != nil {
		return err
	}
	dst, err := os.OpenRoot(fs.Arg(0))
	if err != nil {
		return err
	}
	defer func() { _ = dst.Close() }()
	files, bytes, err := backuprole.CopySet(ctx, set, dst, backuprole.CopyOptions{Prefix: *prefix, NoClobber: *noClobber})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "copied %d files (%d bytes)\n", files, bytes)
	return err
}

// backupRestoreRepo rebuilds the local repository from a backup set (plan M15, amendment 2026-11-05, A5): it refuses
// while a restore plan runs, empties the repository and copies the whole set into it. --check only refuses while a
// plan runs, so restore.sh learns it before it stops anything.
func backupRestoreRepo(ctx context.Context, l *config.Loader, args []string, in io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("backup restore-repo", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var src setSource
	src.register(fs)
	check := fs.Bool("check", false, "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || !*check && !src.valid() {
		return errUsage
	}
	repoDir := l.String("PADDOCK_BACKUP_REPO_DIR", "/backup-repo")
	pool, err := backupPool(ctx, l)
	if err != nil {
		return err
	}
	var running int64
	err = pool.InBackup(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		running, err = q.BackupRoleRunningRestorePlans(ctx)
		return err
	})
	pool.Close()
	if err != nil {
		return err
	}
	if running > 0 {
		return errors.New("a restore plan is running; the repository is restored only when none runs")
	}
	if *check {
		_, err = fmt.Fprintln(out, "no restore plan is running")
		return err
	}
	set, err := src.open(ctx, l, in)
	if err != nil {
		return err
	}
	// The set must be readable before the repository is emptied: a wrong target name or credential keeps it.
	names, err := set.List(ctx)
	if err != nil {
		return fmt.Errorf("list the backup set: %w", err)
	}
	if _, ok := names["manifest.json"]; !ok {
		return errors.New("the backup set has no manifest.json")
	}
	repo, err := os.OpenRoot(repoDir)
	if err != nil {
		return err
	}
	defer func() { _ = repo.Close() }()
	if err := backuprole.EmptyDir(repo); err != nil {
		return fmt.Errorf("empty the repository: %w", err)
	}
	files, bytes, err := backuprole.CopySet(ctx, set, repo, backuprole.CopyOptions{})
	if err != nil {
		return err
	}
	info, err := backuprole.InspectSet(repo, time.Time{})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "copied %d files (%d bytes)\nrepo_path=%s\n", files, bytes, info.Manifest.Contents.PgBackRest.Path)
	return err
}

// backupRestoreEscrow puts the escrowed LUKS headers of the set in dir back into the escrow bucket: listing with the
// backup role's read-only credential, writing with the credential PADDOCK_ESCROW_RESTORE_S3_*_FILE (the gateway's,
// the only one that may put headers), and skipping every copy a Destroy covers.
func backupRestoreEscrow(ctx context.Context, l *config.Loader, args []string, out io.Writer) error {
	if len(args) != 1 {
		return errUsage
	}
	endpoint := l.Required("PADDOCK_ESCROW_S3_ENDPOINT")
	bucket := l.String("PADDOCK_ESCROW_S3_BUCKET", "paddock-escrow")
	lister := objectstore.New(endpoint, l.SecretFile("PADDOCK_ESCROW_S3_ACCESS_KEY_FILE"),
		l.SecretFile("PADDOCK_ESCROW_S3_SECRET_KEY_FILE"), bucket)
	putter := objectstore.New(endpoint, l.SecretFile("PADDOCK_ESCROW_RESTORE_S3_ACCESS_KEY_FILE"),
		l.SecretFile("PADDOCK_ESCROW_RESTORE_S3_SECRET_KEY_FILE"), bucket)
	pool, err := backupPool(ctx, l)
	if err != nil {
		return err
	}
	defer pool.Close()
	root, err := os.OpenRoot(args[0])
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	info, err := backuprole.InspectSet(root, time.Time{})
	if err != nil {
		return err
	}
	destroyed, err := backuprole.NewPGStore(pool, nil, nil).EscrowEvidence(ctx)
	if err != nil {
		return fmt.Errorf("read the Destroy evidence: %w", err)
	}
	res, err := backuprole.RestoreEscrow(ctx, root, info.Manifest, lister, putter, destroyed)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "escrow: %d headers put, %d already present, %d skipped (device escrow destroyed)\n",
		res.Put, res.Present, res.Destroyed)
	return err
}

// backupTargetExport prints the target file of one S3 target, with its decrypted credentials, as JSON.
func backupTargetExport(ctx context.Context, l *config.Loader, args []string, out io.Writer) error {
	if len(args) != 1 {
		return errUsage
	}
	t, keys, closeDB, err := lookupTarget(ctx, l, args[0])
	if err != nil {
		return err
	}
	defer closeDB()
	f, err := backuprole.ExportTarget(ctx, keys, t)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(f)
}
