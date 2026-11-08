package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/backuprole"
	"github.com/phischl/paddock-mdm/server/internal/config"
	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// errRestoreRunning refuses the host step while a restore plan runs (plan M15 decision 20): the restore owns the
// backup role's volumes until it reports.
var errRestoreRunning = errors.New("a restore plan is running: ./paddock backup-target apply waits until it finished")

// runBackupTargets implements `paddock-server admin backup-targets render|revisions|purge`, the database side of
// ./paddock backup-target apply (plan M15 decision 20), run in a one-off paddock-backup container:
//
//	render [--local-root <dir>]  the targets for the host (backuprole.WriteHostRender) on stdout, which only the host
//	                             script reads: it holds the decrypted SMB passwords
//	revisions                    the revision list of the live volume targets (./paddock check --online)
//	purge <id>...                delete the rows of deleted targets whose volumes the host removed
func runBackupTargets(ctx context.Context, l *config.Loader, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errUsage
	}
	switch args[0] {
	case "render":
		fs := flag.NewFlagSet("admin backup-targets render", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		root := fs.String("local-root", "", "")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
			return errUsage
		}
		return renderBackupTargets(ctx, l, *root, out)
	case "revisions":
		if len(args) != 1 {
			return errUsage
		}
		targets, err := loadHostTargets(ctx, l, nil)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, backuprole.Revisions(targets))
		return err
	case "purge":
		ids := make([]uuid.UUID, 0, len(args)-1)
		for _, a := range args[1:] {
			id, err := uuid.Parse(a)
			if err != nil {
				return errUsage
			}
			ids = append(ids, id)
		}
		if len(ids) == 0 {
			return errUsage
		}
		return purgeBackupTargets(ctx, l, ids, out)
	default:
		return errUsage
	}
}

// renderBackupTargets decrypts the SMB credentials with the AppRole paddock-backup and writes the render only when
// every target rendered, so the host never sees half a file.
func renderBackupTargets(ctx context.Context, l *config.Loader, root string, out io.Writer) error {
	baoCfg := config.LoadOpenBao(l)
	if err := l.Err(); err != nil {
		return err
	}
	keys, err := bao.New(baoCfg.Addr, baoCfg.RoleID, baoCfg.SecretID)
	if err != nil {
		return err
	}
	targets, err := loadHostTargets(ctx, l, keys)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := backuprole.WriteHostRender(&buf, time.Now(), root, targets); err != nil {
		return err
	}
	_, err = out.Write(buf.Bytes())
	return err
}

// loadHostTargets reads every volume target through the backup role's database role; with keys it refuses during a
// running restore plan and decrypts the credentials of live SMB targets.
func loadHostTargets(ctx context.Context, l *config.Loader, keys backuprole.Decrypter) ([]backuprole.HostTarget, error) {
	dsn := l.SecretFile("PADDOCK_DB_BACKUP_URL_FILE")
	if err := l.Err(); err != nil {
		return nil, err
	}
	pool, err := db.NewBackupPool(ctx, dsn, db.Options{ApplicationName: "paddock-backup-targets", MaxConns: 2})
	if err != nil {
		return nil, err
	}
	defer pool.Close()
	var rows []pgstore.BackupHostTargetsRow
	err = pool.InBackup(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		if keys != nil {
			plan, err := q.OpenBackupRestorePlan(ctx)
			switch {
			case err == nil && plan.State == "running":
				return errRestoreRunning
			case err != nil && !errors.Is(err, pgx.ErrNoRows):
				return err
			}
		}
		var err error
		rows, err = q.BackupHostTargets(ctx)
		return err
	})
	if err != nil {
		return nil, err
	}
	out := make([]backuprole.HostTarget, 0, len(rows))
	for _, r := range rows {
		settings, err := backupset.ParseSettings(r.Settings)
		if err != nil {
			return nil, err
		}
		t := backuprole.HostTarget{ID: r.ID, Name: r.Name, Type: backupset.TargetType(r.Type), Settings: settings,
			Revision: int(r.HostRevision), Deleted: r.Deleted}
		if keys != nil && !r.Deleted && t.Type == backupset.TypeSMB {
			if r.CredentialsCiphertext == nil {
				return nil, fmt.Errorf("backup target %q: no credentials", r.Name)
			}
			plain, err := keys.DecryptPlatform(ctx, app.BackupWrapKey, *r.CredentialsCiphertext)
			if err != nil {
				return nil, fmt.Errorf("backup target %q: decrypt credentials: %w", r.Name, err)
			}
			if t.Credentials, err = backupset.ParseCredentials(plain); err != nil {
				return nil, fmt.Errorf("backup target %q: %w", r.Name, err)
			}
		}
		out = append(out, t)
	}
	return out, nil
}

// purgeBackupTargets deletes the rows of deleted targets. It completes the deletion a platform administrator already
// made (platform.backup_target_deleted), so it records no event of its own; a row an open restore plan reads from
// stays.
func purgeBackupTargets(ctx context.Context, l *config.Loader, ids []uuid.UUID, out io.Writer) error {
	dsn := l.SecretFile("PADDOCK_DB_PLATFORM_URL_FILE")
	if err := l.Err(); err != nil {
		return err
	}
	pool, err := db.NewPlatformPool(ctx, dsn, db.Options{ApplicationName: "paddock-backup-targets", MaxConns: 2})
	if err != nil {
		return err
	}
	defer pool.Close()
	return pool.InPlatform(principal.With(ctx, hostOperator), func(ctx context.Context, q *pgstore.Queries) error {
		for _, id := range ids {
			n, err := q.PurgeDeletedBackupTarget(ctx, id)
			if err != nil {
				return err
			}
			word := "removed"
			if n == 0 {
				word = "kept"
			}
			_, _ = fmt.Fprintln(out, word+" "+id.String())
		}
		return nil
	})
}

// backupMarkMount implements `paddock-server backup mark-mount <id> <revision>...`: the marker of each target's
// revision in its volume (plan M15 decision 20), in a one-off paddock-backup container with the rendered volumes.
func backupMarkMount(l *config.Loader, args []string, out io.Writer) error {
	if len(args) == 0 || len(args)%2 != 0 {
		return errUsage
	}
	dir := l.String("PADDOCK_BACKUP_TARGETS_DIR", "/backup-targets")
	var errs []error
	for ; len(args) >= 2; args = args[2:] {
		id, err := uuid.Parse(args[0])
		rev, rerr := strconv.Atoi(args[1])
		if err != nil || rerr != nil || rev < 1 {
			return errUsage
		}
		if err := backuprole.WriteMountMarker(dir, id, rev); err != nil {
			errs = append(errs, err)
			continue
		}
		_, _ = fmt.Fprintf(out, "marked %s %d\n", id, rev)
	}
	return errors.Join(errs...)
}

// backupResolveLocal implements `paddock-server backup resolve-local [--root <dir>] <device>...`: every local device of
// the rendered file must still resolve below the root (backuprole.ResolveLocal, plan M15 decision 36). ./paddock runs
// it in a container without network or capabilities that sees the root's parent read-only at its own path, at
// backup-target apply and before every up, because the kernel resolves a bind mount again on every start.
func backupResolveLocal(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("backup resolve-local", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	root := fs.String("root", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() == 0 {
		return errUsage
	}
	if *root == "" {
		*root = backupset.DefaultLocalRoot
	}
	var errs []error
	for _, dev := range fs.Args() {
		sub, ok := strings.CutPrefix(dev, *root+"/")
		if !ok {
			errs = append(errs, fmt.Errorf("%w: %s is not below %s (PADDOCK_BACKUP_LOCAL_ROOT changed: run ./paddock backup-target apply)",
				backuprole.ErrLocalPath, dev, *root))
			continue
		}
		got, err := backuprole.ResolveLocal(*root, sub)
		if err == nil && got != dev {
			err = fmt.Errorf("%w: %s resolves to %s", backuprole.ErrLocalPath, dev, got)
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		_, _ = fmt.Fprintln(out, "ok "+dev)
	}
	return errors.Join(errs...)
}
