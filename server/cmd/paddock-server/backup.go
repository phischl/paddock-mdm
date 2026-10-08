package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/phischl/paddock-mdm/server/internal/backup"
	"github.com/phischl/paddock-mdm/server/internal/config"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/platform/objectstore"
	"github.com/phischl/paddock-mdm/server/internal/worker"
)

// backupConfig is the worker's part of the backup (plan M6a decisions 5 and 9, compose.backup.yaml); without
// PADDOCK_BACKUP_S3_ENDPOINT the worker takes no OpenBao snapshots and exports no backup ages.
type backupConfig struct {
	store *objectstore.Store
	snap  *bao.Client
	key   []byte
}

func loadBackup(l *config.Loader, baoAddr string) (*backupConfig, error) {
	endpoint := l.String("PADDOCK_BACKUP_S3_ENDPOINT", "")
	if endpoint == "" {
		return nil, nil
	}
	store := objectstore.New(endpoint, l.SecretFile("PADDOCK_BACKUP_S3_ACCESS_KEY_FILE"),
		l.SecretFile("PADDOCK_BACKUP_S3_SECRET_KEY_FILE"), l.String("PADDOCK_BACKUP_S3_BUCKET", "paddock-backup"))
	rawKey := l.SecretFile("PADDOCK_BACKUP_ENCRYPTION_KEY_FILE")
	// The snapshot uses its own AppRole: the worker's role may only sign commands (plan M4a decision 2).
	roleID := l.SecretFile("PADDOCK_BACKUP_OPENBAO_ROLE_ID_FILE")
	secretID := l.SecretFile("PADDOCK_BACKUP_OPENBAO_SECRET_ID_FILE")
	var key []byte
	if rawKey != "" {
		var err error
		if key, err = backup.ParseKey(rawKey); err != nil {
			l.Invalid("PADDOCK_BACKUP_ENCRYPTION_KEY_FILE", err.Error())
		}
	}
	if err := l.Err(); err != nil {
		return nil, err
	}
	snap, err := bao.New(baoAddr, roleID, secretID)
	if err != nil {
		return nil, err
	}
	return &backupConfig{store: store, snap: snap, key: key}, nil
}

// runBackup implements `paddock-server backup openbao` (a snapshot now, after key operations; run in the worker
// container) and `paddock-server backup decrypt <in> <out>` (restore, docs/operations/restore.md).
func runBackup(ctx context.Context, l *config.Loader, args []string) error {
	switch {
	case len(args) == 1 && args[0] == "openbao":
		addr := l.Required("PADDOCK_OPENBAO_ADDR")
		bc, err := loadBackup(l, addr)
		if err != nil {
			return err
		}
		if bc == nil {
			return fmt.Errorf("backup openbao: PADDOCK_BACKUP_S3_ENDPOINT is not set")
		}
		key, err := worker.NewBackups(bc.store, bc.snap, bc.key, nil).SnapshotOpenBao(ctx)
		if err != nil {
			return err
		}
		slog.InfoContext(ctx, "OpenBao snapshot stored", "key", key)
		return nil
	case len(args) == 3 && args[0] == "decrypt":
		raw := l.SecretFile("PADDOCK_BACKUP_ENCRYPTION_KEY_FILE")
		if err := l.Err(); err != nil {
			return err
		}
		key, err := backup.ParseKey(raw)
		if err != nil {
			return err
		}
		sealed, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		plain, err := backup.Open(key, sealed)
		if err != nil {
			return err
		}
		return os.WriteFile(args[2], plain, 0o600) //nolint:gosec // the operator names the output file on the command line
	default:
		return errUsage
	}
}
