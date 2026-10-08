package worker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/phischl/paddock-mdm/server/internal/backup"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// backupRoundInterval is how often the worker reads the backup ages and checks whether an OpenBao snapshot is due.
const backupRoundInterval = 5 * time.Minute

// OpenBaoSnapshotInterval is the age of the newest OpenBao snapshot from which the worker takes a new one (architecture
// §20: RPO 6 h).
const OpenBaoSnapshotInterval = 6 * time.Hour

// backupLockKey is the advisory lock of the OpenBao snapshot ("padd bak").
const backupLockKey = 0x7061646420626b70

var metricBackupLastSuccess = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "paddock_backup_last_success_timestamp_seconds",
	Help: "Last-modified time of the newest backup of each kind in the backup bucket (postgres, authentik, openbao, fleet); absent before the first.",
}, []string{"kind"})

// BackupStore is the backup bucket: the worker's credential may list and write below openbao/ only.
type BackupStore interface {
	Newest(ctx context.Context, prefix string) (time.Time, bool, error)
	Put(ctx context.Context, key, contentType, cacheControl string, body []byte) error
}

// Snapshotter takes OpenBao's Raft snapshot (bao.Client with the AppRole paddock-backup).
type Snapshotter interface {
	RaftSnapshot(ctx context.Context, w io.Writer) error
}

// LeaderLocker runs fn while holding a cluster-wide advisory lock; false when another replica holds it.
type LeaderLocker interface {
	WithLeaderLock(ctx context.Context, key int64, fn func(ctx context.Context) error) (bool, error)
}

// Backups is the backup job of the worker (plan M6a decisions 5 and 9): it exports the age of every kind of backup
// and takes an encrypted OpenBao snapshot when the newest one is older than OpenBaoSnapshotInterval.
type Backups struct {
	store BackupStore
	snap  Snapshotter
	key   []byte
	lock  LeaderLocker
	now   func() time.Time
}

// NewBackups creates the job; key is the backup encryption key.
func NewBackups(store BackupStore, snap Snapshotter, key []byte, lock LeaderLocker) *Backups {
	return &Backups{store: store, snap: snap, key: key, lock: lock, now: time.Now}
}

// Run runs the round at start and then every backupRoundInterval until ctx ends.
func (b *Backups) Run(ctx context.Context) error {
	tick := time.NewTicker(backupRoundInterval)
	defer tick.Stop()
	for {
		if err := b.Round(ctx); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "backup round failed; retrying next round", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// Round exports the backup ages and, on the replica holding the lock, takes a due OpenBao snapshot.
func (b *Backups) Round(ctx context.Context) error {
	if err := b.ages(ctx); err != nil {
		return err
	}
	sys := principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker"})
	_, err := b.lock.WithLeaderLock(sys, backupLockKey, func(ctx context.Context) error {
		// Again under the lock: another replica may just have taken the snapshot.
		newest, found, err := b.store.Newest(ctx, backup.OpenBaoPrefix)
		if err != nil {
			return err
		}
		if found && b.now().Sub(newest) < OpenBaoSnapshotInterval {
			return nil
		}
		key, err := b.SnapshotOpenBao(ctx)
		if err != nil {
			return err
		}
		slog.InfoContext(ctx, "OpenBao snapshot stored", "key", key)
		return nil
	})
	return err
}

// ages sets the gauge of every kind that has a backup.
func (b *Backups) ages(ctx context.Context) error {
	for _, k := range backup.Kinds {
		newest, found, err := b.store.Newest(ctx, k.Prefix)
		if err != nil {
			return fmt.Errorf("backup age %s: %w", k.Name, err)
		}
		if found {
			metricBackupLastSuccess.WithLabelValues(k.Name).Set(float64(newest.Unix()))
		}
	}
	return nil
}

// SnapshotOpenBao takes a snapshot, encrypts it and stores it; it returns the object key. `paddock-server backup
// openbao` calls it after key operations.
func (b *Backups) SnapshotOpenBao(ctx context.Context) (string, error) {
	var buf bytes.Buffer
	if err := b.snap.RaftSnapshot(ctx, &buf); err != nil {
		return "", err
	}
	if buf.Len() == 0 {
		return "", fmt.Errorf("openbao snapshot is empty")
	}
	sealed, err := backup.Seal(b.key, buf.Bytes())
	if err != nil {
		return "", err
	}
	at := b.now()
	key := backup.OpenBaoKey(at)
	if err := b.store.Put(ctx, key, "application/octet-stream", "no-store", sealed); err != nil {
		return "", fmt.Errorf("store %s: %w", key, err)
	}
	metricBackupLastSuccess.WithLabelValues("openbao").Set(float64(at.Unix()))
	return key, nil
}
