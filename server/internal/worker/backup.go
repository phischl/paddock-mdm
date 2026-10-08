package worker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/phischl/paddock-mdm/server/internal/backup"
	"github.com/phischl/paddock-mdm/server/internal/platform/objectstore"
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
	Help: "Last-modified time of the newest backup of each kind in the backup bucket (postgres, authentik, openbao, fleet); 0 before the first.",
}, []string{"kind"})

// metricBackupKinds lets an alert notice ages that are never exported, e.g. because listing the bucket fails from the
// start (PaddockBackupAgeMissing).
var metricBackupKinds = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "paddock_backup_kinds",
	Help: "Number of backup kinds whose age the worker exports (0 without a backup configuration).",
})

var metricWALLastArchived = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "paddock_backup_wal_last_archived_timestamp_seconds",
	Help: "Last-modified time of the newest archived WAL segment of each pgBackRest stanza in the backup bucket; 0 before the first.",
}, []string{"stanza"})

// metricWALStanzas lets an alert notice WAL archive ages that are never exported (PaddockWALArchiveLagMissing).
var metricWALStanzas = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "paddock_backup_wal_stanzas",
	Help: "Number of pgBackRest stanzas whose WAL archive age the worker exports (0 without a backup configuration).",
})

// walListPages bounds the pages (up to 1000 entries each) that one listing of a WAL archive reads per round.
const walListPages = 10

// walDirPattern is the name of a WAL directory of pgBackRest: timeline and log, 8 hex digits each.
var walDirPattern = regexp.MustCompile(`^[0-9A-F]{16}$`)

// BackupStore is the backup bucket: the worker's credential may list and write below openbao/ only.
type BackupStore interface {
	Newest(ctx context.Context, prefix string) (time.Time, bool, error)
	Put(ctx context.Context, key, contentType, cacheControl string, body []byte) error
	ListPage(ctx context.Context, q objectstore.ListQuery) (objectstore.ListPage, error)
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
	// walCursor is the newest WAL directory seen per stanza; the next listing starts there.
	walCursor map[string]string
}

// NewBackups creates the job; key is the backup encryption key.
func NewBackups(store BackupStore, snap Snapshotter, key []byte, lock LeaderLocker) *Backups {
	return &Backups{store: store, snap: snap, key: key, lock: lock, now: time.Now, walCursor: map[string]string{}}
}

// Run runs the round at start and then every backupRoundInterval until ctx ends.
func (b *Backups) Run(ctx context.Context) error {
	metricBackupKinds.Set(float64(len(backup.Kinds)))
	metricWALStanzas.Set(float64(len(backup.WALStanzas)))
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

// Round exports the backup ages and, on the replica holding the lock, takes a due OpenBao snapshot. A kind whose age
// cannot be read neither hides the others nor stops the snapshot; all errors are returned together.
func (b *Backups) Round(ctx context.Context) error {
	agesErr := errors.Join(b.ages(ctx), b.walAges(ctx))
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
	return errors.Join(agesErr, err)
}

// ages sets the gauge of every kind it can read and returns the errors of the others.
func (b *Backups) ages(ctx context.Context) error {
	var errs []error
	for _, k := range backup.Kinds {
		newest, found, err := b.store.Newest(ctx, k.Prefix)
		if err != nil {
			errs = append(errs, fmt.Errorf("backup age %s: %w", k.Name, err))
			continue
		}
		// 0 without any backup, so that the stale alert also fires when a kind never ran.
		value := 0.0
		if found {
			value = float64(newest.Unix())
		}
		metricBackupLastSuccess.WithLabelValues(k.Name).Set(value)
	}
	return errors.Join(errs...)
}

// walAges sets the WAL archive gauge of every stanza it can read and returns the errors of the others.
func (b *Backups) walAges(ctx context.Context) error {
	var errs []error
	for _, stanza := range backup.WALStanzas {
		newest, found, err := b.walArchived(ctx, stanza)
		if err != nil {
			errs = append(errs, fmt.Errorf("wal archive age %s: %w", stanza, err))
			continue
		}
		value := 0.0
		if found {
			value = float64(newest.Unix())
		}
		metricWALLastArchived.WithLabelValues(stanza).Set(value)
	}
	return errors.Join(errs...)
}

// walArchived returns the last-modified time of the newest archived WAL segment of stanza. It never lists the whole
// archive, which holds every segment since the oldest kept backup: it takes the newest archive ID, lists the WAL
// directories from the newest one seen before (StartAfter; a later timeline sorts after it) and then the segments of
// the newest directory only.
func (b *Backups) walArchived(ctx context.Context, stanza string) (time.Time, bool, error) {
	root := backup.WALArchivePrefix(stanza)
	ids, _, err := b.listBounded(ctx, objectstore.ListQuery{Prefix: root, Delimiter: "/"})
	if err != nil {
		return time.Time{}, false, err
	}
	id, ok := newestArchiveID(root, ids)
	if !ok {
		return time.Time{}, false, nil
	}
	q := objectstore.ListQuery{Prefix: id, Delimiter: "/"}
	if cursor := b.walCursor[stanza]; strings.HasPrefix(cursor, id) {
		q.StartAfter = strings.TrimSuffix(cursor, "/")
	}
	dirs, _, err := b.listBounded(ctx, q)
	if err != nil {
		return time.Time{}, false, err
	}
	dir := newestWALDir(id, dirs)
	if dir == "" && q.StartAfter != "" {
		// The directory seen before is gone (the stanza was recreated): list from the start once.
		q.StartAfter = ""
		if dirs, _, err = b.listBounded(ctx, q); err != nil {
			return time.Time{}, false, err
		}
		dir = newestWALDir(id, dirs)
	}
	if dir == "" {
		delete(b.walCursor, stanza)
		return time.Time{}, false, nil
	}
	b.walCursor[stanza] = dir
	_, objects, err := b.listBounded(ctx, objectstore.ListQuery{Prefix: dir})
	if err != nil {
		return time.Time{}, false, err
	}
	var newest time.Time
	found := false
	for _, o := range objects {
		if !found || o.LastModified.After(newest) {
			newest, found = o.LastModified, true
		}
	}
	return newest, found, nil
}

// listBounded reads at most walListPages pages of q.
func (b *Backups) listBounded(ctx context.Context, q objectstore.ListQuery) ([]string, []objectstore.ListedObject, error) {
	var prefixes []string
	var objects []objectstore.ListedObject
	for range walListPages {
		page, err := b.store.ListPage(ctx, q)
		if err != nil {
			return nil, nil, err
		}
		prefixes = append(prefixes, page.Prefixes...)
		objects = append(objects, page.Objects...)
		if page.Next == "" {
			break
		}
		q.Token = page.Next
	}
	return prefixes, objects, nil
}

// newestArchiveID returns the archive directory (<PostgreSQL version>-<n>/) with the highest n: n grows with every
// stanza upgrade, while the version does not sort as text (9-1 < 10-2).
func newestArchiveID(root string, prefixes []string) (string, bool) {
	best, bestN := "", -1
	for _, p := range prefixes {
		name := strings.TrimSuffix(strings.TrimPrefix(p, root), "/")
		_, after, ok := strings.Cut(name, "-")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(after)
		if err != nil || n <= bestN {
			continue
		}
		best, bestN = p, n
	}
	return best, bestN >= 0
}

// newestWALDir returns the WAL directory below id that sorts last, or "" without one.
func newestWALDir(id string, prefixes []string) string {
	best := ""
	for _, p := range prefixes {
		if walDirPattern.MatchString(strings.TrimSuffix(strings.TrimPrefix(p, id), "/")) && p > best {
			best = p
		}
	}
	return best
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
