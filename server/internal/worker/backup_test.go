package worker

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/phischl/paddock-mdm/server/internal/backup"
)

type fakeBackupStore struct {
	newest map[string]time.Time
	puts   map[string][]byte
	fail   map[string]error
}

func (f *fakeBackupStore) Newest(_ context.Context, prefix string) (time.Time, bool, error) {
	if err := f.fail[prefix]; err != nil {
		return time.Time{}, false, err
	}
	var newest time.Time
	found := false
	for key, t := range f.newest {
		if strings.HasPrefix(key, prefix) && (!found || t.After(newest)) {
			newest, found = t, true
		}
	}
	return newest, found, nil
}

func (f *fakeBackupStore) Put(_ context.Context, key, _, _ string, body []byte) error {
	f.puts[key] = body
	return nil
}

type fakeSnapshotter struct {
	data  string
	err   error
	calls int
}

func (f *fakeSnapshotter) RaftSnapshot(_ context.Context, w io.Writer) error {
	f.calls++
	if f.err != nil {
		return f.err
	}
	_, err := io.WriteString(w, f.data)
	return err
}

type fakeLock struct{ held bool }

func (f fakeLock) WithLeaderLock(ctx context.Context, _ int64, fn func(ctx context.Context) error) (bool, error) {
	if f.held {
		return false, nil
	}
	return true, fn(ctx)
}

func newBackupsForTest(store *fakeBackupStore, snap *fakeSnapshotter, lock fakeLock, now time.Time) (*Backups, []byte) {
	key := make([]byte, backup.KeySize)
	b := NewBackups(store, snap, key, lock)
	b.now = func() time.Time { return now }
	return b, key
}

func TestBackupsTakesDueSnapshotEncrypted(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	store := &fakeBackupStore{puts: map[string][]byte{}, newest: map[string]time.Time{
		"pgbackrest/backup/paddock/backup.info":   now.Add(-2 * time.Hour),
		"pgbackrest/backup/authentik/backup.info": now.Add(-3 * time.Hour),
		"fleet/20261008T000000Z.sql.gz.enc":       now.Add(-12 * time.Hour),
		"openbao/20261008T050000Z.snap.enc":       now.Add(-7 * time.Hour),
	}}
	snap := &fakeSnapshotter{data: "raft-snapshot"}
	b, key := newBackupsForTest(store, snap, fakeLock{}, now)
	if err := b.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	sealed, ok := store.puts["openbao/20261008T120000Z.snap.enc"]
	if !ok {
		t.Fatalf("no snapshot stored: %v", store.puts)
	}
	plain, err := backup.Open(key, sealed)
	if err != nil || string(plain) != "raft-snapshot" {
		t.Fatalf("stored snapshot: %q, %v", plain, err)
	}
	for kind, want := range map[string]time.Time{"postgres": now.Add(-2 * time.Hour), "authentik": now.Add(-3 * time.Hour),
		"fleet": now.Add(-12 * time.Hour), "openbao": now} {
		if got := testutil.ToFloat64(metricBackupLastSuccess.WithLabelValues(kind)); got != float64(want.Unix()) {
			t.Errorf("%s: gauge %v, want %v", kind, got, want.Unix())
		}
	}
}

func TestBackupsSkipsFreshSnapshotAndOtherReplicas(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	fresh := &fakeBackupStore{puts: map[string][]byte{}, newest: map[string]time.Time{"openbao/x": now.Add(-5 * time.Hour)}}
	snap := &fakeSnapshotter{data: "s"}
	b, _ := newBackupsForTest(fresh, snap, fakeLock{}, now)
	if err := b.Round(context.Background()); err != nil || snap.calls != 0 {
		t.Fatalf("fresh snapshot: calls %d, %v", snap.calls, err)
	}

	missing := &fakeBackupStore{puts: map[string][]byte{}, newest: map[string]time.Time{}}
	b, _ = newBackupsForTest(missing, snap, fakeLock{held: true}, now)
	if err := b.Round(context.Background()); err != nil || snap.calls != 0 {
		t.Fatalf("lock held elsewhere: calls %d, %v", snap.calls, err)
	}
	// A kind without any backup reads 0, so that the stale alert fires for it too.
	if got := testutil.ToFloat64(metricBackupLastSuccess.WithLabelValues("postgres")); got != 0 {
		t.Fatalf("postgres without backup: gauge %v, want 0", got)
	}
}

func TestBackupsSnapshotFailure(t *testing.T) {
	now := time.Now()
	store := &fakeBackupStore{puts: map[string][]byte{}, newest: map[string]time.Time{}}
	b, _ := newBackupsForTest(store, &fakeSnapshotter{err: errors.New("permission denied")}, fakeLock{}, now)
	if err := b.Round(context.Background()); err == nil || len(store.puts) != 0 {
		t.Fatalf("expected an error and no object: %v, %v", err, store.puts)
	}
	b, _ = newBackupsForTest(store, &fakeSnapshotter{}, fakeLock{}, now)
	if _, err := b.SnapshotOpenBao(context.Background()); err == nil {
		t.Fatal("an empty snapshot must fail")
	}
}

// TestBackupsOneFailingKind is the regression of review 1 finding 4: an error on one kind neither hides the other
// kinds' ages nor stops the OpenBao snapshot, and the round still reports it.
func TestBackupsOneFailingKind(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	store := &fakeBackupStore{puts: map[string][]byte{},
		newest: map[string]time.Time{"fleet/1.sql.gz.enc": now.Add(-time.Hour)},
		fail:   map[string]error{"pgbackrest/backup/paddock/backup.info": errors.New("AccessDenied")}}
	snap := &fakeSnapshotter{data: "s"}
	b, _ := newBackupsForTest(store, snap, fakeLock{}, now)
	err := b.Round(context.Background())
	if err == nil || !strings.Contains(err.Error(), "backup age postgres") {
		t.Fatalf("expected the postgres error, got %v", err)
	}
	if snap.calls != 1 || len(store.puts) != 1 {
		t.Fatalf("the snapshot must still run: calls %d, puts %d", snap.calls, len(store.puts))
	}
	if got := testutil.ToFloat64(metricBackupLastSuccess.WithLabelValues("fleet")); got != float64(now.Add(-time.Hour).Unix()) {
		t.Fatalf("fleet age %v not exported", got)
	}
}
