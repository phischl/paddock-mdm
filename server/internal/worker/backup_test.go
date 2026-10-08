package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/phischl/paddock-mdm/server/internal/backup"
	"github.com/phischl/paddock-mdm/server/internal/platform/objectstore"
)

type fakeBackupStore struct {
	newest map[string]time.Time
	puts   map[string][]byte
	fail   map[string]error
	// pageSize is the page size of ListPage (default 1000, like S3); queries records its calls.
	pageSize int
	queries  []objectstore.ListQuery
}

// ListPage lists newest's keys like ListObjectsV2: in key order, after StartAfter, grouped at Delimiter.
func (f *fakeBackupStore) ListPage(_ context.Context, q objectstore.ListQuery) (objectstore.ListPage, error) {
	f.queries = append(f.queries, q)
	if err := f.fail[q.Prefix]; err != nil {
		return objectstore.ListPage{}, err
	}
	keys := make([]string, 0, len(f.newest))
	for key := range f.newest {
		if strings.HasPrefix(key, q.Prefix) && key > q.StartAfter {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	type entry struct {
		prefix string
		object objectstore.ListedObject
	}
	var entries []entry
	for _, key := range keys {
		if q.Delimiter != "" {
			if i := strings.Index(key[len(q.Prefix):], q.Delimiter); i >= 0 {
				prefix := key[:len(q.Prefix)+i+len(q.Delimiter)]
				if len(entries) == 0 || entries[len(entries)-1].prefix != prefix {
					entries = append(entries, entry{prefix: prefix})
				}
				continue
			}
		}
		entries = append(entries, entry{object: objectstore.ListedObject{Key: key, LastModified: f.newest[key]}})
	}
	size := f.pageSize
	if size == 0 {
		size = 1000
	}
	start := 0
	if q.Token != "" {
		start, _ = strconv.Atoi(q.Token)
	}
	var page objectstore.ListPage
	end := min(start+size, len(entries))
	for _, e := range entries[start:end] {
		if e.prefix != "" {
			page.Prefixes = append(page.Prefixes, e.prefix)
		} else {
			page.Objects = append(page.Objects, e.object)
		}
	}
	if end < len(entries) {
		page.Next = strconv.Itoa(end)
	}
	return page, nil
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

// walArchive fills store with an archive of stanza: dirs WAL directories of timeline 1 in archive ID 16-1 with three
// segments each, the newest segment archived at newest, plus an older archive ID and the files pgBackRest keeps next
// to the directories.
func walArchive(store *fakeBackupStore, stanza string, dirs int, newest time.Time) {
	root := backup.WALArchivePrefix(stanza)
	store.newest[root+"archive.info"] = newest.Add(-30 * 24 * time.Hour)
	store.newest[root+"9-1/0000000100000099/000000010000009900000001-aa"] = newest.Add(-40 * 24 * time.Hour)
	store.newest[root+"16-1/00000002.history"] = newest.Add(-20 * 24 * time.Hour)
	for d := range dirs {
		for seg := range 3 {
			at := newest.Add(-time.Duration((dirs-1-d)*3+(2-seg)) * time.Minute)
			store.newest[fmt.Sprintf("%s16-1/00000001%08X/00000001%08X%08X-%040x.gz", root, d, d, seg, seg)] = at
		}
	}
}

// TestBackupsWALArchiveAge (PDK-015): the worker exports the time of the newest archived WAL segment of each stanza,
// 0 for a stanza without an archive.
func TestBackupsWALArchiveAge(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	store := &fakeBackupStore{puts: map[string][]byte{}, newest: map[string]time.Time{"openbao/x": now}}
	walArchive(store, "paddock", 5, now.Add(-2*time.Minute))
	b, _ := newBackupsForTest(store, &fakeSnapshotter{data: "s"}, fakeLock{}, now)
	if err := b.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(metricWALLastArchived.WithLabelValues("paddock")); got != float64(now.Add(-2*time.Minute).Unix()) {
		t.Errorf("paddock: gauge %v, want %v", got, now.Add(-2*time.Minute).Unix())
	}
	if got := testutil.ToFloat64(metricWALLastArchived.WithLabelValues("authentik")); got != 0 {
		t.Errorf("authentik without archive: gauge %v, want 0", got)
	}

	// A later timeline (after a restore) sorts after the current one and is taken from the next round on.
	store.newest[backup.WALArchivePrefix("paddock")+"16-1/0000000200000004/000000020000000400000001-ff.gz"] = now
	if err := b.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(metricWALLastArchived.WithLabelValues("paddock")); got != float64(now.Unix()) {
		t.Errorf("paddock after the new timeline: gauge %v, want %v", got, now.Unix())
	}
}

// TestBackupsWALArchiveListingIsBounded (PDK-015): the worker never lists the whole WAL archive. The first round lists
// the directories once, every later round only from the newest directory on, and the segments of that directory only.
func TestBackupsWALArchiveListingIsBounded(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	store := &fakeBackupStore{puts: map[string][]byte{}, newest: map[string]time.Time{"openbao/x": now}, pageSize: 4}
	const dirs = 30
	walArchive(store, "paddock", dirs, now.Add(-time.Minute))
	root := backup.WALArchivePrefix("paddock")
	newestDir := fmt.Sprintf("%s16-1/00000001%08X/", root, dirs-1)
	b, _ := newBackupsForTest(store, &fakeSnapshotter{data: "s"}, fakeLock{}, now)

	for round := 1; round <= 3; round++ {
		store.queries = nil
		if err := b.Round(context.Background()); err != nil {
			t.Fatal(err)
		}
		if got := testutil.ToFloat64(metricWALLastArchived.WithLabelValues("paddock")); got != float64(now.Add(-time.Minute).Unix()) {
			t.Fatalf("round %d: gauge %v, want %v", round, got, now.Add(-time.Minute).Unix())
		}
		dirPages := 0
		for _, q := range store.queries {
			if !strings.HasPrefix(q.Prefix, root) {
				continue
			}
			if q.Delimiter == "" && q.Prefix != newestDir {
				t.Fatalf("round %d: listing without delimiter outside the newest WAL directory: %+v", round, q)
			}
			if q.Prefix == root+"16-1/" {
				dirPages++
				if round > 1 && q.StartAfter != strings.TrimSuffix(newestDir, "/") {
					t.Fatalf("round %d: directory listing without StartAfter on the newest directory: %+v", round, q)
				}
			}
		}
		// 30 directories and one .history file in pages of 4: 8 pages in the first round, 1 afterwards.
		want := 1
		if round == 1 {
			want = 8
		}
		if dirPages != want {
			t.Fatalf("round %d: %d pages of the directory listing, want %d", round, dirPages, want)
		}
	}
}

// TestBackupsWALArchivePageBound: a directory listing longer than walListPages pages is read in parts over several
// rounds, each continuing from the newest directory seen, instead of in one unbounded listing.
func TestBackupsWALArchivePageBound(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	store := &fakeBackupStore{puts: map[string][]byte{}, newest: map[string]time.Time{"openbao/x": now}, pageSize: 2}
	walArchive(store, "paddock", 3*walListPages*2, now)
	b, _ := newBackupsForTest(store, &fakeSnapshotter{data: "s"}, fakeLock{}, now)
	var gauges []float64
	for range 4 {
		store.queries = nil
		if err := b.Round(context.Background()); err != nil {
			t.Fatal(err)
		}
		for _, q := range store.queries {
			if q.Prefix == backup.WALArchivePrefix("paddock")+"16-1/" && q.Token == "" {
				pages := 0
				for _, r := range store.queries {
					if r.Prefix == q.Prefix && r.StartAfter == q.StartAfter {
						pages++
					}
				}
				if pages > walListPages {
					t.Fatalf("%d pages in one listing, bound %d", pages, walListPages)
				}
			}
		}
		gauges = append(gauges, testutil.ToFloat64(metricWALLastArchived.WithLabelValues("paddock")))
	}
	if gauges[0] >= gauges[1] || gauges[1] >= gauges[2] || gauges[3] != float64(now.Unix()) {
		t.Fatalf("gauges %v: want rising to %v", gauges, now.Unix())
	}
}

// TestBackupsWALArchiveError: a stanza whose archive cannot be listed is reported and keeps the other stanza's age.
func TestBackupsWALArchiveError(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	store := &fakeBackupStore{puts: map[string][]byte{}, newest: map[string]time.Time{"openbao/x": now},
		fail: map[string]error{backup.WALArchivePrefix("authentik"): errors.New("AccessDenied")}}
	walArchive(store, "paddock", 2, now.Add(-3*time.Minute))
	b, _ := newBackupsForTest(store, &fakeSnapshotter{data: "s"}, fakeLock{}, now)
	err := b.Round(context.Background())
	if err == nil || !strings.Contains(err.Error(), "wal archive age authentik") {
		t.Fatalf("expected the authentik error, got %v", err)
	}
	if got := testutil.ToFloat64(metricWALLastArchived.WithLabelValues("paddock")); got != float64(now.Add(-3*time.Minute).Unix()) {
		t.Fatalf("paddock age %v not exported", got)
	}
}
