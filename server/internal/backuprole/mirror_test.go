package backuprole

import (
	"bytes"
	"context"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/phischl/paddock-mdm/server/internal/backup"
	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
	"github.com/phischl/paddock-mdm/server/internal/platform/objectstore"
)

// testManifest returns a valid manifest.json of installation; mutate may fill its contents.
func testManifest(t *testing.T, installation string, mutate func(m *backupset.Manifest)) []byte {
	t.Helper()
	m := backupset.Manifest{Schema: backupset.ManifestSchema, InstallationID: installation, ServerVersion: "0.1.0-test",
		GeneratedAt: time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC), KeyID: testKeyID,
		KeyFingerprint: backupset.Fingerprint(testKey)}
	m.Contents.PgBackRest.Path = backupset.RepoPath(testKeyID)
	if mutate != nil {
		mutate(&m)
	}
	b, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// openSet writes files into a new repository and returns it with its index.
func openSet(t *testing.T, files map[string]string) (*os.Root, repoIndex) {
	t.Helper()
	dir := t.TempDir()
	for p, body := range files {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, p), []byte(body), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	repo, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	idx, err := indexRepo(repo)
	if err != nil {
		t.Fatal(err)
	}
	return repo, idx
}

// testRetention is the retention of a round at now with the default schedule's numbers (retention_full 2, a daily
// full backup, 30 keep days) and the active key testKeyID; the round's manifest was written.
func testRetention(now time.Time) retention {
	return retention{active: backupset.RepoPath(testKeyID), retired: map[string]time.Time{},
		known: map[string]bool{backupset.RepoPath(testKeyID): true}, full: 2, keep: 2 * 24 * time.Hour,
		kindKeep: map[string]time.Duration{"openbao/": 30 * 24 * time.Hour, "fleet/": 30 * 24 * time.Hour},
		walOK:    map[string]bool{}, manifestOK: true, now: now}
}

func noHooks() mirrorHooks {
	return mirrorHooks{tick: func() {}, phase: func(string) {}, begin: func(int64) {}, end: func() {},
		stop: func() bool { return false }}
}

func mirror(t *testing.T, repo *os.Root, idx repoIndex, dst Target, pushed map[string]fileInfo) error {
	t.Helper()
	_, err := mirrorSet(context.Background(), repo, idx, dst, pushed, testRetention(time.Now()), noHooks())
	return err
}

// TestMirrorRefusesForeignSet: a target whose manifest belongs to another installation, or does not parse, is
// neither written nor cleaned, and fails with the class foreign_set.
func TestMirrorRefusesForeignSet(t *testing.T) {
	repo, idx := openSet(t, map[string]string{"openbao/20261104T100000Z.snap.enc": "new",
		backupset.ManifestPath: string(testManifest(t, InstallationID(42), nil))})
	for name, remote := range map[string][]byte{
		"other installation": testManifest(t, InstallationID(7), nil),
		"unparseable":        []byte("{}"),
	} {
		t.Run(name, func(t *testing.T) {
			dst := newMemTarget()
			dst.files = map[string][]byte{backupset.ManifestPath: remote, "openbao/20260101T000000Z.snap.enc": []byte("old")}
			err := mirror(t, repo, idx, dst, map[string]fileInfo{})
			if ErrorClass(err) != ClassForeignSet {
				t.Fatalf("error %v (%s), want %s", err, ErrorClass(err), ClassForeignSet)
			}
			if len(dst.ops) != 0 || !bytes.Equal(dst.files[backupset.ManifestPath], remote) {
				t.Errorf("the foreign set was changed: %v", dst.ops)
			}
		})
	}
}

// TestMirrorShrunkSetWritesNothing: after a lost repository volume the stanza is created again and its info files
// differ from the target's; the shrink guard runs before the first write, so the target keeps every byte, its
// pgBackRest info files included, and the mirror fails with set_shrunk.
func TestMirrorShrunkSetWritesNothing(t *testing.T) {
	path := backupset.RepoPath(testKeyID)
	theirs := testManifest(t, InstallationID(42), func(m *backupset.Manifest) {
		m.Contents.PgBackRest.Stanzas = []backupset.Stanza{{Name: "paddock", LastFull: "20261101-010000F"}}
	})
	dst := newMemTarget()
	dst.files = map[string][]byte{backupset.ManifestPath: theirs,
		path + "/backup/paddock/20261101-010000F/backup.manifest": []byte("m"),
		path + "/backup/paddock/backup.info":                      []byte("lists 20261101-010000F"),
		path + "/backup/paddock/backup.info.copy":                 []byte("lists 20261101-010000F"),
		path + "/archive/paddock/archive.info":                    []byte("db-id=1 system-id=7")}
	before := maps.Clone(dst.files)
	repo, idx := openSet(t, map[string]string{backupset.ManifestPath: string(testManifest(t, InstallationID(42), nil)),
		path + "/backup/paddock/backup.info":      "empty",
		path + "/backup/paddock/backup.info.copy": "empty",
		path + "/archive/paddock/archive.info":    "db-id=1 system-id=9",
		"openbao/20261105T060000Z.snap.enc":       "new"})
	if err := mirror(t, repo, idx, dst, map[string]fileInfo{}); ErrorClass(err) != ClassSetShrunk {
		t.Fatalf("error %v (%s), want %s", err, ErrorClass(err), ClassSetShrunk)
	}
	if len(dst.ops) != 0 || !maps.EqualFunc(dst.files, before, bytes.Equal) {
		t.Errorf("a shrunk set changed the target: %v", dst.ops)
	}
}

// TestMirrorRewrittenInfoAndManifestHash: pgBackRest's info files are copied again after an in-place rewrite of the
// same size, a target's manifest of the same size but other content is replaced, and a manifest that does not read
// back with the written SHA-256 fails the mirror (plan M15 decision 16 e).
func TestMirrorRewrittenInfoAndManifestHash(t *testing.T) {
	manifest := testManifest(t, InstallationID(42), nil)
	info := "pgbackrest/" + testKeyID + "/backup/paddock/backup.info"
	repo, idx := openSet(t, map[string]string{info: "v1", info + ".copy": "v1", backupset.ManifestPath: string(manifest)})
	dst := newMemTarget()
	pushed := map[string]fileInfo{}
	if err := mirror(t, repo, idx, dst, pushed); err != nil {
		t.Fatal(err)
	}
	dst.ops = nil
	if err := mirror(t, repo, idx, dst, pushed); err != nil || len(dst.ops) != 0 {
		t.Fatalf("an unchanged set was copied again: %v, %v", dst.ops, err)
	}
	later := time.Now().Add(time.Minute)
	for _, p := range []string{info, info + ".copy"} {
		if err := repo.WriteFile(p, []byte("v2"), 0o640); err != nil {
			t.Fatal(err)
		}
		if err := repo.Chtimes(p, later, later); err != nil {
			t.Fatal(err)
		}
	}
	tampered := bytes.Clone(manifest)
	tampered[len(tampered)-2] = ' '
	dst.files[backupset.ManifestPath] = tampered
	idx, err := indexRepo(repo)
	if err != nil {
		t.Fatal(err)
	}
	if err := mirror(t, repo, idx, dst, pushed); err != nil {
		t.Fatal(err)
	}
	if string(dst.files[info]) != "v2" || string(dst.files[info+".copy"]) != "v2" ||
		!bytes.Equal(dst.files[backupset.ManifestPath], manifest) {
		t.Errorf("target after the rewrite: ops %v", dst.ops)
	}

	bad := newMemTarget()
	bad.garble = true
	if err := mirror(t, repo, idx, bad, map[string]fileInfo{}); err == nil || !strings.Contains(err.Error(), "manifest") {
		t.Errorf("a garbled manifest passed: %v", err)
	}
}

// TestEscrowSkipsDiagnostics: diagnostics bundles share the escrow bucket but are never mirrored; the role's
// credential could not read them, and the escrow run still succeeds.
func TestEscrowSkipsDiagnostics(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	f.escrow["org/o1/devices/d1/diagnostics/20261104T090000Z.tar.gz"] = "personal data"
	f.round(t)
	r, ok := f.store.run(KindEscrow)
	if !ok || !r.Succeeded || r.Bytes != int64(len("header")) {
		t.Errorf("escrow run %+v", r)
	}
	files := f.repoFiles(t)
	for p := range files {
		if strings.Contains(p, "diagnostics") {
			t.Errorf("a diagnostics bundle reached the set: %s", p)
		}
	}
	if _, ok := files["escrow/org/o1/devices/d1/luks-header/1.bin"]; !ok {
		t.Error("the header was not copied")
	}
}

// TestDirTargetPlantedSymlinks: symlinks planted on a share never lead the role out of the volume: a paddock-backup
// symlink fails the mirror, and the probe files and the marker are never followed (PDK-732 review, finding 2).
func TestDirTargetPlantedSymlinks(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	victim := filepath.Join(base, "runtime")
	if err := os.Mkdir(victim, 0o750); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(victim, "key")
	if err := os.WriteFile(keyFile, []byte("secret"), 0o640); err != nil {
		t.Fatal(err)
	}
	targets := filepath.Join(base, "targets")
	rec := TargetRecord{HostRevision: 1}
	mount := MountDir(targets, rec)
	if err := os.MkdirAll(mount, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mount, markerFile), []byte("1"), 0o640); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{probeFile, testFile} {
		if err := os.Symlink(keyFile, filepath.Join(mount, name)); err != nil {
			t.Fatal(err)
		}
	}
	if got := HostState(targets, rec); got != HostMounted {
		t.Errorf("host state %s", got)
	}
	d := NewDirTarget(filepath.Join(mount, backupset.SetRoot))
	if err := d.Probe(ctx); err != nil {
		t.Errorf("probe: %v", err)
	}
	if err := os.Symlink(victim, filepath.Join(mount, backupset.SetRoot)); err != nil {
		t.Fatal(err)
	}
	repo, idx := openSet(t, map[string]string{"openbao/20261104T100000Z.snap.enc": "x",
		backupset.ManifestPath: string(testManifest(t, InstallationID(42), nil))})
	if err := mirror(t, repo, idx, d, map[string]fileInfo{}); err == nil {
		t.Error("a mirror through a planted paddock-backup symlink succeeded")
	}
	if b, err := os.ReadFile(keyFile); err != nil || string(b) != "secret" { //nolint:gosec // test file
		t.Errorf("the file outside the volume changed: %q, %v", b, err)
	}
	if entries, _ := os.ReadDir(victim); len(entries) != 1 {
		t.Errorf("the directory outside the volume holds %d entries", len(entries))
	}

	if err := os.Remove(filepath.Join(mount, markerFile)); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "marker")
	if err := os.WriteFile(outside, []byte("1"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(mount, markerFile)); err != nil {
		t.Fatal(err)
	}
	if got := HostState(targets, rec); got != HostPending {
		t.Errorf("a marker symlinked out of the volume counted: %s", got)
	}
}

// fakeS3 is an S3Store in memory.
type fakeS3 struct{ objects map[string]string }

func (f *fakeS3) Ping(context.Context) error { return nil }
func (f *fakeS3) ListSizes(_ context.Context, prefix string) (map[string]int64, error) {
	out := map[string]int64{}
	for k, v := range f.objects {
		if strings.HasPrefix(k, prefix) {
			out[k] = int64(len(v))
		}
	}
	return out, nil
}
func (f *fakeS3) ListSizesPaged(ctx context.Context, prefix string, page func()) (map[string]int64, error) {
	out, err := f.ListSizes(ctx, prefix)
	for range out {
		page()
	}
	return out, err
}
func (f *fakeS3) Newest(context.Context, string) (time.Time, bool, error) {
	return time.Time{}, false, nil
}
func (f *fakeS3) Open(_ context.Context, key string) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(f.objects[key])), nil
}
func (f *fakeS3) PutReader(_ context.Context, key string, body io.ReadSeeker, _ int64) error {
	b, err := io.ReadAll(body)
	f.objects[key] = string(b)
	return err
}
func (f *fakeS3) Delete(_ context.Context, key string) error {
	delete(f.objects, key)
	return nil
}

// TestS3TargetSkipsUnusableKeys: an object below the set's prefix whose key the role could neither write nor delete
// is left out of the listing, so it cannot fail every round.
func TestS3TargetSkipsUnusableKeys(t *testing.T) {
	s3 := &fakeS3{objects: map[string]string{"site/paddock-backup/a//b": "x", "site/paddock-backup/fleet/f.enc": "y"}}
	got, err := NewS3Target(s3, "site").List(context.Background())
	if err != nil || len(got) != 1 || got["fleet/f.enc"] != 1 {
		t.Errorf("list %v, %v", got, err)
	}
}

// blockingTarget is a target whose Put blocks until release is closed, as a hard-mounted share that went away.
type blockingTarget struct {
	*memTarget
	release chan struct{}
	mu      sync.Mutex
	puts    int
}

func (b *blockingTarget) Put(ctx context.Context, p string, r io.Reader, size int64) error {
	b.mu.Lock()
	b.puts++
	b.mu.Unlock()
	<-b.release
	return errors.New("share gone")
}

// TestStalledTargetDoesNotBlockTheRound: a target that stalls fails after the stall deadline while the other target
// still receives the set and the runs are recorded; the next round skips the still blocked target instead of
// starting a second mirror to it (PDK-732 review, finding 5).
func TestStalledTargetDoesNotBlockTheRound(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	// The stall deadline also applies to the reachable target, whose mirror must tick within it even on a starved
	// host; 50 ms was shorter than a scheduling delay under load and failed the good target instead of the stuck one.
	f.engine.stall = time.Second
	stuck := &blockingTarget{memTarget: newMemTarget(), release: make(chan struct{})}
	releaseOnce := sync.OnceFunc(func() { close(stuck.release) })
	t.Cleanup(releaseOnce)
	good := newMemTarget()
	stuckRec := f.addTarget(t, backupset.TypeNFS, stuck)
	f.addTarget(t, backupset.TypeS3, good)
	// The stuck target stays blocked until the end of the test, so a round that returns at all was not held by it; a
	// wall-clock bound on the round only measured host load.
	roundDone := make(chan error, 1)
	go func() { roundDone <- f.engine.Round(context.Background()) }()
	select {
	case err := <-roundDone:
		if err != nil {
			t.Fatalf("round: %v", err)
		}
	case <-time.After(time.Minute):
		t.Fatal("the round stayed blocked by the stalled target")
	}
	if _, ok := good.files[backupset.ManifestPath]; !ok {
		t.Error("the reachable target got no manifest")
	}
	r, ok := f.store.run(KindOpenBao)
	if !ok {
		t.Fatal("no run recorded")
	}
	for _, rt := range r.Targets {
		if rt.TargetID == stuckRec.ID.String() && (rt.OK || rt.ErrorClass != ClassIO) {
			t.Errorf("stalled target %+v", rt)
		}
	}
	f.round(t)
	stuck.mu.Lock()
	puts := stuck.puts
	stuck.mu.Unlock()
	if puts != 1 {
		t.Errorf("puts to the stalled target %d, want 1", puts)
	}
	releaseOnce()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		f.engine.busyMu.Lock()
		busy := f.engine.busy[stuckRec.ID]
		f.engine.busyMu.Unlock()
		if !busy {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("the target stayed busy after its call returned")
}

// TestFleetSealFailureBacksOff: a dump whose sealing fails is tried once per retryAfter, not every round, and its
// plaintext is deleted with a failed run once it is older than fleetPlainMaxAge (PDK-732 review, finding 4).
func TestFleetSealFailureBacksOff(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	f.store.history[KindOpenBao] = KindHistory{LastAttempt: f.now, LastSuccess: f.now}
	f.store.history[KindEscrow] = KindHistory{LastAttempt: f.now, LastSuccess: f.now}
	dump := filepath.Join(f.cfg.FleetDumpsDir, "20261104T095900Z.sql.gz")
	if err := os.WriteFile(dump, []byte("dump"), 0o640); err != nil {
		t.Fatal(err)
	}
	// A file where the sealed dumps' directory belongs makes every sealing fail.
	if err := os.WriteFile(filepath.Join(f.cfg.RepoDir, "fleet"), []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	failedRuns := func() int {
		n := 0
		for _, r := range f.store.runs {
			if r.Kind == KindFleet && !r.Succeeded {
				n++
			}
		}
		return n
	}
	f.round(t)
	f.now = f.now.Add(time.Minute)
	f.round(t)
	if n := failedRuns(); n != 1 {
		t.Fatalf("failed fleet runs after two rounds: %d, want 1", n)
	}
	if _, err := os.Stat(filepath.Join(f.cfg.FleetDumpsDir, fleetRequestFile)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a dump was requested while one waits: %v", err)
	}
	f.now = f.now.Add(retryAfter)
	f.round(t)
	if n := failedRuns(); n != 2 {
		t.Errorf("failed fleet runs after the back-off: %d, want 2", n)
	}
	f.now = time.Date(2026, 11, 4, 9, 59, 0, 0, time.UTC).Add(fleetPlainMaxAge + time.Minute)
	f.round(t)
	if _, err := os.Stat(dump); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the plaintext outlived %s: %v", fleetPlainMaxAge, err)
	}
	if n := failedRuns(); n != 3 {
		t.Errorf("failed fleet runs after the deletion: %d, want 3", n)
	}
}

// TestStaleDumpDeletedWithoutKey: without a confirmed key nothing seals a waiting dump, so it is deleted once it is
// older than fleetPlainMaxAge, and nothing is recorded.
func TestStaleDumpDeletedWithoutKey(t *testing.T) {
	f := newFixture(t)
	old := filepath.Join(f.cfg.FleetDumpsDir, "20261104T000000Z.sql.gz")
	fresh := filepath.Join(f.cfg.FleetDumpsDir, "20261104T095000Z.sql.gz")
	for _, p := range []string{old, fresh} {
		if err := os.WriteFile(p, []byte("dump"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	f.round(t)
	if _, err := os.Stat(old); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the stale plaintext stayed: %v", err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("the fresh dump was deleted: %v", err)
	}
	if len(f.store.runs) != 0 {
		t.Errorf("runs recorded without a key: %+v", f.store.runs)
	}
}

// TestFleetRequestTimeout: a dump request fleet-backup does not answer within requestTimeout (Fleet's schema missing,
// mysqldump failing) fails once and is withdrawn (PDK-732 review, minor 9).
func TestFleetRequestTimeout(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	f.store.history[KindOpenBao] = KindHistory{LastAttempt: f.now, LastSuccess: f.now}
	f.store.history[KindEscrow] = KindHistory{LastAttempt: f.now, LastSuccess: f.now}
	req := filepath.Join(f.cfg.FleetDumpsDir, fleetRequestFile)
	f.round(t)
	if _, err := os.Stat(req); err != nil {
		t.Fatalf("no dump requested: %v", err)
	}
	f.now = f.now.Add(requestTimeout - time.Minute)
	f.round(t)
	if _, ok := f.store.run(KindFleet); ok {
		t.Fatal("the request failed before its timeout")
	}
	f.now = f.now.Add(2 * time.Minute)
	f.round(t)
	r, ok := f.store.run(KindFleet)
	if !ok || r.Succeeded || r.ErrorClass != runClassTimeout {
		t.Errorf("fleet run %+v", r)
	}
	if _, err := os.Stat(req); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the unanswered request stayed: %v", err)
	}
}

// TestExpireKeepsNewestAndWaitsForActiveFull: the newest OpenBao snapshot and Fleet dump stay whatever their age, and a
// retired key's repository past its retention stays until the active key's repository holds a full backup of both
// stanzas (PDK-732 review, finding 6).
func TestExpireKeepsNewestAndWaitsForActiveFull(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	f.store.history[KindOpenBao] = KindHistory{LastAttempt: f.now, LastSuccess: f.now}
	f.store.history[KindEscrow] = KindHistory{LastAttempt: f.now, LastSuccess: f.now}
	f.store.history[KindFleet] = KindHistory{LastAttempt: f.now, LastSuccess: f.now}
	older, old := f.now.Add(-60*24*time.Hour), f.now.Add(-40*24*time.Hour)
	retired := "bk-20260101-00000001"
	f.store.retired = []string{retired}
	sealed, err := backup.Seal(testKey, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	write := func(p string, at time.Time) {
		full := filepath.Join(f.cfg.RepoDir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, sealed, 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(full, at, at); err != nil {
			t.Fatal(err)
		}
	}
	for _, at := range []time.Time{older, old} {
		write(backupset.OpenBaoKey(at), at)
		write(backupset.FleetKey(at), at)
	}
	write("pgbackrest/"+retired+"/backup/paddock/20260101-000000F/backup.manifest", old)
	write("pgbackrest/"+testKeyID+"/backup/paddock/20261104-000000F/backup.manifest", f.now)
	f.round(t)
	files := f.repoFiles(t)
	for p, want := range map[string]bool{backupset.OpenBaoKey(older): false, backupset.OpenBaoKey(old): true,
		backupset.FleetKey(older): false, backupset.FleetKey(old): true,
		"pgbackrest/" + retired + "/backup/paddock/20260101-000000F/backup.manifest": true} {
		if _, ok := files[p]; ok != want {
			t.Errorf("%s present %v, want %v", p, ok, want)
		}
	}
	write("pgbackrest/"+testKeyID+"/backup/authentik/20261104-000000F/backup.manifest", f.now)
	f.round(t)
	if _, ok := f.repoFiles(t)["pgbackrest/"+retired+"/backup/paddock/20260101-000000F/backup.manifest"]; ok {
		t.Error("the retired repository stayed once the active one held both full backups")
	}
}

// TestHostCheckInFlight: while a volume's previous host check has not returned (a hung share), the round reports the
// target unreachable without starting another check.
func TestHostCheckInFlight(t *testing.T) {
	f := newFixture(t)
	rec := f.addTarget(t, backupset.TypeSMB, newMemTarget())
	f.engine.checking[rec.ID] = true
	f.round(t)
	if f.store.hostState[rec.ID] != HostUnreachable {
		t.Errorf("host state %q", f.store.hostState[rec.ID])
	}
	if _, err := os.Stat(filepath.Join(MountDir(f.cfg.TargetsDir, rec), probeFile)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("probe file: %v", err)
	}
}

// incompleteFull writes a running or aborted pgBackRest full backup: backup.manifest.copy and data, no
// backup.manifest.
func incompleteFull(dir string) map[string]string {
	return map[string]string{dir + "/backup.manifest.copy": "c", dir + "/pg_data/base/1/1.gz": "data"}
}

// TestIncompleteFullIsNoFull: a label directory without backup.manifest is not a full backup, neither for the shrunk
// guard, nor for the expiry of a retired key's repository, nor for manifest.json's last_full (PDK-732 review 2,
// finding 1).
func TestIncompleteFullIsNoFull(t *testing.T) {
	path := backupset.RepoPath(testKeyID)
	t.Run("newestFull", func(t *testing.T) {
		files := incompleteFull(path + "/backup/paddock/20261105-010000F")
		files[path+"/backup/paddock/20261101-010000F/backup.manifest"] = "m"
		_, idx := openSet(t, files)
		if label, _ := idx.newestFull(path, "paddock"); label != "20261101-010000F" {
			t.Errorf("newest full %q, want the completed 20261101-010000F", label)
		}
	})
	t.Run("shrunk", func(t *testing.T) {
		theirs := testManifest(t, InstallationID(42), func(m *backupset.Manifest) {
			m.Contents.PgBackRest.Stanzas = []backupset.Stanza{{Name: "paddock", LastFull: "20261101-010000F"}}
		})
		dst := newMemTarget()
		dst.files = map[string][]byte{backupset.ManifestPath: theirs,
			path + "/backup/paddock/20261101-010000F/backup.manifest": []byte("m")}
		files := incompleteFull(path + "/backup/paddock/20261105-010000F")
		maps.Copy(files, incompleteFull(path+"/backup/paddock/20261101-010000F"))
		files[backupset.ManifestPath] = string(testManifest(t, InstallationID(42), nil))
		repo, idx := openSet(t, files)
		if err := mirror(t, repo, idx, dst, map[string]fileInfo{}); ErrorClass(err) != ClassSetShrunk {
			t.Fatalf("error %v (%s), want %s", err, ErrorClass(err), ClassSetShrunk)
		}
		if _, ok := dst.files[path+"/backup/paddock/20261101-010000F/backup.manifest"]; !ok ||
			!bytes.Equal(dst.files[backupset.ManifestPath], theirs) {
			t.Errorf("the target's last complete full backup was dropped: %v", dst.ops)
		}
	})
	t.Run("expire and manifest", func(t *testing.T) {
		f := newFixture(t)
		f.confirmKey()
		retired := "bk-20260101-00000001"
		f.store.retired = []string{retired}
		files := map[string]string{"pgbackrest/" + retired + "/backup/paddock/20260101-000000F/backup.manifest": "m",
			path + "/backup/paddock/20261101-010000F/backup.manifest": "m"}
		maps.Copy(files, incompleteFull(path+"/backup/paddock/20261104-010000F"))
		maps.Copy(files, incompleteFull(path+"/backup/authentik/20261104-010000F"))
		old := f.now.Add(-60 * 24 * time.Hour)
		for p, body := range files {
			full := filepath.Join(f.cfg.RepoDir, p)
			if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, []byte(body), 0o640); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(full, old, old); err != nil {
				t.Fatal(err)
			}
		}
		f.round(t)
		got := f.repoFiles(t)
		if _, ok := got["pgbackrest/"+retired+"/backup/paddock/20260101-000000F/backup.manifest"]; !ok {
			t.Error("a retired repository was expired while the active one holds no completed full of authentik")
		}
		m, err := backupset.Parse(got[backupset.ManifestPath])
		if err != nil {
			t.Fatal(err)
		}
		last := map[string]string{}
		for _, st := range m.Contents.PgBackRest.Stanzas {
			last[st.Name] = st.LastFull
		}
		if last["paddock"] != "20261101-010000F" || last["authentik"] != "" {
			t.Errorf("manifest last_full %v, want only the completed paddock full", last)
		}
	})
}

// within fails the test unless fn returns within 5 s: a call blocked on a planted FIFO would never return.
func within(t *testing.T, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s blocked on a planted FIFO", what)
	}
}

// TestDirTargetPlantedFIFOs: a FIFO planted on the share under a temporary file's name, as manifest.json or as the
// host marker neither blocks a write, a read nor the host check (PDK-732 review 2, finding 3).
func TestDirTargetPlantedFIFOs(t *testing.T) {
	mount := t.TempDir()
	set := filepath.Join(mount, "paddock-backup")
	if err := os.Mkdir(set, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(set, tmpPrefix+"file"), filepath.Join(set, backupset.ManifestPath),
		filepath.Join(mount, markerFile)} {
		if err := syscall.Mkfifo(p, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	dst := NewDirTarget(set)
	ctx := context.Background()
	within(t, "Put", func() {
		if err := dst.Put(ctx, "file", strings.NewReader("data"), 4); err != nil {
			t.Errorf("put: %v", err)
		}
	})
	if b, err := os.ReadFile(filepath.Join(set, "file")); err != nil || string(b) != "data" {
		t.Errorf("written file %q, %v", b, err)
	}
	within(t, "Read", func() {
		if _, _, err := dst.Read(ctx, backupset.ManifestPath); !errors.Is(err, errPlanted) {
			t.Errorf("read of a FIFO: %v, want %v", err, errPlanted)
		}
	})
	within(t, "host check", func() {
		if got := hostState(mount, 1); got != HostPending {
			t.Errorf("host state with a FIFO marker %q, want %q", got, HostPending)
		}
	})
}

// cancelTarget cancels the mirror's context on its first Put, as the round's end does to a mirror that outlived it.
type cancelTarget struct {
	*memTarget
	cancel context.CancelFunc
}

func (c *cancelTarget) Put(ctx context.Context, p string, r io.Reader, size int64) error {
	c.cancel()
	return c.memTarget.Put(ctx, p, r, size)
}

// TestMirrorStopsWithItsContext: a mirror whose context ended copies, writes the manifest and deletes nothing more
// (PDK-732 review 2, finding 4).
func TestMirrorStopsWithItsContext(t *testing.T) {
	repo, idx := openSet(t, map[string]string{backupset.ManifestPath: string(testManifest(t, InstallationID(42), nil)),
		"openbao/20261105T060000Z.snap.enc": "a", "openbao/20261105T070000Z.snap.enc": "b"})
	t.Run("put loop", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		dst := &cancelTarget{memTarget: newMemTarget(), cancel: cancel}
		_, err := mirrorSet(ctx, repo, idx, dst, map[string]fileInfo{}, testRetention(time.Now()), noHooks())
		if !errors.Is(err, context.Canceled) || len(dst.ops) != 1 {
			t.Errorf("error %v, ops %v; want one put and context.Canceled", err, dst.ops)
		}
	})
	t.Run("delete loop", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		dst := &cancelOnList{memTarget: newMemTarget(), cancel: cancel, at: 2}
		if err := mirror(t, repo, idx, dst.memTarget, map[string]fileInfo{}); err != nil {
			t.Fatal(err)
		}
		dst.files["openbao/20260101T000000Z.snap.enc"] = []byte("old")
		dst.files["openbao/20260102T000000Z.snap.enc"] = []byte("old")
		dst.ops = nil
		_, err := mirrorSet(ctx, repo, idx, dst, map[string]fileInfo{}, testRetention(time.Now()), noHooks())
		if !errors.Is(err, context.Canceled) || len(dst.ops) != 0 {
			t.Errorf("error %v, ops %v; want no deletion and context.Canceled", err, dst.ops)
		}
	})
}

// cancelOnList cancels the mirror's context on its at-th List, the one before the deletions.
type cancelOnList struct {
	*memTarget
	cancel context.CancelFunc
	at     int
	lists  int
}

func (c *cancelOnList) List(ctx context.Context) (map[string]int64, error) {
	if c.lists++; c.lists == c.at {
		c.cancel()
	}
	return c.memTarget.List(ctx)
}

// countingTarget counts its connection tests.
type countingTarget struct {
	*memTarget
	probes atomic.Int64
}

func (c *countingTarget) Probe(ctx context.Context) error {
	c.probes.Add(1)
	return c.memTarget.Probe(ctx)
}

// TestTargetTestInFlight: while a target's previous connection test has not returned (a hung share), a repeated
// request fails with io at once instead of starting another one (PDK-732 review 2, finding 5).
func TestTargetTestInFlight(t *testing.T) {
	f := newFixture(t)
	dst := &countingTarget{memTarget: newMemTarget()}
	rec := f.addTarget(t, backupset.TypeS3, dst)
	f.store.targets[0].TestRequested = true
	f.engine.testing[rec.ID] = true
	f.round(t)
	if c, done := f.store.tests[rec.ID]; !done || c != ClassIO || dst.probes.Load() != 0 {
		t.Errorf("test result %q (%v), probes %d; want io without a probe", c, done, dst.probes.Load())
	}
	delete(f.engine.testing, rec.ID)
	f.round(t)
	if c := f.store.tests[rec.ID]; c != "" || dst.probes.Load() != 1 {
		t.Errorf("test result %q, probes %d; want ok after one probe", c, dst.probes.Load())
	}
}

// TestMirrorBudgetResumesNextRound: a target that is slow but progressing gets the round's budget, keeps its old
// manifest until it holds every file, and goes on next round with what it still lacks (PDK-732 review 2, finding 6).
func TestMirrorBudgetResumesNextRound(t *testing.T) {
	files := map[string]string{backupset.ManifestPath: string(testManifest(t, InstallationID(42), nil))}
	for _, h := range []string{"01", "02", "03"} {
		files["openbao/20261105T"+h+"0000Z.snap.enc"] = h
	}
	repo, idx := openSet(t, files)
	dst := newMemTarget()
	for round := 1; round <= 3; round++ {
		_, err := mirrorSet(context.Background(), repo, idx, dst, map[string]fileInfo{}, testRetention(time.Now()),
			mirrorHooks{tick: func() {}, phase: func(string) {}, begin: func(int64) {}, end: func() {},
				stop: func() bool { return true }})
		if !errors.Is(err, errBudget) || len(dst.files) != round {
			t.Fatalf("round %d: error %v, files %v", round, err, slices.Sorted(maps.Keys(dst.files)))
		}
		if _, ok := dst.files[backupset.ManifestPath]; ok {
			t.Fatalf("round %d: manifest written before the target held the set", round)
		}
	}
	if err := mirror(t, repo, idx, dst, map[string]fileInfo{}); err != nil || len(dst.files) != len(files) {
		t.Fatalf("final round: %v, files %v", err, slices.Sorted(maps.Keys(dst.files)))
	}

	f := newFixture(t)
	f.confirmKey()
	f.engine.budget = 0
	slow := newMemTarget()
	rec := f.addTarget(t, backupset.TypeS3, slow)
	f.round(t)
	r, ok := f.store.run(KindOpenBao)
	if !ok || len(r.Targets) != 1 || r.Targets[0].TargetID != rec.ID.String() || r.Targets[0].OK ||
		r.Targets[0].ErrorClass != ClassContinues {
		t.Fatalf("run targets %+v, want the slow target not ok (continues)", r.Targets)
	}
	if len(slow.ops) != 1 {
		t.Errorf("ops in a round without budget %v, want one copied file", slow.ops)
	}
	// The budget's end is no error (decisions-alpha9 item 79): no last_error, and no last success yet.
	if st := f.store.status[rec.ID.String()+"/"+KindOpenBao]; st.Error != "" || !st.LastSuccess.IsZero() {
		t.Errorf("target status %+v after the budget's end, want no error and no success", st)
	}
	if got := testutil.ToFloat64(f.metrics.reachable.WithLabelValues(rec.Name)); got != 1 {
		t.Errorf("reachable %v after the budget's end, want 1", got)
	}
}

// trickleTarget reads what it stores one byte at a time, slowly but steadily, until its context ends.
type trickleTarget struct {
	*memTarget
	every time.Duration
	done  atomic.Int64
}

func (tt *trickleTarget) Put(ctx context.Context, p string, r io.Reader, size int64) error {
	b := make([]byte, 1)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(tt.every):
		}
		if _, err := r.Read(b); err == io.EOF {
			tt.done.Add(1)
			return nil
		} else if err != nil {
			return err
		}
	}
}

// TestTricklingTargetHitsHardCap: a target that keeps making progress far below the minimum rate cannot hold the
// round past budget + size/minRate of the file it copies (plan M15, amendment 2026-11-05, A7; PDK-732 review 3).
func TestTricklingTargetHitsHardCap(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	f.engine.stall, f.engine.budget, f.engine.minRate = 200*time.Millisecond, 0, 1000
	slow := &trickleTarget{memTarget: newMemTarget(), every: 30 * time.Millisecond}
	rec := f.addTarget(t, backupset.TypeS3, slow)
	start := time.Now()
	f.round(t)
	if took := time.Since(start); took > 4*time.Second {
		t.Errorf("the round took %s", took)
	}
	r, ok := f.store.run(KindOpenBao)
	if !ok || len(r.Targets) != 1 || r.Targets[0].TargetID != rec.ID.String() || r.Targets[0].OK ||
		r.Targets[0].ErrorClass != ClassIO {
		t.Fatalf("run targets %+v, want the trickling target failed (io)", r.Targets)
	}
	// Without the cap the budget would end the mirror only after its first file.
	if n := slow.done.Load(); n != 0 {
		t.Errorf("the trickling target finished %d files; the cap did not cancel the copy in flight", n)
	}
}

// sizeTarget stores one byte less than it was given and reports success.
type sizeTarget struct{ *memTarget }

func (s sizeTarget) Put(ctx context.Context, p string, r io.Reader, size int64) error {
	if err := s.memTarget.Put(ctx, p, r, size); err != nil {
		return err
	}
	if p != backupset.ManifestPath && len(s.files[p]) > 0 {
		s.files[p] = s.files[p][1:]
	}
	return nil
}

// TestMirrorVerifiesSizesBeforeTheManifest: a target that stores another size than copied fails with size_mismatch
// before the manifest and before any delete (A3 step 4; PDK-732 review 4).
func TestMirrorVerifiesSizesBeforeTheManifest(t *testing.T) {
	repo, idx := localSet(t, set{snapAt(time.Hour): "new"})
	dst := sizeTarget{targetOf(t, set{snapAt(40 * day): "old", snapAt(35 * day): "older"}, matrixNow.Add(-day), false)}
	manifest := bytes.Clone(dst.files[backupset.ManifestPath])
	_, err := runMirror(repo, idx, dst, defaultRules())
	if ErrorClass(err) != ClassSizeMismatch {
		t.Fatalf("error %v (%s), want %s", err, ErrorClass(err), ClassSizeMismatch)
	}
	if !bytes.Equal(dst.files[backupset.ManifestPath], manifest) || len(opsOf(dst.memTarget, "delete")) != 0 {
		t.Errorf("manifest written or files deleted: %v", dst.ops)
	}
}

// TestMirrorWithoutLocalManifestDeletesNothing: a round whose local manifest could not be written copies, but neither
// writes the manifest nor deletes (A3 step 5; PDK-732 review 4).
func TestMirrorWithoutLocalManifestDeletesNothing(t *testing.T) {
	repo, idx := localSet(t, set{snapAt(time.Hour): "new"})
	dst := targetOf(t, set{snapAt(40 * day): "old", snapAt(35 * day): "older"}, matrixNow.Add(-day), false)
	manifest := bytes.Clone(dst.files[backupset.ManifestPath])
	r := defaultRules()
	r.noManifest = true
	if _, err := runMirror(repo, idx, dst, r); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(opsOf(dst, "put"), []string{snapAt(time.Hour)}) || len(opsOf(dst, "delete")) != 0 ||
		!bytes.Equal(dst.files[backupset.ManifestPath], manifest) {
		t.Errorf("ops %v", dst.ops)
	}
}

// TestMirrorSkipsRunningFull: a label directory without backup.manifest (a running backup) is not copied (A3 step 3).
func TestMirrorSkipsRunningFull(t *testing.T) {
	running := fullOf(pathA, "paddock", label2)
	delete(running, pathA+"/backup/paddock/"+label2+"/"+fullManifest)
	repo, idx := localSet(t, with(completeA(label1), running))
	dst := targetOf(t, nil, matrixNow, true)
	if _, err := runMirror(repo, idx, dst, defaultRules()); err != nil {
		t.Fatal(err)
	}
	for p := range running {
		if _, ok := dst.files[p]; ok {
			t.Errorf("copied %s of a running backup", p)
		}
	}
}

// TestWALContiguity: the local archive is contiguous across a log file boundary, not with a missing segment, and the
// role's wal_ok needs a contiguous archive and a whole-stanza verify newer than the newest full (A2).
func TestWALContiguity(t *testing.T) {
	boundary := set{}
	for _, seg := range []string{"0000000100000000000000FE", "0000000100000000000000FF", "000000010000000100000000"} {
		boundary[pathA+"/archive/paddock/18-1/x/"+seg+"-"+strings.Repeat("b", 40)+".zst"] = "w"
	}
	for name, c := range map[string]struct {
		s    set
		want bool
	}{
		"contiguous":          {walOf(pathA, "paddock", span(3, 7)...), true},
		"a log boundary":      {boundary, true},
		"a gap":               {walOf(pathA, "paddock", 3, 4, 6), false},
		"no WAL":              {nil, false},
		"a history file only": {set{pathA + "/archive/paddock/18-1/00000002.history": "h"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			_, idx := openSet(t, c.s)
			if got := idx.contiguousWAL(pathA, "paddock"); got != c.want {
				t.Errorf("contiguous %v, want %v", got, c.want)
			}
		})
	}

	f := newFixture(t)
	_, idx := openSet(t, with(fullOf(pathA, "paddock", label2), walOf(pathA, "paddock", 1, 2, 3),
		fullOf(pathA, "authentik", label2), walOf(pathA, "authentik", 1, 3)))
	full := time.Date(2026, 11, 2, 1, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		verified time.Time
		want     map[string]bool
	}{
		{time.Time{}, map[string]bool{}},
		{full.Add(-time.Hour), map[string]bool{}},
		{full.Add(time.Hour), map[string]bool{pathA + "/paddock": true}},
	} {
		for _, stanza := range []string{"paddock", "authentik"} {
			p := filepath.Join(f.cfg.StateDir, stanza, "verify-ok")
			_ = os.Remove(p)
			if !c.verified.IsZero() {
				if err := os.WriteFile(p, []byte(strconvUnix(c.verified)), 0o640); err != nil {
					t.Fatal(err)
				}
			}
		}
		if got := f.engine.walOK(idx, pathA); !maps.Equal(got, c.want) {
			t.Errorf("verify-ok %v: wal_ok %v, want %v (authentik has a gap)", c.verified, got, c.want)
		}
	}
}

// failingEscrow is an escrow bucket whose listing fails.
type failingEscrow struct{ fakeEscrow }

func (failingEscrow) ListInfo(context.Context, string) (map[string]objectstore.ObjectInfo, error) {
	return nil, errors.New("bucket unreachable")
}

// TestExpireEscrowAndRetiredAt: the local expire removes an escrowed header the bucket no longer holds only after a
// successful listing and on Destroy evidence older than the keep window that covers the copy (A2 notes b and c), and keeps a retired key's repository for the retention counted from max(newest file,
// retired_at) (plan M15, amendment 2026-11-05, A2).
func TestExpireEscrowAndRetiredAt(t *testing.T) {
	gone := escrowOf("gone")
	recent := backupset.RepoPath("bk-20261001-00000002")
	for name, listing := range map[string]bool{"listing ok": true, "listing failed": false} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.confirmKey()
			if !listing {
				f.engine.escrow = failingEscrow{f.escrow}
			}
			f.store.keys = []KeyRecord{{ID: "bk-20261001-00000002", State: "retired", RetiredAt: f.now.Add(-2 * day)}}
			f.store.evidence = map[string]time.Time{"o1/d1": f.now.Add(-15 * day)}
			for p, at := range map[string]time.Time{gone: f.now, recent + "/backup/paddock/x": f.now.Add(-20 * day)} {
				full := filepath.Join(f.cfg.RepoDir, p)
				if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, []byte("x"), 0o640); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(full, at, at); err != nil {
					t.Fatal(err)
				}
			}
			for p, body := range completeA(label9) {
				full := filepath.Join(f.cfg.RepoDir, p)
				if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, []byte(body), 0o640); err != nil {
					t.Fatal(err)
				}
			}
			// A first round, while the bucket still holds the header, records its escrow object time in the set's
			// index; without that time no Destroy covers the copy (A2 note c).
			bucketKey := strings.TrimPrefix(gone, backupset.EscrowKey(""))
			f.escrow[bucketKey] = "x"
			if err := f.engine.Round(context.Background()); err != nil && listing {
				t.Fatal(err)
			}
			delete(f.escrow, bucketKey)
			if err := f.engine.Round(context.Background()); err != nil && listing {
				t.Fatal(err)
			}
			files := f.repoFiles(t)
			if _, ok := files[gone]; ok == listing {
				t.Errorf("the header the bucket dropped present %v with listing %v", ok, listing)
			}
			if _, ok := files[recent+"/backup/paddock/x"]; !ok {
				t.Error("a repository retired 2 days ago was expired by its files' age")
			}
		})
	}
}
