package backuprole

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/phischl/paddock-mdm/server/internal/backup"
	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
	"github.com/phischl/paddock-mdm/server/internal/platform/objectstore"
)

var testKey = bytes.Repeat([]byte{7}, backup.KeySize)

const testKeyID = "bk-20261104-7f3a9c1e"

// fakeStore records what the engine writes.
type fakeStore struct {
	key       *ActiveKey
	retired   []string
	retiredAt time.Time
	keys      []KeyRecord
	schedule  backupset.Schedule
	targets   []TargetRecord
	requests  []RequestedRun
	history   map[string]KindHistory
	// runsMu guards runs, mirrorErr, duplicates and status: the mirror lanes record their results while a round runs.
	runsMu    sync.Mutex
	runs      []fakeRun
	mirrorErr error
	// duplicates counts the phase 2 writes for a run that had its results already (a second audit event).
	duplicates int
	status     map[string]KindStatus
	hostState  map[uuid.UUID]string
	tests      map[uuid.UUID]string
	// evidence is the Destroy evidence by "<org>/<device>"; evidenceErr fails the query.
	evidence    map[string]time.Time
	evidenceErr error
	// highWater is the highest device.bundle_seq; highWaterErr fails its read.
	highWater    int64
	highWaterErr error
}

func newFakeStore() *fakeStore {
	return &fakeStore{schedule: backupset.DefaultSchedule(), history: map[string]KindHistory{},
		status: map[string]KindStatus{}, hostState: map[uuid.UUID]string{}, tests: map[uuid.UUID]string{}}
}

func (s *fakeStore) ActiveKey(context.Context) (ActiveKey, bool, error) {
	if s.key == nil {
		return ActiveKey{}, false, nil
	}
	return *s.key, true, nil
}
func (s *fakeStore) Keys(context.Context) ([]KeyRecord, error) {
	out := slices.Clone(s.keys)
	if s.key != nil {
		out = append(out, KeyRecord{ID: s.key.ID, State: "confirmed"})
	}
	for _, id := range s.retired {
		out = append(out, KeyRecord{ID: id, State: "retired", RetiredAt: s.retiredAt})
	}
	return out, nil
}
func (s *fakeStore) Schedule(context.Context) (backupset.Schedule, error) { return s.schedule, nil }
func (s *fakeStore) Targets(context.Context) ([]TargetRecord, error) {
	return slices.Clone(s.targets), nil
}
func (s *fakeStore) RequestedRuns(context.Context) ([]RequestedRun, error)   { return s.requests, nil }
func (s *fakeStore) History(context.Context) (map[string]KindHistory, error) { return s.history, nil }
func (s *fakeStore) InstallationID(context.Context) (string, error)          { return InstallationID(42), nil }
func (s *fakeStore) SchemaVersion(context.Context) (int, error)              { return 107, nil }
func (s *fakeStore) BundleSeqHighWater(context.Context) (int64, error) {
	return s.highWater, s.highWaterErr
}
func (s *fakeStore) SetHostState(_ context.Context, id uuid.UUID, _ int, st string) error {
	s.hostState[id] = st
	return nil
}
func (s *fakeStore) SetTestResult(_ context.Context, id uuid.UUID, class string) error {
	s.tests[id] = class
	return nil
}
func (s *fakeStore) SetTargetStatus(_ context.Context, id uuid.UUID, kind string, st KindStatus) error {
	s.runsMu.Lock()
	defer s.runsMu.Unlock()
	s.status[id.String()+"/"+kind] = st
	return nil
}
func (s *fakeStore) EscrowEvidence(context.Context) (map[string]time.Time, error) {
	return maps.Clone(s.evidence), s.evidenceErr
}

// fakeRun is a recorded run with the mirror results of its phase 2 (mirrored).
type fakeRun struct {
	RunRecord
	id       uuid.UUID
	Targets  []backupset.RunTarget
	mirrored bool
}

func (s *fakeStore) RecordRun(_ context.Context, r RunRecord) ([]uuid.UUID, error) {
	s.runsMu.Lock()
	defer s.runsMu.Unlock()
	id := uuid.New()
	s.runs = append(s.runs, fakeRun{RunRecord: r, id: id})
	return []uuid.UUID{id}, nil
}

func (s *fakeStore) UnmirroredRuns(context.Context) ([]uuid.UUID, error) {
	s.runsMu.Lock()
	defer s.runsMu.Unlock()
	var out []uuid.UUID
	for _, r := range s.runs {
		if !r.mirrored {
			out = append(out, r.id)
		}
	}
	return out, nil
}

func (s *fakeStore) MirrorRuns(_ context.Context, results []backupset.RunTarget, runs []uuid.UUID) error {
	s.runsMu.Lock()
	defer s.runsMu.Unlock()
	if s.mirrorErr != nil {
		return s.mirrorErr
	}
	for i := range s.runs {
		if slices.Contains(runs, s.runs[i].id) {
			if s.runs[i].mirrored {
				s.duplicates++
				continue
			}
			s.runs[i].Targets, s.runs[i].mirrored = slices.Clone(results), true
		}
	}
	return nil
}

func (s *fakeStore) count(kind string) int {
	s.runsMu.Lock()
	defer s.runsMu.Unlock()
	n := 0
	for _, r := range s.runs {
		if r.Kind == kind {
			n++
		}
	}
	return n
}

// answers counts the recorded runs that answer the request id.
func (s *fakeStore) answers(id uuid.UUID) int {
	s.runsMu.Lock()
	defer s.runsMu.Unlock()
	n := 0
	for _, r := range s.runs {
		if slices.ContainsFunc(r.Requests, func(q RequestedRun) bool { return q.ID == id }) {
			n++
		}
	}
	return n
}

func (s *fakeStore) run(kind string) (fakeRun, bool) {
	s.runsMu.Lock()
	defer s.runsMu.Unlock()
	for _, r := range s.runs {
		if r.Kind == kind {
			return r, true
		}
	}
	return fakeRun{}, false
}

type fakeKeys struct{}

func (fakeKeys) DecryptPlatform(_ context.Context, key, ciphertext string) ([]byte, error) {
	if key != "backup-wrap" {
		return nil, errors.New("wrong transit key")
	}
	switch ciphertext {
	case "vault:v1:key":
		return testKey, nil
	case "vault:v1:creds":
		return []byte(`{"access_key":"a","secret_key":"s"}`), nil
	}
	return nil, errors.New("unknown ciphertext")
}

type fakeSnap struct{ calls int }

func (f *fakeSnap) RaftSnapshot(_ context.Context, w io.Writer) error {
	f.calls++
	_, err := w.Write([]byte("raft snapshot"))
	return err
}

type fakeEscrow map[string]string

// fakeEscrowAt is the LastModified of every object of a fakeEscrow: long before the fixtures' rounds.
var fakeEscrowAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func (f fakeEscrow) ListInfo(context.Context, string) (map[string]objectstore.ObjectInfo, error) {
	out := map[string]objectstore.ObjectInfo{}
	for k, v := range f {
		out[k] = objectstore.ObjectInfo{Size: int64(len(v)), Modified: fakeEscrowAt}
	}
	return out, nil
}

// Open refuses every object but a LUKS header, as the policy paddock-escrow-backup does.
func (f fakeEscrow) Open(_ context.Context, key string) (io.ReadCloser, error) {
	if !strings.Contains(key, "/luks-header/") {
		return nil, errors.New("AccessDenied")
	}
	return io.NopCloser(strings.NewReader(f[key])), nil
}

// memTarget is a Target in memory; ops logs puts and deletes in order. garble alters what Put stores. mod holds the
// modification time of a file, set by Put from now; a file without one counts as modified at the zero time.
type memTarget struct {
	files  map[string][]byte
	mod    map[string]time.Time
	now    func() time.Time
	ops    []string
	fail   error
	garble bool
}

func newMemTarget() *memTarget {
	return &memTarget{files: map[string][]byte{}, mod: map[string]time.Time{}, now: time.Now}
}

func (m *memTarget) Newest(_ context.Context, dir string) (time.Time, error) {
	if m.fail != nil {
		return time.Time{}, m.fail
	}
	var newest time.Time
	for p := range m.files {
		if strings.HasPrefix(p, dir) && m.mod[p].After(newest) {
			newest = m.mod[p]
		}
	}
	return newest, nil
}

func (m *memTarget) List(context.Context) (map[string]int64, error) {
	if m.fail != nil {
		return nil, m.fail
	}
	out := map[string]int64{}
	for k, v := range m.files {
		out[k] = int64(len(v))
	}
	return out, nil
}

func (m *memTarget) Put(_ context.Context, p string, r io.Reader, size int64) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	if int64(len(b)) != size {
		return errors.New("short read")
	}
	if m.garble && len(b) > 0 {
		b[0] ^= 0xff
	}
	m.files[p] = b
	m.mod[p] = m.now()
	m.ops = append(m.ops, "put "+p)
	return nil
}

func (m *memTarget) Read(_ context.Context, p string) ([]byte, bool, error) {
	if m.fail != nil {
		return nil, false, m.fail
	}
	b, ok := m.files[p]
	return bytes.Clone(b), ok, nil
}

func (m *memTarget) Delete(_ context.Context, p string) error {
	delete(m.files, p)
	m.ops = append(m.ops, "delete "+p)
	return nil
}

func (m *memTarget) Probe(context.Context) error { return m.fail }

type fakeFactory map[uuid.UUID]Target

func (f fakeFactory) Open(_ context.Context, t TargetRecord) (Target, error) { return f[t.ID], nil }

type noLock struct{}

func (noLock) Lead(ctx context.Context, _ int64, _ time.Duration, fn func(context.Context) error) (bool, error) {
	return true, fn(ctx)
}

type fixture struct {
	cfg     Config
	store   *fakeStore
	snap    *fakeSnap
	escrow  fakeEscrow
	factory fakeFactory
	metrics *Metrics
	now     time.Time
	engine  *Engine
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	f := &fixture{
		cfg: Config{RepoDir: filepath.Join(dir, "repo"), RuntimeDir: filepath.Join(dir, "run"),
			TargetsDir: filepath.Join(dir, "targets"), FleetDumpsDir: filepath.Join(dir, "dumps"),
			StateDir: filepath.Join(dir, "state"), RoundInterval: time.Minute, ServerVersion: "0.1.0-test"},
		store: newFakeStore(), snap: &fakeSnap{}, escrow: fakeEscrow{"org/o1/devices/d1/luks-header/1.bin": "header"},
		factory: fakeFactory{}, metrics: NewMetrics(prometheus.NewRegistry()),
		now: time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC),
	}
	for _, d := range []string{f.cfg.RepoDir, f.cfg.RuntimeDir, f.cfg.TargetsDir, f.cfg.FleetDumpsDir,
		filepath.Join(f.cfg.StateDir, "paddock"), filepath.Join(f.cfg.StateDir, "authentik")} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	f.engine = NewEngine(f.cfg, noLock{}, f.store, fakeKeys{}, f.snap, f.escrow, f.factory, f.metrics,
		func() time.Time { return f.now })
	return f
}

func (f *fixture) confirmKey() {
	f.store.key = &ActiveKey{ID: testKeyID, Ciphertext: "vault:v1:key", Fingerprint: backupset.Fingerprint(testKey)}
}

func (f *fixture) addTarget(t *testing.T, typ backupset.TargetType, dst Target) TargetRecord {
	t.Helper()
	rec := TargetRecord{ID: uuid.New(), Name: "target-" + string(typ) + "-" + uuid.NewString()[:4], Type: typ,
		Enabled: true, HostState: HostNA, HostRevision: 1}
	if backupset.Mounted(typ) {
		rec.HostState = HostMounted
		dir := MountDir(f.cfg.TargetsDir, rec)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, markerFile), []byte("1\n"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	f.store.targets = append(f.store.targets, rec)
	f.factory[rec.ID] = dst
	return rec
}

// round runs one round and waits for the lanes it started, so the test sees their results.
func (f *fixture) round(t *testing.T) {
	t.Helper()
	if err := f.engine.Round(context.Background()); err != nil {
		t.Fatalf("round: %v", err)
	}
	f.engine.waitLanes()
}

func (f *fixture) repoFiles(t *testing.T) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	err := filepath.WalkDir(f.cfg.RepoDir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(f.cfg.RepoDir, p)
		b, err := os.ReadFile(p) //nolint:gosec // test files
		out[filepath.ToSlash(rel)] = b
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestRoundWithoutKey: without a confirmed key the role writes no key file, runs nothing and exports
// paddock_backup_key_confirmed 0 (plan M15 decision 16 a).
func TestRoundWithoutKey(t *testing.T) {
	f := newFixture(t)
	if err := os.WriteFile(filepath.Join(f.cfg.RuntimeDir, keyFileName), []byte("stale"), 0o640); err != nil {
		t.Fatal(err)
	}
	f.store.requests = []RequestedRun{{ID: uuid.New(), Kind: KindOpenBao, CreatedAt: f.now}}
	f.round(t)
	if _, err := os.Stat(filepath.Join(f.cfg.RuntimeDir, keyFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("key file still there: %v", err)
	}
	if f.snap.calls != 0 || len(f.store.runs) != 0 || len(f.repoFiles(t)) != 0 {
		t.Errorf("something ran without a key: snapshots %d, runs %v", f.snap.calls, f.store.runs)
	}
	if v := testutil.ToFloat64(f.metrics.keyConfirmed); v != 0 {
		t.Errorf("paddock_backup_key_confirmed = %v", v)
	}
}

// TestRoundBacksUpAndMirrors: with a confirmed key one round hands the key and schedule to pgBackRest, takes the
// sealed OpenBao snapshot and the escrow objects into the set, writes the manifest and mirrors the identical set to
// both targets; every run is recorded once with both targets ok.
func TestRoundBacksUpAndMirrors(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	local, s3 := newMemTarget(), newMemTarget()
	f.addTarget(t, backupset.TypeLocal, local)
	f.addTarget(t, backupset.TypeS3, s3)
	f.round(t)

	keyFile, err := os.ReadFile(filepath.Join(f.cfg.RuntimeDir, keyFileName))
	if err != nil || string(keyFile) != base64.StdEncoding.EncodeToString(testKey) {
		t.Fatalf("key file %q, %v", keyFile, err)
	}
	env, _ := os.ReadFile(filepath.Join(f.cfg.RuntimeDir, scheduleFileName))
	for _, want := range []string{"PADDOCK_BACKUP_REPO_PATH=pgbackrest/" + testKeyID + "\n",
		"PADDOCK_BACKUP_RETENTION_FULL=14\n", "PADDOCK_BACKUP_FULL_INTERVAL_S=86400\n"} {
		if !strings.Contains(string(env), want) {
			t.Errorf("schedule.env lacks %q:\n%s", want, env)
		}
	}
	if info, _ := os.Stat(filepath.Join(f.cfg.RuntimeDir, keyFileName)); info.Mode().Perm() != 0o640 {
		t.Errorf("key file mode %v", info.Mode().Perm())
	}

	files := f.repoFiles(t)
	snap := files[backupset.OpenBaoKey(f.now)]
	if plain, err := backup.Open(testKey, snap); err != nil || string(plain) != "raft snapshot" {
		t.Errorf("sealed snapshot: %q, %v", plain, err)
	}
	if string(files["escrow/org/o1/devices/d1/luks-header/1.bin"]) != "header" {
		t.Errorf("escrow object not in the set: %v", slices.Collect(maps.Keys(files)))
	}
	m, err := backupset.Parse(files[backupset.ManifestPath])
	if err != nil {
		t.Fatal(err)
	}
	if m.KeyID != testKeyID || len(m.Contents.OpenBao) != 1 || len(m.Contents.Escrow) != 1 ||
		m.Contents.PgBackRest.Path != "pgbackrest/"+testKeyID || m.SchemaVersions["paddock"] != 107 {
		t.Errorf("manifest %+v", m)
	}

	for name, dst := range map[string]*memTarget{"local": local, "s3": s3} {
		if len(dst.files) != len(files) {
			t.Errorf("%s holds %d files, the set %d", name, len(dst.files), len(files))
		}
		for p, b := range files {
			if !bytes.Equal(dst.files[p], b) {
				t.Errorf("%s: %s differs", name, p)
			}
		}
		if last := dst.ops[len(dst.ops)-1]; last != "put "+backupset.ManifestPath {
			t.Errorf("%s: manifest not written last: %v", name, dst.ops)
		}
	}
	for _, kind := range []string{KindOpenBao, KindEscrow} {
		r, ok := f.store.run(kind)
		if !ok || !r.Succeeded || len(r.Targets) != 2 || !r.Targets[0].OK || !r.Targets[1].OK {
			t.Errorf("%s run %+v", kind, r)
		}
	}
	if len(f.store.runs) != 2 {
		t.Errorf("runs %d, want 2 (openbao, escrow)", len(f.store.runs))
	}
	if v := testutil.ToFloat64(f.metrics.keyConfirmed); v != 1 {
		t.Errorf("paddock_backup_key_confirmed = %v", v)
	}
}

// TestFailingTargetDoesNotStopTheOthers: an unreachable target is reported as failed and unreachable while the other
// target still receives the set.
func TestFailingTargetDoesNotStopTheOthers(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	bad, good := newMemTarget(), newMemTarget()
	bad.fail = errors.New("connection refused")
	badRec := f.addTarget(t, backupset.TypeS3, bad)
	goodRec := f.addTarget(t, backupset.TypeS3, good)
	f.round(t)
	if _, ok := good.files[backupset.ManifestPath]; !ok {
		t.Fatal("the reachable target got no manifest")
	}
	r, _ := f.store.run(KindOpenBao)
	if !r.Succeeded {
		t.Error("a failing target failed the run")
	}
	byID := map[string]backupset.RunTarget{}
	for _, rt := range r.Targets {
		byID[rt.TargetID] = rt
	}
	if byID[badRec.ID.String()].OK || byID[badRec.ID.String()].ErrorClass != ClassIO || !byID[goodRec.ID.String()].OK {
		t.Errorf("targets %+v", r.Targets)
	}
	if v := testutil.ToFloat64(f.metrics.reachable.WithLabelValues(badRec.Name)); v != 0 {
		t.Errorf("reachable of the failing target = %v", v)
	}
	if v := testutil.ToFloat64(f.metrics.reachable.WithLabelValues(goodRec.Name)); v != 1 {
		t.Errorf("reachable of the good target = %v", v)
	}
	if st := f.store.status[badRec.ID.String()+"/openbao"]; st.Error != ClassIO {
		t.Errorf("status of the failing target %+v", st)
	}
}

// TestShrunkSetFailsTheTargetAndAlerts: a round after a lost repository volume (the full backups gone, the stanza
// created again with other info files) leaves the target byte-for-byte as the previous round wrote it, records the
// target as failed with set_shrunk and sets paddock_backup_target_reachable to 0, which PaddockBackupTargetUnreachable
// alerts on.
func TestShrunkSetFailsTheTargetAndAlerts(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	path := "pgbackrest/" + testKeyID
	write := func(files map[string]string) {
		t.Helper()
		for p, body := range files {
			full := filepath.Join(f.cfg.RepoDir, p)
			if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, []byte(body), 0o640); err != nil {
				t.Fatal(err)
			}
		}
	}
	write(map[string]string{path + "/backup/paddock/20261103-000000F/backup.manifest": "m",
		path + "/backup/authentik/20261103-000000F/backup.manifest": "m",
		path + "/backup/paddock/backup.info":                        "lists 20261103-000000F",
		path + "/backup/paddock/backup.info.copy":                   "lists 20261103-000000F",
		path + "/archive/paddock/archive.info":                      "db-id=1 system-id=7"})
	dst := newMemTarget()
	rec := f.addTarget(t, backupset.TypeS3, dst)
	f.round(t)
	if testutil.ToFloat64(f.metrics.reachable.WithLabelValues(rec.Name)) != 1 {
		t.Fatalf("the first round did not reach the target: %v", dst.ops)
	}
	before, ops := maps.Clone(dst.files), len(dst.ops)

	for _, stanza := range []string{"paddock", "authentik"} {
		if err := os.RemoveAll(filepath.Join(f.cfg.RepoDir, path, "backup", stanza, "20261103-000000F")); err != nil {
			t.Fatal(err)
		}
	}
	write(map[string]string{path + "/backup/paddock/backup.info": "empty",
		path + "/backup/paddock/backup.info.copy": "empty",
		path + "/archive/paddock/archive.info":    "db-id=1 system-id=9"})
	f.store.runs = nil
	f.round(t)
	if len(dst.ops) != ops || !maps.EqualFunc(dst.files, before, bytes.Equal) {
		t.Errorf("a shrunk set changed the target: %v", dst.ops[ops:])
	}
	if len(f.store.runs) == 0 {
		t.Fatal("the round recorded no run")
	}
	for _, r := range f.store.runs {
		if len(r.Targets) != 1 || r.Targets[0].OK || r.Targets[0].ErrorClass != ClassSetShrunk {
			t.Errorf("%s run targets %+v, want failed with %s", r.Kind, r.Targets, ClassSetShrunk)
		}
	}
	if st := f.store.status[rec.ID.String()+"/"+KindPostgres]; st.Error != ClassSetShrunk {
		t.Errorf("target status %+v", st)
	}
	if v := testutil.ToFloat64(f.metrics.reachable.WithLabelValues(rec.Name)); v != 0 {
		t.Errorf("paddock_backup_target_reachable = %v, want 0", v)
	}
}

// TestRotationThenLostRepositoryKeepsOldKeyOnEveryTarget: a key rotation, then a lost pgBackRest repository, then
// the new key's first full backup: every target keeps the old key's backups byte for byte until they are older than
// the retention, and only then loses them (PDK-732 review 4, major 1).
func TestRotationThenLostRepositoryKeepsOldKeyOnEveryTarget(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	old, newID := "pgbackrest/"+testKeyID, "bk-20261105-00000001"
	newPath := "pgbackrest/" + newID
	write := func(files map[string]string) {
		t.Helper()
		for p, body := range files {
			full := filepath.Join(f.cfg.RepoDir, p)
			if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, []byte(body), 0o640); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, stanza := range []string{"paddock", "authentik"} {
		write(map[string]string{old + "/backup/" + stanza + "/20261103-000000F/backup.manifest": "m",
			old + "/backup/" + stanza + "/backup.info":   "lists 20261103-000000F",
			old + "/archive/" + stanza + "/archive.info": "db-id=1 system-id=7"})
	}
	var dsts []*memTarget
	for range 2 {
		dst := newMemTarget()
		dst.now = func() time.Time { return f.now }
		f.addTarget(t, backupset.TypeS3, dst)
		dsts = append(dsts, dst)
	}
	f.round(t)

	f.store.key = &ActiveKey{ID: newID, Ciphertext: "vault:v1:key", Fingerprint: backupset.Fingerprint(testKey)}
	f.store.retired = []string{testKeyID}
	stanzas := func(body string) map[string]string {
		return map[string]string{newPath + "/backup/paddock/backup.info": body, newPath + "/archive/paddock/archive.info": body,
			newPath + "/backup/authentik/backup.info": body, newPath + "/archive/authentik/archive.info": body}
	}
	write(stanzas("created"))
	f.now = f.now.Add(time.Hour)
	f.round(t)
	var before []map[string][]byte
	for i, dst := range dsts {
		if _, ok := dst.files[old+"/backup/paddock/20261103-000000F/backup.manifest"]; !ok {
			t.Fatalf("target %d lacks the old key's full backup before the loss: %v", i, dst.ops)
		}
		before = append(before, maps.Clone(dst.files))
	}
	keptOld := func(when string) {
		t.Helper()
		for i, dst := range dsts {
			for p, body := range before[i] {
				if strings.HasPrefix(p, old+"/") && !bytes.Equal(dst.files[p], body) {
					t.Errorf("%s: target %d lost or changed the old key's %s", when, i, p)
				}
			}
		}
	}

	if err := os.RemoveAll(filepath.Join(f.cfg.RepoDir, "pgbackrest")); err != nil {
		t.Fatal(err)
	}
	write(stanzas("created again"))
	f.now = f.now.Add(time.Hour)
	f.round(t)
	keptOld("lost repository")

	write(map[string]string{newPath + "/backup/paddock/20261104-120000F/backup.manifest": "n",
		newPath + "/backup/authentik/20261104-120000F/backup.manifest": "n"})
	f.now = f.now.Add(time.Hour)
	f.round(t)
	keptOld("the new key's first full")

	f.now = f.now.Add(15 * 24 * time.Hour)
	f.round(t)
	for i, dst := range dsts {
		for p := range dst.files {
			if strings.HasPrefix(p, old+"/") {
				t.Errorf("target %d kept %s past the retention", i, p)
			}
		}
	}
}

// TestMirrorAddsReplacesDeletes: the mirror copies what the target lacks, replaces a file of another size, deletes
// a snapshot past its keep days that is not the target's newest after the manifest, and leaves equal files alone.
func TestMirrorAddsReplacesDeletes(t *testing.T) {
	manifest := testManifest(t, InstallationID(42), nil)
	repo, idx := openSet(t, map[string]string{"openbao/20261104T060000Z.snap.enc": "aaaa",
		"fleet/20261104T020000Z.sql.gz.enc": "bb", "pgbackrest/" + testKeyID + "/archive/paddock/x": "same",
		backupset.ManifestPath: string(manifest)})
	dst := newMemTarget()
	dst.files = map[string][]byte{"fleet/20261104T020000Z.sql.gz.enc": []byte("old size"),
		"pgbackrest/" + testKeyID + "/archive/paddock/x": []byte("same"),
		"openbao/20260901T060000Z.snap.enc":              []byte("x"), "openbao/20260902T060000Z.snap.enc": []byte("y")}
	now := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	if _, err := mirrorSet(context.Background(), repo, idx, dst, map[string]fileInfo{}, testRetention(now),
		noHooks()); err != nil {
		t.Fatal(err)
	}
	want := []string{"put fleet/20261104T020000Z.sql.gz.enc", "put openbao/20261104T060000Z.snap.enc",
		"put manifest.json", "delete openbao/20260901T060000Z.snap.enc"}
	if !slices.Equal(dst.ops, want) {
		t.Errorf("ops %v, want %v", dst.ops, want)
	}
}

// TestKeyRotationSwitchesRepoPath: a new active key writes its own repository path and key file.
func TestKeyRotationSwitchesRepoPath(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	f.round(t)
	f.store.key = &ActiveKey{ID: "bk-20261105-00000001", Ciphertext: "vault:v1:key", Fingerprint: backupset.Fingerprint(testKey)}
	f.store.retired = []string{testKeyID}
	f.round(t)
	env, _ := os.ReadFile(filepath.Join(f.cfg.RuntimeDir, scheduleFileName))
	if !strings.Contains(string(env), "PADDOCK_BACKUP_REPO_PATH=pgbackrest/bk-20261105-00000001\n") {
		t.Errorf("schedule.env after the rotation:\n%s", env)
	}
}

// TestDevelopmentFullInterval: Config.FullInterval replaces the schedule's interval in schedule.env.
func TestDevelopmentFullInterval(t *testing.T) {
	f := newFixture(t)
	f.cfg.FullInterval = 120 * time.Second
	f.engine.cfg = f.cfg
	f.confirmKey()
	f.round(t)
	env, _ := os.ReadFile(filepath.Join(f.cfg.RuntimeDir, scheduleFileName))
	if !strings.Contains(string(env), "PADDOCK_BACKUP_FULL_INTERVAL_S=120\n") {
		t.Errorf("schedule.env:\n%s", env)
	}
}

// TestPgBackRestMarkers: a full backup pgBackRest finished after the newest recorded run is recorded once with the
// requests it answers; a failure is recorded as failed; a request is handed to serve through the runtime directory
// and fails after an hour without an answer.
func TestPgBackRestMarkers(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	f.store.history[KindOpenBao] = KindHistory{LastAttempt: f.now, LastSuccess: f.now}
	f.store.history[KindEscrow] = KindHistory{LastAttempt: f.now, LastSuccess: f.now}
	f.store.history[KindFleet] = KindHistory{LastAttempt: f.now, LastSuccess: f.now}
	full := f.now.Add(-time.Minute)
	early := RequestedRun{ID: uuid.New(), Kind: KindPostgres, Label: "before", CreatedAt: full.Add(-time.Minute)}
	late := RequestedRun{ID: uuid.New(), Kind: KindAuthentik, Label: "pending", CreatedAt: f.now.Add(-2 * time.Hour)}
	waiting := RequestedRun{ID: uuid.New(), Kind: KindAuthentik, Label: "fresh", CreatedAt: f.now.Add(-time.Minute)}
	f.store.requests = []RequestedRun{early, late, waiting}
	write := func(stanza, name string, at time.Time) {
		if err := os.WriteFile(filepath.Join(f.cfg.StateDir, stanza, name), []byte(strconvUnix(at)), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	write("paddock", "last-full", full)
	write("authentik", "last-error", full)
	f.round(t)

	pg, ok := f.store.run(KindPostgres)
	if !ok || !pg.Succeeded || len(pg.Requests) != 1 || pg.Requests[0].ID != early.ID || !pg.FinishedAt.Equal(full) {
		t.Errorf("postgres run %+v", pg)
	}
	var failed, timedOut int
	for _, r := range f.store.runs {
		if r.Kind == KindAuthentik && r.ErrorClass == runClassPgBackRest {
			failed++
		}
		if r.Kind == KindAuthentik && r.ErrorClass == runClassTimeout {
			timedOut++
			if len(r.Requests) != 1 || r.Requests[0].ID != late.ID {
				t.Errorf("timeout answers %+v", r.Requests)
			}
		}
	}
	if failed != 1 || timedOut != 1 {
		t.Errorf("authentik failures %d, timeouts %d: %+v", failed, timedOut, f.store.runs)
	}
	req, err := os.ReadFile(filepath.Join(f.cfg.RuntimeDir, "request-authentik"))
	if err != nil || string(req) != strconvUnix(late.CreatedAt) {
		t.Errorf("request file %q, %v", req, err)
	}
	if _, err := os.Stat(filepath.Join(f.cfg.RuntimeDir, "request-paddock")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("answered request file still there: %v", err)
	}
}

func strconvUnix(t time.Time) string { return strconv.FormatInt(t.Unix(), 10) }

// TestFleetDumpSealed: a complete plaintext dump is sealed into the set and deleted; with none waiting and the kind
// due, the role asks fleet-backup for one.
func TestFleetDumpSealed(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	dump := filepath.Join(f.cfg.FleetDumpsDir, "20261104T090000Z.sql.gz")
	if err := os.WriteFile(dump, []byte("dump"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.cfg.FleetDumpsDir, ".20261104T091000Z.tmp"), []byte("partial"), 0o640); err != nil {
		t.Fatal(err)
	}
	f.round(t)
	if _, err := os.Stat(dump); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("plaintext dump still there: %v", err)
	}
	sealed := f.repoFiles(t)["fleet/20261104T090000Z.sql.gz.enc"]
	if plain, err := backup.Open(testKey, sealed); err != nil || string(plain) != "dump" {
		t.Errorf("sealed dump %q, %v", plain, err)
	}
	if r, ok := f.store.run(KindFleet); !ok || !r.Succeeded {
		t.Errorf("fleet run %+v", r)
	}

	f.store.runs = nil
	f.store.history[KindFleet] = KindHistory{}
	f.round(t)
	if _, err := os.Stat(filepath.Join(f.cfg.FleetDumpsDir, fleetRequestFile)); err != nil {
		t.Errorf("no dump requested: %v", err)
	}
	if _, ok := f.store.run(KindFleet); ok {
		t.Error("a requested dump was recorded before it exists")
	}
}

// TestHostStateFromMarker: a volume target is pending without its marker or with an older revision, mounted with the
// current one; an S3 target keeps n/a.
func TestHostStateFromMarker(t *testing.T) {
	f := newFixture(t)
	rec := f.addTarget(t, backupset.TypeSMB, newMemTarget())
	s3 := f.addTarget(t, backupset.TypeS3, newMemTarget())
	if got := HostState(f.cfg.TargetsDir, rec); got != HostMounted {
		t.Errorf("current marker: %s", got)
	}
	rec.HostRevision = 2
	if got := HostState(f.cfg.TargetsDir, rec); got != HostPending {
		t.Errorf("older marker: %s", got)
	}
	f.store.targets[0].HostRevision = 2
	f.round(t)
	if f.store.hostState[rec.ID] != HostPending {
		t.Errorf("stored host state %q", f.store.hostState[rec.ID])
	}
	if _, ok := f.store.hostState[s3.ID]; ok {
		t.Error("an S3 target got a host state")
	}
	if err := os.RemoveAll(MountDir(f.cfg.TargetsDir, rec)); err != nil {
		t.Fatal(err)
	}
	if got := HostState(f.cfg.TargetsDir, rec); got != HostPending {
		t.Errorf("missing volume: %s", got)
	}
}

// TestTargetTests: a requested test stores ok or the error class; a pending volume target reports not_mounted
// without a write.
func TestTargetTests(t *testing.T) {
	f := newFixture(t)
	ok, bad := newMemTarget(), newMemTarget()
	bad.fail = &net.DNSError{Err: "no such host", Name: "s3.invalid", IsNotFound: true}
	okRec := f.addTarget(t, backupset.TypeS3, ok)
	badRec := f.addTarget(t, backupset.TypeS3, bad)
	pending := f.addTarget(t, backupset.TypeNFS, newMemTarget())
	if err := os.Remove(filepath.Join(MountDir(f.cfg.TargetsDir, pending), markerFile)); err != nil {
		t.Fatal(err)
	}
	for i := range f.store.targets {
		f.store.targets[i].TestRequested = true
	}
	f.round(t)
	if c, done := f.store.tests[okRec.ID]; !done || c != "" {
		t.Errorf("ok target: %q %v", c, done)
	}
	if f.store.tests[badRec.ID] != ClassDNS || f.store.tests[pending.ID] != ClassNotMounted {
		t.Errorf("tests %v", f.store.tests)
	}
}

// TestDirTargetNewest: Newest reports the modification time of the newest regular file below a directory of the set,
// ignores a symlink planted there and files elsewhere, gives the zero time for a directory the target lacks, and
// refuses a path that leaves the set.
func TestDirTargetNewest(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "mount", backupset.SetRoot)
	if err := os.MkdirAll(filepath.Join(root, "pgbackrest/k/backup"), 0o750); err != nil {
		t.Fatal(err)
	}
	old, newer, other := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for p, at := range map[string]time.Time{"pgbackrest/k/backup/a": old, "pgbackrest/k/b": newer, "openbao/x": other} {
		full := filepath.Join(root, p)
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
	if err := os.Symlink(filepath.Join(root, "openbao/x"), filepath.Join(root, "pgbackrest/k/link")); err != nil {
		t.Fatal(err)
	}
	d := NewDirTarget(root)
	if got, err := d.Newest(ctx, "pgbackrest/k/"); err != nil || !got.Equal(newer) {
		t.Errorf("Newest = %v, %v; want %v", got, err, newer)
	}
	if got, err := d.Newest(ctx, "pgbackrest/none/"); err != nil || !got.IsZero() {
		t.Errorf("Newest of a missing directory = %v, %v; want the zero time", got, err)
	}
	if _, err := d.Newest(ctx, "../"); err == nil {
		t.Error("Newest accepted a path out of the set")
	}
}

// TestDirTargetConfinement: a directory target writes below its root only and reports a missing volume as
// not_mounted (PDK-729 review, minor 4).
func TestDirTargetConfinement(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	mount := filepath.Join(base, "mount")
	d := NewDirTarget(filepath.Join(mount, backupset.SetRoot))
	if _, err := d.List(ctx); ErrorClass(err) != ClassNotMounted {
		t.Fatalf("missing volume: %v (%s)", err, ErrorClass(err))
	}
	if err := os.Mkdir(mount, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"../escape", "/abs", "a/../../b", "a//b", ""} {
		if err := d.Put(ctx, p, strings.NewReader("x"), 1); err == nil {
			t.Errorf("Put(%q) accepted", p)
		}
	}
	if err := os.Symlink(base, filepath.Join(mount, backupset.SetRoot, "link")); err != nil {
		if err := os.MkdirAll(filepath.Join(mount, backupset.SetRoot), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(base, filepath.Join(mount, backupset.SetRoot, "link")); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.Put(ctx, "link/planted", strings.NewReader("x"), 1); err == nil {
		t.Error("a write through a symlink out of the root was accepted")
	}
	if err := d.Put(ctx, "escrow/org/o/devices/d/h.bin", strings.NewReader("abc"), 3); err != nil {
		t.Fatal(err)
	}
	got, err := d.List(ctx)
	if err != nil || got["escrow/org/o/devices/d/h.bin"] != 3 || len(got) != 1 {
		t.Errorf("list %v, %v", got, err)
	}
	if err := d.Delete(ctx, "escrow/org/o/devices/d/h.bin"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(mount, backupset.SetRoot, "escrow")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("empty directories stay: %v", err)
	}
	if err := d.Probe(ctx); err != nil {
		t.Errorf("probe: %v", err)
	}
}

// TestEscrowKeyConfinement: an escrow object whose key would leave the set is skipped, the others are copied.
func TestEscrowKeyConfinement(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	f.escrow["../../etc/evil"] = "x"
	f.round(t)
	if _, err := os.Stat(filepath.Join(filepath.Dir(f.cfg.RepoDir), "etc")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("escrow key escaped the repository: %v", err)
	}
	if _, ok := f.repoFiles(t)["escrow/org/o1/devices/d1/luks-header/1.bin"]; !ok {
		t.Error("the valid object was not copied")
	}
}

// TestExpire: snapshots older than their keep days and a retired key's repository past its retention are deleted
// once the active key's repository holds a full backup of both stanzas; the active key's repository stays.
func TestExpire(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	old := f.now.Add(-31 * 24 * time.Hour)
	retired := "bk-20260101-00000001"
	f.store.retired = []string{retired}
	for p, at := range map[string]time.Time{backupset.OpenBaoKey(old): old,
		"pgbackrest/" + retired + "/backup/paddock/x":                                    f.now.Add(-15 * 24 * time.Hour),
		"pgbackrest/" + testKeyID + "/backup/paddock/20261103-000000F/backup.manifest":   old,
		"pgbackrest/" + testKeyID + "/backup/authentik/20261103-000000F/backup.manifest": old} {
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
	f.round(t)
	files := f.repoFiles(t)
	if _, ok := files[backupset.OpenBaoKey(old)]; ok {
		t.Error("an expired snapshot stayed")
	}
	if _, ok := files["pgbackrest/"+retired+"/backup/paddock/x"]; ok {
		t.Error("the retired key's repository stayed past its retention")
	}
	if _, ok := files["pgbackrest/"+testKeyID+"/backup/paddock/20261103-000000F/backup.manifest"]; !ok {
		t.Error("the active key's repository was expired")
	}
}
