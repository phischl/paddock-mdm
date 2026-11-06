// Package backuprole is the backup role `paddock-server serve backup` (plan M15 decisions 15–19, ADR 0046): the only
// process that holds the backup key at run time. Every round it hands the key and the schedule to pgBackRest through
// the runtime tmpfs, takes the due OpenBao snapshots, seals the Fleet dumps, copies the escrow objects into the local
// repository, expires old files, writes manifest.json and mirrors the set to every enabled target.
package backuprole

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/backup"
	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
	"github.com/phischl/paddock-mdm/server/internal/platform/objectstore"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// LockKey is the advisory lock of the backup round ("padd bkp"), the key of the worker's former backup job.
const LockKey = 0x7061646420626b70

// Kinds and their pgBackRest stanzas (compose.backup.yaml).
const (
	KindPostgres  = "postgres"
	KindAuthentik = "authentik"
	KindOpenBao   = "openbao"
	KindFleet     = "fleet"
	KindEscrow    = "escrow"
)

// Stanzas maps the database kinds to their pgBackRest stanzas.
var Stanzas = map[string]string{KindPostgres: "paddock", KindAuthentik: "authentik"}

// Error classes of a failed run (platform.backup_failed).
const (
	runClassOpenBao    = "openbao"
	runClassFleet      = "fleet"
	runClassEscrow     = "escrow"
	runClassPgBackRest = "pgbackrest"
	runClassTimeout    = "timeout"
)

const (
	// retryAfter spaces the attempts of a kind whose last attempt failed.
	retryAfter = 15 * time.Minute
	// requestTimeout fails a requested run that pgBackRest or the Fleet dump did not answer.
	requestTimeout = time.Hour
	// Files in the runtime tmpfs, read by the pgBackRest containers (decision 17).
	keyFileName      = "key"
	scheduleFileName = "schedule.env"
	// fleetRequestFile asks fleet-backup for a dump (deploy/compose/fleet/backup.sh).
	fleetRequestFile = ".request"
	// fleetPlainMaxAge bounds the life of a plaintext Fleet dump the role cannot seal (repository full, no confirmed
	// key): the dump is personal data outside the backup key's protection, so it is deleted instead.
	fleetPlainMaxAge = 6 * time.Hour
	// mirrorStall fails a target's mirror that made no progress for this long; a hard-mounted share that went away
	// or a stalled S3 endpoint must not hold the round (and the leader lock).
	mirrorStall = 2 * time.Minute
	// mirrorBudget bounds the time a round gives one target's mirror: a slow but progressing target (the first upload
	// of a large set over a WAN link) would otherwise hold the round, and with it the snapshots, the sealing and the
	// other targets, for hours. The mirror stops after the file it is copying and goes on next round.
	mirrorBudget = 10 * time.Minute
	// mirrorMinRate is the slowest a target may copy the file in flight when the budget ends: the mirror is cancelled
	// at started + budget + size/mirrorMinRate (plan M15, amendment 2026-11-05, A7).
	mirrorMinRate = 1 << 20
	// testTimeout bounds a requested connection test.
	testTimeout = 30 * time.Second
)

// Config holds the role's directories and timing (plan M15 decision 15).
type Config struct {
	RepoDir       string
	RuntimeDir    string
	TargetsDir    string
	FleetDumpsDir string
	// StateDir holds one read-only pgBackRest state volume per stanza (<StateDir>/<stanza>/last-full).
	StateDir      string
	RoundInterval time.Duration
	// FullInterval replaces the schedule's full_interval_hours in schedule.env (development only, so a full backup
	// is due within minutes).
	FullInterval  time.Duration
	ServerVersion string
}

// LeaderLocker runs fn while holding a cluster-wide advisory lock; false when another replica holds it.
type LeaderLocker interface {
	WithLeaderLock(ctx context.Context, key int64, fn func(ctx context.Context) error) (bool, error)
}

// Snapshotter takes OpenBao's Raft snapshot (bao.Client with the AppRole paddock-backup).
type Snapshotter interface {
	RaftSnapshot(ctx context.Context, w io.Writer) error
}

// EscrowStore is the escrow bucket through its read-only backup credential.
type EscrowStore interface {
	ListInfo(ctx context.Context, prefix string) (map[string]objectstore.ObjectInfo, error)
	Open(ctx context.Context, key string) (io.ReadCloser, error)
}

// Engine runs the backup rounds.
type Engine struct {
	cfg     Config
	lock    LeaderLocker
	store   Store
	keys    Decrypter
	snap    Snapshotter
	escrow  EscrowStore
	targets TargetFactory
	metrics *Metrics
	now     func() time.Time
	hashes  map[string]hashEntry
	// mirrored is the newest time of every kind a target held after its last successful mirror.
	mirrored map[string]map[string]time.Time
	// pushed is, per target, the local state of every in-place rewritten file when the mirror last copied it.
	pushed map[uuid.UUID]map[string]fileInfo
	// fleetFailed is the time of the last failed sealing of a waiting dump, by file name.
	fleetFailed map[string]time.Time
	stall       time.Duration
	budget      time.Duration
	// minRate is the throughput a target must reach on the file it copies when the budget ends (bytes per second).
	minRate int64
	// busy holds the targets whose mirror outlived its round: a blocked file system call cannot be interrupted, so
	// the next rounds skip the target until it returns.
	busyMu sync.Mutex
	busy   map[uuid.UUID]bool
	// checking holds the volume targets whose host check has not returned.
	checking map[uuid.UUID]bool
	// testing holds the targets whose connection test has not returned.
	testing map[uuid.UUID]bool
	// escrowMissing is the last escrow pass's sorted set paths of headers missing without evidence: a change is
	// warned about once.
	escrowMissing []string
	// held is the held count of each target's last mirror that reached step 6; a failed mirror keeps it, so one
	// failure does not reset PaddockBackupTargetHolding's for: window (PDK-732 review 6, F3).
	held map[uuid.UUID]int
}

// NewEngine creates the engine.
func NewEngine(cfg Config, lock LeaderLocker, store Store, keys Decrypter, snap Snapshotter, escrow EscrowStore,
	targets TargetFactory, metrics *Metrics, now func() time.Time) *Engine {
	return &Engine{cfg: cfg, lock: lock, store: store, keys: keys, snap: snap, escrow: escrow, targets: targets,
		metrics: metrics, now: now, hashes: map[string]hashEntry{}, mirrored: map[string]map[string]time.Time{},
		pushed: map[uuid.UUID]map[string]fileInfo{}, fleetFailed: map[string]time.Time{}, stall: mirrorStall,
		budget: mirrorBudget, minRate: mirrorMinRate, busy: map[uuid.UUID]bool{}, checking: map[uuid.UUID]bool{}, testing: map[uuid.UUID]bool{},
		held: map[uuid.UUID]int{}}
}

// Run runs a round at start and then every RoundInterval until ctx ends.
func (e *Engine) Run(ctx context.Context) error {
	tick := time.NewTicker(e.cfg.RoundInterval)
	defer tick.Stop()
	for {
		if err := e.Round(ctx); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "backup round failed; retrying next round", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

func principalWith(ctx context.Context) context.Context {
	return principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: Actor})
}

// Round runs one round on the replica that holds the lock.
func (e *Engine) Round(ctx context.Context) error {
	_, err := e.lock.WithLeaderLock(SystemContext(ctx), LockKey, e.round)
	return err
}

// run is one run of one kind before its mirror results are known.
type run = RunRecord

func (e *Engine) round(ctx context.Context) error {
	targets, err := e.store.Targets(ctx)
	if err != nil {
		return err
	}
	errs := []error{e.hostStates(ctx, targets), e.tests(ctx, targets)}
	key, ok, err := e.store.ActiveKey(ctx)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	if !ok {
		// Without a confirmed key nothing runs (decision 16 a): pgBackRest's serve waits for the key file.
		if err := os.Remove(filepath.Join(e.cfg.RuntimeDir, keyFileName)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
		e.metrics.keyConfirmed.Set(0)
		e.metrics.series.Set(0)
		e.metrics.walStanzas.Set(0)
		return errors.Join(append(errs, e.dropStaleDumps(ctx))...)
	}
	raw, err := e.keys.DecryptPlatform(ctx, app.BackupWrapKey, key.Ciphertext)
	if err == nil && len(raw) != backup.KeySize {
		err = fmt.Errorf("backup key %s: %d bytes, want %d", key.ID, len(raw), backup.KeySize)
	}
	if err != nil {
		return errors.Join(append(errs, fmt.Errorf("decrypt backup key: %w", err))...)
	}
	sched, err := e.store.Schedule(ctx)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	if err := e.writeRuntime(key.ID, raw, sched); err != nil {
		return errors.Join(append(errs, err)...)
	}
	e.metrics.keyConfirmed.Set(1)

	repo, err := os.OpenRoot(e.cfg.RepoDir)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	defer func() { _ = repo.Close() }()
	requests, err := e.store.RequestedRuns(ctx)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	history, err := e.store.History(ctx)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	byKind := map[string][]RequestedRun{}
	for _, r := range requests {
		byKind[r.Kind] = append(byKind[r.Kind], r)
	}

	var runs []run
	if e.due(history[KindOpenBao], hours(sched.OpenBaoIntervalHours)) || len(byKind[KindOpenBao]) > 0 {
		runs = append(runs, e.snapshotOpenBao(ctx, repo, raw, byKind[KindOpenBao]))
	}
	var escrow escrowRule
	if e.due(history[KindEscrow], hours(sched.EscrowIntervalHours)) || len(byKind[KindEscrow]) > 0 {
		var r run
		r, escrow = e.mirrorEscrow(ctx, repo, byKind[KindEscrow])
		runs = append(runs, r)
	}
	fleetRuns, err := e.fleet(ctx, repo, raw, history[KindFleet], hours(sched.FleetIntervalHours), byKind[KindFleet])
	errs = append(errs, err)
	runs = append(runs, fleetRuns...)
	dbRuns, err := e.pgbackrest(ctx, key.ID, history, byKind)
	errs = append(errs, err)
	runs = append(runs, dbRuns...)
	runs = append(runs, e.timeouts(byKind, runs)...)

	keys, err := e.store.Keys(ctx)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	ret := e.retention(key.ID, keys, sched, escrow)
	idx, err := indexRepo(repo)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	if e.expire(ctx, repo, idx, ret) {
		if idx, err = indexRepo(repo); err != nil {
			return errors.Join(append(errs, err)...)
		}
	}
	kinds := e.kindState(idx, key.ID, history, runs)
	if err := e.writeManifest(ctx, repo, idx, key, kinds, ret.escrow.copied); err != nil {
		errs = append(errs, err)
	} else {
		ret.manifestOK = true
	}
	if idx, err = indexRepo(repo); err != nil {
		return errors.Join(append(errs, err)...)
	}
	e.repoMetrics(idx, key.ID, kinds)

	ret.walOK = e.walOK(idx, ret.active)
	results := e.mirrorAll(ctx, repo, idx, targets, kinds, ret)
	for i := range runs {
		runs[i].Targets = results
		if err := e.store.RecordRun(ctx, runs[i]); err != nil {
			errs = append(errs, fmt.Errorf("record %s run: %w", runs[i].Kind, err))
			continue
		}
		outcome := "succeeded"
		if !runs[i].Succeeded {
			outcome = "failed"
		}
		e.metrics.runs.WithLabelValues(runs[i].Kind, outcome).Inc()
	}
	return errors.Join(errs...)
}

func hours(h int) time.Duration { return time.Duration(h) * time.Hour }

// retention collects the inputs of the round's expire and mirror (plan M15, amendment 2026-11-05, A1). escrow is the
// rule of this round's escrow pass, the zero rule without one.
func (e *Engine) retention(activeKeyID string, keys []KeyRecord, sched backupset.Schedule,
	escrow escrowRule) retention {
	ret := retention{active: backupset.RepoPath(activeKeyID), retired: map[string]time.Time{},
		known: map[string]bool{backupset.RepoPath(activeKeyID): true}, full: sched.RetentionFull,
		keep: time.Duration(sched.RetentionFull) * hours(sched.FullIntervalHours),
		kindKeep: map[string]time.Duration{"openbao/": time.Duration(sched.OpenBaoKeepDays) * 24 * time.Hour,
			"fleet/": time.Duration(sched.FleetKeepDays) * 24 * time.Hour},
		escrow: escrow, now: e.now()}
	for _, k := range keys {
		if !backupset.ValidKeyID(k.ID) {
			continue
		}
		ret.known[backupset.RepoPath(k.ID)] = true
		if k.State == "retired" {
			ret.retired[backupset.RepoPath(k.ID)] = k.RetiredAt
		}
	}
	return ret
}

// walOK reports, per "<repository path>/<stanza>" of the active repository, whether the local archive is contiguous
// and pgBackRest's last whole-stanza verify (verify-ok in the stanza's state volume, run.sh full_backup) is newer than
// the newest completed full backup (plan M15, amendment 2026-11-05, A2). Only then may WAL leave a target (D2).
func (e *Engine) walOK(idx repoIndex, active string) map[string]bool {
	out := map[string]bool{}
	for _, stanza := range Stanzas {
		_, full := idx.newestFull(active, stanza)
		if full.IsZero() || !idx.contiguousWAL(active, stanza) {
			continue
		}
		state, err := os.OpenRoot(filepath.Join(e.cfg.StateDir, stanza))
		if err != nil {
			continue
		}
		verified := readEpoch(state, "verify-ok")
		_ = state.Close()
		if verified.After(full) {
			out[active+"/"+stanza] = true
		}
	}
	return out
}

// due reports whether a kind's newest success is older than its interval, waiting retryAfter after a failed attempt.
func (e *Engine) due(h KindHistory, interval time.Duration) bool {
	now := e.now()
	return now.Sub(h.LastSuccess) >= interval && now.Sub(h.LastAttempt) >= retryAfter
}

// writeRuntime writes the key file and schedule.env for pgBackRest (decision 16 a); both are replaced atomically.
func (e *Engine) writeRuntime(keyID string, key []byte, sched backupset.Schedule) error {
	full := time.Duration(sched.FullIntervalHours) * time.Hour
	if e.cfg.FullInterval > 0 {
		full = e.cfg.FullInterval
	}
	env := fmt.Sprintf("PADDOCK_BACKUP_REPO_PATH=%s\nPADDOCK_BACKUP_RETENTION_FULL=%d\nPADDOCK_BACKUP_FULL_INTERVAL_S=%d\n",
		backupset.RepoPath(keyID), sched.RetentionFull, int64(full/time.Second))
	rt, err := os.OpenRoot(e.cfg.RuntimeDir)
	if err != nil {
		return err
	}
	defer func() { _ = rt.Close() }()
	// pgBackRest's cipher pass is the key's base64 text, as it was with the host key file before M15.
	text := base64.StdEncoding.EncodeToString(key)
	if err := replaceFile(rt, keyFileName, []byte(text)); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}
	return replaceFile(rt, scheduleFileName, []byte(env))
}

// replaceFile writes data to name below r unless it already holds exactly data.
func replaceFile(r *os.Root, name string, data []byte) error {
	if cur, err := r.ReadFile(name); err == nil && bytes.Equal(cur, data) {
		return nil
	}
	return writeInRoot(r, name, bytes.NewReader(data), int64(len(data)))
}

func newRun(kind string, reqs []RequestedRun, started time.Time) run {
	return run{Kind: kind, Requests: reqs, StartedAt: started}
}

func (e *Engine) finish(r run, bytes int64, err error, class string) run {
	r.FinishedAt = e.now()
	r.Bytes = bytes
	r.Succeeded = err == nil
	if err != nil {
		r.ErrorClass = class
		slog.Warn("backup run failed", "kind", r.Kind, "error_class", class, "error", err)
	}
	return r
}

// snapshotOpenBao takes OpenBao's Raft snapshot, seals it with the key and stores it in the repository.
func (e *Engine) snapshotOpenBao(ctx context.Context, repo *os.Root, key []byte, reqs []RequestedRun) run {
	r := newRun(KindOpenBao, reqs, e.now())
	var buf bytes.Buffer
	err := e.snap.RaftSnapshot(ctx, &buf)
	if err == nil && buf.Len() == 0 {
		err = errors.New("openbao snapshot is empty")
	}
	var sealed []byte
	if err == nil {
		sealed, err = backup.Seal(key, buf.Bytes())
	}
	if err == nil {
		err = writeInRoot(repo, backupset.OpenBaoKey(r.StartedAt), bytes.NewReader(sealed), int64(len(sealed)))
	}
	return e.finish(r, int64(len(sealed)), err, runClassOpenBao)
}

// mirrorEscrow copies every escrowed LUKS header the repository lacks or holds with another size; objects are
// immutable, so name and size decide. Each copy's escrow object time (LastModified at copy time, never the local
// file's mtime) goes into the set's index, the manifest, so the escrow rule can tell whether a Destroy covers it (A2
// note c). Other objects of the bucket (diagnostics bundles) are never part of the set,
// and the role's read-only credential could not read them. It returns the rule that decides which header copies may
// leave the set and the targets this round (plan M15, amendment 2026-11-05, A2 note b): the zero rule, which deletes
// nothing, when the listing or the evidence query failed. A listing that lacks, without Destroy evidence, all or
// more than a tenth of the local headers is suspicious (an empty, re-created or wrong bucket): nothing is copied or
// deleted, the run fails and PaddockBackupEscrowListingSuspicious fires. Fewer such absences are held and warned
// about once per change.
func (e *Engine) mirrorEscrow(ctx context.Context, repo *os.Root, reqs []RequestedRun) (run, escrowRule) {
	r := newRun(KindEscrow, reqs, e.now())
	objects, err := e.escrow.ListInfo(ctx, "org/")
	if err != nil {
		return e.finish(r, 0, err, runClassEscrow), escrowRule{}
	}
	destroyed, err := e.store.EscrowEvidence(ctx)
	if err != nil {
		return e.finish(r, 0, fmt.Errorf("escrow evidence: %w", err), runClassEscrow), escrowRule{}
	}
	idx, err := indexRepo(repo)
	if err != nil {
		return e.finish(r, 0, err, runClassEscrow), escrowRule{}
	}
	rule := escrowRule{listed: map[string]bool{}, destroyed: destroyed, copied: recordedEscrowTimes(repo, idx)}
	for k, o := range objects {
		if !backupset.EscrowHeader(k) || !validPath(k) {
			continue
		}
		p := backupset.EscrowKey(k)
		rule.listed[p] = true
		// A copy whose time the index does not hold yet (a manifest written before the time was recorded) is the
		// object listed under its name with its size: objects are immutable, so this is its time at copy time too.
		if fi, held := idx[p]; held && fi.size == o.Size && rule.copied[p].IsZero() {
			rule.copied[p] = o.Modified.UTC()
		}
	}
	local := idx.under(backupset.EscrowKey(""))
	missing := rule.unevidenced(local)
	rule.suspicious = suspicious(len(missing), len(local))
	e.metrics.escrowUnevidenced.Set(float64(len(missing)))
	if rule.suspicious {
		e.metrics.escrowSuspicious.Set(1)
		slog.ErrorContext(ctx, "escrow bucket listing lacks escrowed headers without Destroy evidence; nothing copied or deleted",
			"missing", len(missing), "local", len(local))
		e.escrowMissing = missing
		return e.finish(r, 0, errors.New("suspicious escrow bucket listing"), runClassEscrow), rule
	}
	e.metrics.escrowSuspicious.Set(0)
	if len(missing) > 0 && !slices.Equal(missing, e.escrowMissing) {
		slog.WarnContext(ctx, "escrowed headers missing from the bucket without Destroy evidence are held",
			"missing", len(missing), "paths", missing)
	}
	e.escrowMissing = missing
	var total int64
	for _, k := range slices.Sorted(maps.Keys(objects)) {
		if !backupset.EscrowHeader(k) {
			continue
		}
		size := objects[k].Size
		total += size
		if !validPath(k) {
			slog.WarnContext(ctx, "escrow object with an unusable key skipped", "key", k)
			continue
		}
		local := backupset.EscrowKey(k)
		if info, err := repo.Stat(local); err == nil && info.Size() == size {
			continue
		}
		if err := e.copyEscrow(ctx, repo, k, local, size); err != nil {
			return e.finish(r, total, err, runClassEscrow), rule
		}
		rule.copied[local] = objects[k].Modified.UTC()
	}
	return e.finish(r, total, nil, ""), rule
}

func (e *Engine) copyEscrow(ctx context.Context, repo *os.Root, key, local string, size int64) error {
	body, err := e.escrow.Open(ctx, key)
	if err != nil {
		return err
	}
	defer func() { _ = body.Close() }()
	return writeInRoot(repo, local, body, size)
}

// fleetDump matches a complete plaintext dump of fleet-backup (backup.sh writes <ts>.sql.gz through a temporary name).
var fleetDump = regexp.MustCompile(`^(\d{8}T\d{6}Z)\.sql\.gz$`)

// fleet seals every complete dump fleet-backup left in the dumps volume and deletes the plaintext. A dump whose
// sealing failed is tried again after retryAfter (one failed run per attempt), and deleted with a failed run once it
// is older than fleetPlainMaxAge. When a dump is due or requested and none waits, it asks fleet-backup for one; a
// request fleet-backup did not answer within requestTimeout fails and is withdrawn.
func (e *Engine) fleet(ctx context.Context, repo *os.Root, key []byte, h KindHistory, interval time.Duration,
	reqs []RequestedRun) ([]run, error) {
	dumps, err := e.fleetDumps()
	if err != nil {
		return nil, err
	}
	var runs []run
	now := e.now()
	for _, d := range dumps {
		if now.Sub(d.at) > fleetPlainMaxAge {
			r := newRun(KindFleet, reqs, now)
			reqs = nil
			err := os.Remove(d.path)
			if err == nil {
				err = fmt.Errorf("fleet dump %s could not be sealed within %s; deleted", d.name, fleetPlainMaxAge)
			}
			delete(e.fleetFailed, d.name)
			runs = append(runs, e.finish(r, 0, err, runClassFleet))
			continue
		}
		if last, ok := e.fleetFailed[d.name]; ok && now.Sub(last) < retryAfter {
			continue
		}
		r := newRun(KindFleet, reqs, now)
		reqs = nil
		plain, err := os.ReadFile(d.path)
		var sealed []byte
		if err == nil {
			sealed, err = backup.Seal(key, plain)
		}
		if err == nil {
			err = writeInRoot(repo, backupset.FleetKey(d.at), bytes.NewReader(sealed), int64(len(sealed)))
		}
		if err == nil {
			err = os.Remove(d.path)
		}
		if err != nil {
			e.fleetFailed[d.name] = now
		} else {
			delete(e.fleetFailed, d.name)
		}
		runs = append(runs, e.finish(r, int64(len(sealed)), err, runClassFleet))
	}
	if len(dumps) > 0 || (!e.due(h, interval) && len(reqs) == 0) {
		return runs, nil
	}
	req := filepath.Join(e.cfg.FleetDumpsDir, fleetRequestFile)
	if _, err := os.Stat(req); err == nil {
		at := readEpochFile(req)
		if now.Sub(at) < requestTimeout {
			return runs, nil
		}
		if err := os.Remove(req); err != nil {
			return runs, fmt.Errorf("withdraw fleet dump request: %w", err)
		}
		answered := slices.DeleteFunc(slices.Clone(reqs), func(q RequestedRun) bool { return q.CreatedAt.After(at) })
		slog.WarnContext(ctx, "fleet-backup did not answer the dump request", "requested_at", at)
		return append(runs, run{Kind: KindFleet, Requests: answered, StartedAt: at, FinishedAt: now,
			ErrorClass: runClassTimeout}), nil
	}
	if err := os.WriteFile(req, []byte(strconv.FormatInt(e.now().Unix(), 10)), 0o640); err != nil { //nolint:gosec // fixed name in the dumps volume
		return runs, fmt.Errorf("request fleet dump: %w", err)
	}
	slog.InfoContext(ctx, "fleet dump requested")
	return runs, nil
}

// fleetDumpFile is a complete plaintext dump in the dumps volume.
type fleetDumpFile struct {
	name, path string
	at         time.Time
}

// fleetDumps lists the complete plaintext dumps fleet-backup left, oldest first.
func (e *Engine) fleetDumps() ([]fleetDumpFile, error) {
	entries, err := os.ReadDir(e.cfg.FleetDumpsDir)
	if err != nil {
		return nil, fmt.Errorf("fleet dumps: %w", err)
	}
	var out []fleetDumpFile
	for _, ent := range entries {
		m := fleetDump.FindStringSubmatch(ent.Name())
		if m == nil || !ent.Type().IsRegular() {
			continue
		}
		at, err := time.Parse("20060102T150405Z", m[1])
		if err != nil {
			continue
		}
		out = append(out, fleetDumpFile{name: ent.Name(), path: filepath.Join(e.cfg.FleetDumpsDir, ent.Name()), at: at})
	}
	return out, nil
}

// dropStaleDumps deletes the plaintext dumps older than fleetPlainMaxAge while no key is confirmed: nothing can seal
// them, and nothing is recorded without a key (decision 16 a).
func (e *Engine) dropStaleDumps(ctx context.Context) error {
	dumps, err := e.fleetDumps()
	if err != nil {
		return err
	}
	var errs []error
	for _, d := range dumps {
		if e.now().Sub(d.at) <= fleetPlainMaxAge {
			continue
		}
		if err := os.Remove(d.path); err != nil {
			errs = append(errs, err)
			continue
		}
		slog.WarnContext(ctx, "plaintext fleet dump deleted unsealed: no confirmed backup key", "dump", d.name)
	}
	return errors.Join(errs...)
}

// readEpochFile reads a file holding Unix seconds; zero when it is absent or unreadable.
func readEpochFile(p string) time.Time {
	r, err := os.OpenRoot(filepath.Dir(p))
	if err != nil {
		return time.Time{}
	}
	defer func() { _ = r.Close() }()
	return readEpoch(r, filepath.Base(p))
}

// pgbackrest records the full backups and failures pgBackRest's serve reported in its state volumes since the
// newest recorded run of the kind, and hands requested runs to serve through a request file in the runtime tmpfs.
func (e *Engine) pgbackrest(ctx context.Context, keyID string, history map[string]KindHistory,
	byKind map[string][]RequestedRun) ([]run, error) {
	var runs []run
	var errs []error
	rt, err := os.OpenRoot(e.cfg.RuntimeDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rt.Close() }()
	for _, kind := range []string{KindPostgres, KindAuthentik} {
		stanza := Stanzas[kind]
		state, err := os.OpenRoot(filepath.Join(e.cfg.StateDir, stanza))
		if err != nil {
			errs = append(errs, fmt.Errorf("pgbackrest state of %s: %w", stanza, err))
			continue
		}
		last := history[kind].LastAttempt
		full, failed := readEpoch(state, "last-full"), readEpoch(state, "last-error")
		_ = state.Close()
		reqs := byKind[kind]
		if failed.After(last) {
			slog.WarnContext(ctx, "pgBackRest reported a failed full backup", "kind", kind)
			runs = append(runs, run{Kind: kind, StartedAt: failed, FinishedAt: failed, ErrorClass: runClassPgBackRest})
		}
		if full.After(last) {
			answered := slices.DeleteFunc(slices.Clone(reqs), func(q RequestedRun) bool { return q.CreatedAt.After(full) })
			reqs = slices.DeleteFunc(slices.Clone(reqs), func(q RequestedRun) bool { return !q.CreatedAt.After(full) })
			runs = append(runs, e.fullRun(kind, stanza, keyID, full, answered))
		}
		reqName := "request-" + stanza
		if len(reqs) == 0 {
			if err := rt.Remove(reqName); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			}
			continue
		}
		if err := replaceFile(rt, reqName, []byte(strconv.FormatInt(reqs[0].CreatedAt.Unix(), 10))); err != nil {
			errs = append(errs, err)
		}
	}
	return runs, errors.Join(errs...)
}

// fullRun is the run of a verified full backup that pgBackRest finished at full; its size is the backup's directory.
func (e *Engine) fullRun(kind, stanza, keyID string, full time.Time, reqs []RequestedRun) run {
	r := run{Kind: kind, Requests: reqs, StartedAt: full, FinishedAt: full, Succeeded: true}
	repo, err := os.OpenRoot(e.cfg.RepoDir)
	if err != nil {
		return r
	}
	defer func() { _ = repo.Close() }()
	idx, err := indexRepo(repo)
	if err != nil {
		return r
	}
	repoPath := backupset.RepoPath(keyID)
	if label, started := idx.newestFull(repoPath, stanza); label != "" {
		r.Bytes = idx.bytesUnder(repoPath + "/backup/" + stanza + "/" + label + "/")
		if !started.After(full) {
			r.StartedAt = started
		}
	}
	return r
}

// timeouts fails the requested runs of the kinds another container executes once they waited requestTimeout.
func (e *Engine) timeouts(byKind map[string][]RequestedRun, runs []run) []run {
	answered := map[string]bool{}
	for _, r := range runs {
		for _, q := range r.Requests {
			answered[q.ID.String()] = true
		}
	}
	var out []run
	for _, kind := range []string{KindPostgres, KindAuthentik, KindFleet} {
		var late []RequestedRun
		for _, q := range byKind[kind] {
			if !answered[q.ID.String()] && e.now().Sub(q.CreatedAt) >= requestTimeout {
				late = append(late, q)
			}
		}
		if len(late) > 0 {
			now := e.now()
			out = append(out, run{Kind: kind, Requests: late, StartedAt: late[0].CreatedAt, FinishedAt: now,
				ErrorClass: runClassTimeout})
		}
	}
	return out
}

// expire is the role's part of the local expire (plan M15, amendment 2026-11-05, A2; pgBackRest expires the fulls
// and WAL of the active repository itself). It deletes the snapshots and dumps older than their keep days, but never
// the newest of a kind, so a kind that keeps failing still has its last good file; the escrowed headers the escrow
// rule lets go (escrowRule: a Destroy older than the keep window, never mere absence from the bucket); and the repository of a retired key once the active
// key's repository holds a full backup of every stanza and max(its newest file, retired_at) is older than
// retention_full full intervals. It reports whether it deleted.
func (e *Engine) expire(ctx context.Context, repo *os.Root, idx repoIndex, ret retention) bool {
	deleted := false
	remove := func(p string) {
		if err := repo.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			slog.WarnContext(ctx, "expire failed", "path", p, "error", err)
			return
		}
		deleted = true
	}
	for _, dir := range []string{"openbao/", "fleet/"} {
		newest := ""
		for _, p := range idx.under(dir) {
			if newest == "" || fileTime(p, idx[p]).After(fileTime(newest, idx[newest])) {
				newest = p
			}
		}
		for _, p := range idx.under(dir) {
			if p != newest && ret.now.Sub(fileTime(p, idx[p])) > ret.kindKeep[dir] {
				remove(p)
			}
		}
	}
	for _, p := range idx.under("escrow/") {
		if ret.escrow.gone(p, ret.now, ret.keep) {
			remove(p)
		}
	}
	if !activeComplete(idx, ret.active) {
		return deleted
	}
	for _, repoPath := range slices.Sorted(maps.Keys(ret.retired)) {
		dir := repoPath + "/"
		newest := ret.retired[repoPath]
		found := false
		for _, p := range idx.under(dir) {
			found = true
			if idx[p].mod.After(newest) {
				newest = idx[p].mod
			}
		}
		if !found || ret.now.Sub(newest) <= ret.keep {
			continue
		}
		if err := repo.RemoveAll(path.Clean(dir)); err != nil {
			slog.WarnContext(ctx, "expire of a retired key's repository failed", "path", repoPath, "error", err)
			continue
		}
		slog.InfoContext(ctx, "expired the repository of a retired backup key", "path", repoPath)
		deleted = true
	}
	return deleted
}

// kindInfo is the newest backup time and the size of one kind in the set.
type kindInfo struct {
	at    time.Time
	bytes int64
}

func (e *Engine) kindState(idx repoIndex, keyID string, history map[string]KindHistory, runs []run) map[string]kindInfo {
	repoPath := backupset.RepoPath(keyID)
	out := map[string]kindInfo{}
	for kind, stanza := range Stanzas {
		_, at := idx.newestFull(repoPath, stanza)
		out[kind] = kindInfo{at: at, bytes: idx.bytesUnder(repoPath+"/backup/"+stanza+"/") +
			idx.bytesUnder(repoPath+"/archive/"+stanza+"/")}
	}
	out[KindOpenBao] = kindInfo{at: idx.newestTime("openbao/"), bytes: idx.bytesUnder("openbao/")}
	out[KindFleet] = kindInfo{at: idx.newestTime("fleet/"), bytes: idx.bytesUnder("fleet/")}
	escrowAt := history[KindEscrow].LastSuccess
	for _, r := range runs {
		if r.Kind == KindEscrow && r.Succeeded && r.FinishedAt.After(escrowAt) {
			escrowAt = r.FinishedAt
		}
	}
	out[KindEscrow] = kindInfo{at: escrowAt, bytes: idx.bytesUnder("escrow/")}
	return out
}

// writeManifest writes manifest.json when the set's content changed (decision 16 d). An escrowed header's time is
// the escrow object's time of this round's escrow pass (copied), else the one the previous manifest recorded.
func (e *Engine) writeManifest(ctx context.Context, repo *os.Root, idx repoIndex, key ActiveKey, kinds map[string]kindInfo,
	copied map[string]time.Time) error {
	installation, err := e.store.InstallationID(ctx)
	if err != nil {
		return fmt.Errorf("manifest: installation ID: %w", err)
	}
	version, err := e.store.SchemaVersion(ctx)
	if err != nil {
		return fmt.Errorf("manifest: schema version: %w", err)
	}
	repoPath := backupset.RepoPath(key.ID)
	m := backupset.Manifest{Schema: backupset.ManifestSchema, InstallationID: installation,
		ServerVersion: e.cfg.ServerVersion, GeneratedAt: e.now().UTC(), KeyID: key.ID, KeyFingerprint: key.Fingerprint,
		SchemaVersions: map[string]int{"paddock": version}}
	m.Contents.PgBackRest.Path = repoPath
	for _, kind := range []string{KindPostgres, KindAuthentik} {
		stanza := Stanzas[kind]
		label, at := idx.newestFull(repoPath, stanza)
		wal, _ := idx.newestWAL(repoPath, stanza)
		m.Contents.PgBackRest.Stanzas = append(m.Contents.PgBackRest.Stanzas,
			backupset.Stanza{Name: stanza, LastFull: label, LastFullAt: at, WALMax: wal})
	}
	if m.Contents.OpenBao, err = manifestFiles(repo, idx, "openbao/", true, e.hashes); err != nil {
		return err
	}
	if m.Contents.Fleet, err = manifestFiles(repo, idx, "fleet/", true, e.hashes); err != nil {
		return err
	}
	if m.Contents.Escrow, err = manifestFiles(repo, idx, "escrow/", false, e.hashes); err != nil {
		return err
	}
	times := recordedEscrowTimes(repo, idx)
	maps.Copy(times, copied)
	for i, f := range m.Contents.Escrow {
		m.Contents.Escrow[i].At = times[f.Path]
	}
	if cur, err := repo.ReadFile(backupset.ManifestPath); err == nil {
		if old, err := backupset.Parse(cur); err == nil {
			old.GeneratedAt = m.GeneratedAt
			if reflect.DeepEqual(normalized(old), normalized(m)) {
				return nil
			}
		}
	}
	out, err := m.Marshal()
	if err != nil {
		return err
	}
	return writeInRoot(repo, backupset.ManifestPath, bytes.NewReader(out), int64(len(out)))
}

// normalized makes a parsed and a built manifest comparable (empty lists, UTC times).
func normalized(m backupset.Manifest) backupset.Manifest {
	b, err := m.Marshal()
	if err != nil {
		return m
	}
	out, err := backupset.Parse(b)
	if err != nil {
		return m
	}
	return out
}

// repoMetrics exports the repository's ages, WAL ages and file system usage.
func (e *Engine) repoMetrics(idx repoIndex, keyID string, kinds map[string]kindInfo) {
	for kind, k := range kinds {
		e.metrics.lastSuccess.WithLabelValues(kind, RepoTarget).Set(unix(k.at))
	}
	repoPath := backupset.RepoPath(keyID)
	for _, stanza := range Stanzas {
		_, at := idx.newestWAL(repoPath, stanza)
		e.metrics.walArchived.WithLabelValues(stanza).Set(unix(at))
	}
	e.metrics.walStanzas.Set(float64(len(Stanzas)))
	var st syscall.Statfs_t
	if err := syscall.Statfs(e.cfg.RepoDir, &st); err == nil {
		bsize := uint64(st.Bsize) //nolint:gosec // a block size is positive
		e.metrics.repoBytes.WithLabelValues("used").Set(float64((st.Blocks - st.Bfree) * bsize))
		e.metrics.repoBytes.WithLabelValues("free").Set(float64(st.Bavail * bsize))
	}
}

func unix(t time.Time) float64 {
	if t.IsZero() {
		return 0
	}
	return float64(t.Unix())
}

// mirrorAll mirrors the set to every enabled target, writes their status per kind and returns the runs' target
// results. A failing target never stops the others.
func (e *Engine) mirrorAll(ctx context.Context, repo *os.Root, idx repoIndex, targets []TargetRecord,
	kinds map[string]kindInfo, ret retention) []backupset.RunTarget {
	results := []backupset.RunTarget{}
	e.metrics.reachable.Reset()
	e.metrics.held.Reset()
	enabled := 0
	for _, t := range targets {
		if !t.Enabled {
			continue
		}
		enabled++
		class, held := "", 0
		switch {
		case backupset.Mounted(t.Type) && t.HostState == HostPending:
			class = ClassNotMounted
		case backupset.Mounted(t.Type) && t.HostState == HostUnreachable:
			class = ClassIO
		default:
			var err error
			held, err = e.mirrorTarget(ctx, repo, idx, t, ret)
			switch {
			case errors.Is(err, errBudget):
				class = ErrorClass(err)
				slog.InfoContext(ctx, "mirror to backup target continues next round", "target", t.Name)
			case err != nil:
				class = ErrorClass(err)
				slog.WarnContext(ctx, "mirror to backup target failed", "target", t.Name, "error_class", class, "error", err)
			}
		}
		results = append(results, backupset.RunTarget{TargetID: t.ID.String(), OK: class == "", ErrorClass: class,
			Held: held})
		if class == "" || class == ClassUnknownPath {
			e.held[t.ID] = held
		}
		e.metrics.held.WithLabelValues(t.Name).Set(float64(e.held[t.ID]))
		if class == "" {
			e.metrics.reachable.WithLabelValues(t.Name).Set(1)
			held := map[string]time.Time{}
			for kind, k := range kinds {
				held[kind] = k.at
			}
			e.mirrored[t.Name] = held
		} else {
			e.metrics.reachable.WithLabelValues(t.Name).Set(0)
		}
		for _, kind := range backupset.Kinds {
			st := KindStatus{LastSuccess: kinds[kind].at, Bytes: kinds[kind].bytes, Error: class}
			if err := e.store.SetTargetStatus(ctx, t.ID, kind, st); err != nil {
				slog.WarnContext(ctx, "backup target status not written", "target", t.Name, "error", err)
			}
		}
	}
	e.metrics.lastSuccess.Reset()
	for kind, k := range kinds {
		e.metrics.lastSuccess.WithLabelValues(kind, RepoTarget).Set(unix(k.at))
	}
	for _, t := range targets {
		held, ok := e.mirrored[t.Name]
		if !t.Enabled || !ok {
			continue
		}
		for kind, at := range held {
			e.metrics.lastSuccess.WithLabelValues(kind, t.Name).Set(unix(at))
		}
	}
	e.metrics.series.Set(float64(len(backupset.Kinds) * (1 + enabled)))
	return results
}

// errStalled marks a target operation that made no progress within its deadline.
var errStalled = errors.New("backup target stalled")

// mirrorTarget mirrors the set to t in a goroutine and waits while it makes progress: a target that stalls for
// e.stall fails (its context is cancelled) and the round goes on. A mirror blocked in a file system call keeps the
// target busy, and the next rounds skip it until that call returns. After e.budget the mirror ends with the file it
// is copying (errBudget); a target that trickles cannot stretch that file without bound: the mirror is cancelled at
// started + budget + size/minRate of the file being copied (plan M15, amendment 2026-11-05, A7). The cap applies
// only while a file is being copied: a listing that keeps delivering pages is bounded by the stall deadline alone,
// else a target holding a few hundred thousand objects never reaches its deletions (PDK-865). It returns the number
// of objects the target holds back (mirrorSet).
func (e *Engine) mirrorTarget(ctx context.Context, repo *os.Root, idx repoIndex, t TargetRecord,
	ret retention) (int, error) {
	e.busyMu.Lock()
	if e.busy[t.ID] {
		e.busyMu.Unlock()
		return 0, fmt.Errorf("%w: the previous mirror has not returned", errStalled)
	}
	e.busy[t.ID] = true
	e.busyMu.Unlock()
	pushed := e.pushed[t.ID]
	if pushed == nil {
		pushed = map[string]fileInfo{}
		e.pushed[t.ID] = pushed
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var progress, copying atomic.Int64
	copying.Store(-1)
	type result struct {
		held int
		err  error
	}
	done := make(chan result, 1)
	started, budget := time.Now(), e.budget
	go func() {
		dst, err := e.targets.Open(ctx, t)
		held := 0
		if err == nil {
			held, err = mirrorSet(ctx, repo, idx, dst, pushed, ret, mirrorHooks{
				tick:  func() { progress.Add(1) },
				begin: func(size int64) { copying.Store(size) },
				end:   func() { copying.Store(-1) },
				stop:  func() bool { return time.Since(started) >= budget }})
		}
		e.busyMu.Lock()
		delete(e.busy, t.ID)
		e.busyMu.Unlock()
		done <- result{held, err}
	}()
	check := time.NewTicker(e.stall / 4)
	defer check.Stop()
	last, since := int64(0), time.Now()
	for {
		select {
		case r := <-done:
			return r.held, r.err
		case <-check.C:
			if n := progress.Load(); n != last {
				last, since = n, time.Now()
			} else if time.Since(since) >= e.stall {
				return 0, fmt.Errorf("%w: no progress for %s", errStalled, e.stall)
			}
			if size := copying.Load(); size >= 0 {
				trickle := time.Duration(float64(size) / float64(e.minRate) * float64(time.Second))
				if time.Since(started) >= budget+trickle {
					return 0, fmt.Errorf("%w: slower than %d bytes/s past the round's budget", errStalled, e.minRate)
				}
			}
		}
	}
}

// bounded runs fn with a deadline and returns once it returns or the deadline passed; fn's context ends then, and a
// call blocked in the file system returns later on its own.
func bounded(ctx context.Context, d time.Duration, fn func(ctx context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- fn(ctx) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return fmt.Errorf("%w: %w", errStalled, ctx.Err())
	}
}

// hostState checks t's volume within probeTimeout; a check that does not finish counts as unreachable. A check blocked
// in the file system cannot be interrupted, so while it has not returned the next rounds do not start another one
// (each would hold an OS thread for as long as the share hangs).
func (e *Engine) hostState(t TargetRecord) string {
	e.busyMu.Lock()
	if e.checking[t.ID] {
		e.busyMu.Unlock()
		return HostUnreachable
	}
	e.checking[t.ID] = true
	e.busyMu.Unlock()
	done := make(chan string, 1)
	go func() {
		st := HostState(e.cfg.TargetsDir, t)
		e.busyMu.Lock()
		delete(e.checking, t.ID)
		e.busyMu.Unlock()
		done <- st
	}()
	select {
	case st := <-done:
		return st
	case <-time.After(probeTimeout):
		return HostUnreachable
	}
}

// hostStates updates the host state of every volume target from its marker file (decision 16 g).
func (e *Engine) hostStates(ctx context.Context, targets []TargetRecord) error {
	var errs []error
	for i := range targets {
		t := &targets[i]
		if !backupset.Mounted(t.Type) {
			continue
		}
		state := e.hostState(*t)
		if state == t.HostState {
			continue
		}
		if err := e.store.SetHostState(ctx, t.ID, t.HostRevision, state); err != nil {
			errs = append(errs, err)
			continue
		}
		slog.InfoContext(ctx, "backup target host state changed", "target", t.Name, "from", t.HostState, "to", state)
		t.HostState = state
	}
	return errors.Join(errs...)
}

// test runs one connection test within testTimeout. A test blocked in the file system cannot be interrupted, so while
// it has not returned a repeated request fails at once instead of holding another OS thread on the hung share.
func (e *Engine) test(ctx context.Context, t TargetRecord) error {
	e.busyMu.Lock()
	if e.testing[t.ID] {
		e.busyMu.Unlock()
		return fmt.Errorf("%w: the previous test has not returned", errStalled)
	}
	e.testing[t.ID] = true
	e.busyMu.Unlock()
	return bounded(ctx, testTimeout, func(ctx context.Context) error {
		defer func() {
			e.busyMu.Lock()
			delete(e.testing, t.ID)
			e.busyMu.Unlock()
		}()
		dst, err := e.targets.Open(ctx, t)
		if err == nil {
			err = dst.Probe(ctx)
		}
		return err
	})
}

// tests runs the connection tests the api requested (decision 11) and stores their error class.
func (e *Engine) tests(ctx context.Context, targets []TargetRecord) error {
	var errs []error
	for _, t := range targets {
		if !t.TestRequested {
			continue
		}
		class := ""
		switch {
		case backupset.Mounted(t.Type) && t.HostState == HostPending:
			class = ClassNotMounted
		default:
			err := e.test(ctx, t)
			if err != nil {
				class = ErrorClass(err)
				slog.InfoContext(ctx, "backup target test failed", "target", t.Name, "error_class", class, "error", err)
			}
		}
		if err := e.store.SetTestResult(ctx, t.ID, class); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
