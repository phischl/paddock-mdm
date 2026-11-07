package backuprole

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

// ActiveKey is the confirmed backup key: its Transit ciphertext, never the key itself.
type ActiveKey struct {
	ID          string
	Ciphertext  string
	Fingerprint string
}

// KeyRecord is a backup key the database knows: its ID, its state and, once retired, when (plan M15, amendment
// 2026-11-05, A1).
type KeyRecord struct {
	ID        string
	State     string
	RetiredAt time.Time
}

// TargetRecord is a backup target as the role reads it, credentials still encrypted.
type TargetRecord struct {
	ID                    uuid.UUID
	Name                  string
	Type                  backupset.TargetType
	Enabled               bool
	Settings              backupset.Settings
	CredentialsCiphertext string
	HostState             string
	HostRevision          int
	TestRequested         bool
}

// KindStatus is what a target holds of one kind after a mirror; Error is the error class of a failed mirror.
type KindStatus struct {
	LastSuccess time.Time
	Bytes       int64
	Error       string
}

// RequestedRun is a run a platform administrator or the host requested (state requested).
type RequestedRun struct {
	ID        uuid.UUID
	Kind      string
	Label     string
	CreatedAt time.Time
}

// KindHistory is the newest finished attempt and the newest success of one kind.
type KindHistory struct {
	LastAttempt time.Time
	LastSuccess time.Time
}

// RunRecord is one finished run of one kind (plan M15 decision 16); its mirror results follow in MirrorRuns.
type RunRecord struct {
	Kind string
	// Requests are the requested rows the run answers; without one the run is recorded as a new row.
	Requests   []RequestedRun
	Succeeded  bool
	ErrorClass string
	StartedAt  time.Time
	FinishedAt time.Time
	Bytes      int64
}

// Store is the database of the backup role.
type Store interface {
	ActiveKey(ctx context.Context) (ActiveKey, bool, error)
	Keys(ctx context.Context) ([]KeyRecord, error)
	Schedule(ctx context.Context) (backupset.Schedule, error)
	Targets(ctx context.Context) ([]TargetRecord, error)
	// SetHostState changes the host state only while the target still has the revision the caller read.
	SetHostState(ctx context.Context, id uuid.UUID, revision int, state string) error
	SetTestResult(ctx context.Context, id uuid.UUID, errClass string) error
	SetTargetStatus(ctx context.Context, id uuid.UUID, kind string, s KindStatus) error
	RequestedRuns(ctx context.Context) ([]RequestedRun, error)
	History(ctx context.Context) (map[string]KindHistory, error)
	// RecordRun writes a finished run right after its local step (phase 1); MirrorRuns adds the round's mirror results
	// and the audit event to every run still without them (phase 2, decisions-alpha9 item 79).
	// RecordRun returns the IDs of the rows it wrote; MirrorRuns leaves the runs of skip for a later round.
	RecordRun(ctx context.Context, r RunRecord) ([]uuid.UUID, error)
	MirrorRuns(ctx context.Context, results []backupset.RunTarget, skip []uuid.UUID) error
	// EscrowEvidence returns, by "<org>/<device>", the time of every device's newest successful Destroy
	// (device.escrow_destroyed): the only audited evidence that lets an escrowed header copy leave the set.
	EscrowEvidence(ctx context.Context) (map[string]time.Time, error)
	InstallationID(ctx context.Context) (string, error)
	SchemaVersion(ctx context.Context) (int, error)
	// BundleSeqHighWater returns the highest device.bundle_seq (decisions-alpha9 item 68).
	BundleSeqHighWater(ctx context.Context) (int64, error)
}

// Actor is the system actor of the backup role's audit events.
const Actor = "paddock-backup"

// SpecCompleted and SpecFailed are the run events (plan M15 §6.4).
var (
	SpecCompleted = app.ActionSpec{Code: audit.CodePlatformBackupCompleted}
	SpecFailed    = app.ActionSpec{Code: audit.CodePlatformBackupFailed}
)

// pgStore is the Store on role paddock_backup; the platform pool only reads the schema version.
type pgStore struct {
	pool     *db.BackupPool
	platform *db.PlatformPool
	runner   *app.ActionRunner
}

// NewPGStore creates the store; runner MUST be built with app.WithPlatformScope(pool.InBackup), so a run row and its
// audit event commit together under paddock_backup.
func NewPGStore(pool *db.BackupPool, platform *db.PlatformPool, runner *app.ActionRunner) Store {
	return &pgStore{pool: pool, platform: platform, runner: runner}
}

func (s *pgStore) ActiveKey(ctx context.Context) (ActiveKey, bool, error) {
	var k ActiveKey
	found := false
	err := s.pool.InBackup(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		row, err := q.BackupRoleActiveKey(ctx)
		if db.IsNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		k, found = ActiveKey{ID: row.KeyID, Ciphertext: row.Ciphertext, Fingerprint: row.Fingerprint}, true
		return nil
	})
	return k, found, err
}

func (s *pgStore) Keys(ctx context.Context) ([]KeyRecord, error) {
	var out []KeyRecord
	err := s.pool.InBackup(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		rows, err := q.BackupRoleKeys(ctx)
		if err != nil {
			return err
		}
		for _, r := range rows {
			k := KeyRecord{ID: r.KeyID, State: r.State}
			if r.RetiredAt != nil {
				k.RetiredAt = r.RetiredAt.UTC()
			}
			out = append(out, k)
		}
		return nil
	})
	return out, err
}

func (s *pgStore) EscrowEvidence(ctx context.Context) (map[string]time.Time, error) {
	out := map[string]time.Time{}
	err := s.pool.InBackup(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		rows, err := q.BackupRoleEscrowEvidence(ctx)
		if err != nil {
			return err
		}
		for _, r := range rows {
			out[r.OrganizationID.String()+"/"+r.DeviceID] = r.DestroyedAt.UTC()
		}
		return nil
	})
	return out, err
}

func (s *pgStore) Schedule(ctx context.Context) (backupset.Schedule, error) {
	sc := backupset.DefaultSchedule()
	err := s.pool.InBackup(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		row, err := q.GetBackupSchedule(ctx)
		if db.IsNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		sc = backupset.Schedule{FullIntervalHours: int(row.FullIntervalHours), OpenBaoIntervalHours: int(row.OpenbaoIntervalHours),
			FleetIntervalHours: int(row.FleetIntervalHours), EscrowIntervalHours: int(row.EscrowIntervalHours),
			RetentionFull: int(row.RetentionFull), OpenBaoKeepDays: int(row.OpenbaoKeepDays), FleetKeepDays: int(row.FleetKeepDays)}
		return nil
	})
	return sc, err
}

func (s *pgStore) Targets(ctx context.Context) ([]TargetRecord, error) {
	var out []TargetRecord
	err := s.pool.InBackup(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		rows, err := q.BackupRoleTargets(ctx)
		if err != nil {
			return err
		}
		for _, r := range rows {
			settings, err := backupset.ParseSettings(r.Settings)
			if err != nil {
				return err
			}
			t := TargetRecord{ID: r.ID, Name: r.Name, Type: backupset.TargetType(r.Type), Enabled: r.Enabled,
				Settings: settings, HostState: r.HostState, HostRevision: int(r.HostRevision),
				TestRequested: r.TestRequestedAt != nil}
			if r.CredentialsCiphertext != nil {
				t.CredentialsCiphertext = *r.CredentialsCiphertext
			}
			out = append(out, t)
		}
		return nil
	})
	return out, err
}

func (s *pgStore) SetHostState(ctx context.Context, id uuid.UUID, revision int, state string) error {
	return s.pool.InBackup(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		return q.BackupRoleSetHostState(ctx, pgstore.BackupRoleSetHostStateParams{ID: id, HostRevision: int32(revision), HostState: state}) //nolint:gosec // the revision was read from this int column
	})
}

func (s *pgStore) SetTestResult(ctx context.Context, id uuid.UUID, errClass string) error {
	ok := errClass == ""
	return s.pool.InBackup(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		return q.BackupRoleSetTestResult(ctx, pgstore.BackupRoleSetTestResultParams{ID: id, Ok: &ok, ErrorClass: optional(errClass)})
	})
}

func (s *pgStore) SetTargetStatus(ctx context.Context, id uuid.UUID, kind string, st KindStatus) error {
	p := pgstore.BackupRoleUpsertTargetStatusParams{TargetID: id, Kind: kind, Bytes: st.Bytes, LastError: optional(st.Error)}
	if st.Error == "" && !st.LastSuccess.IsZero() {
		at := st.LastSuccess
		p.LastSuccessAt = &at
	}
	return s.pool.InBackup(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		return q.BackupRoleUpsertTargetStatus(ctx, p)
	})
}

func (s *pgStore) RequestedRuns(ctx context.Context) ([]RequestedRun, error) {
	var out []RequestedRun
	err := s.pool.InBackup(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		rows, err := q.BackupRoleRequestedRuns(ctx)
		for _, r := range rows {
			out = append(out, RequestedRun{ID: r.ID, Kind: r.Kind, Label: r.Label, CreatedAt: r.CreatedAt})
		}
		return err
	})
	return out, err
}

func (s *pgStore) History(ctx context.Context) (map[string]KindHistory, error) {
	out := map[string]KindHistory{}
	err := s.pool.InBackup(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		latest, err := q.BackupRoleLatestFinishedRuns(ctx)
		if err != nil {
			return err
		}
		for _, r := range latest {
			if r.FinishedAt != nil {
				h := out[r.Kind]
				h.LastAttempt = *r.FinishedAt
				out[r.Kind] = h
			}
		}
		ok, err := q.LastSucceededBackupRuns(ctx)
		if err != nil {
			return err
		}
		for _, r := range ok {
			if r.FinishedAt != nil {
				h := out[r.Kind]
				h.LastSuccess = *r.FinishedAt
				out[r.Kind] = h
			}
		}
		return nil
	})
	return out, err
}

// RecordRun writes every requested row the run answers, or one new row, each with its own audit event in the same
// transaction (plan M15 decision 16: one row and one event per run).
// RecordRun is phase 1 of a run (decisions-alpha9 item 79): it writes the finished run, or answers its requests, right
// after the local step and without the mirror's results, so that `backup now --wait` and restore plans see it at once.
// The run's audit event follows in MirrorRuns. A run that cannot be written gets its one event here instead: a
// platform.backup_failed with error_class record, since without a row phase 2 never sees it.
func (s *pgStore) RecordRun(ctx context.Context, r RunRecord) ([]uuid.UUID, error) {
	ids, err := s.recordRun(ctx, r)
	if err == nil {
		return ids, nil
	}
	spec := SpecFailed
	id := uuid.Must(uuid.NewV7())
	label := ""
	if len(r.Requests) > 0 {
		id, label = r.Requests[0].ID, r.Requests[0].Label
	}
	spec.Target = &audit.Target{Type: "backup_run", ID: id.String(), Display: r.Kind}
	spec.Params = map[string]any{"run_id": id.String(), "kind": r.Kind, "label": label, "bytes": r.Bytes,
		"duration_s":   int64(r.FinishedAt.Sub(r.StartedAt).Round(time.Second) / time.Second),
		"completed_at": r.FinishedAt.UTC().Format(time.RFC3339), "targets_ok": 0, "targets_failed": 0,
		"error_class": runClassRecord}
	_ = s.runner.RecordRefusal(context.WithoutCancel(SystemContext(ctx)), app.ScopePlatform, spec, err)
	return nil, err
}

func (s *pgStore) recordRun(ctx context.Context, r RunRecord) ([]uuid.UUID, error) {
	outcome := "failed"
	if r.Succeeded {
		outcome = "succeeded"
	}
	rows := r.Requests
	if len(rows) == 0 {
		rows = []RequestedRun{{Kind: r.Kind}}
	}
	started, finished := r.StartedAt, r.FinishedAt
	empty := []byte("[]")
	var ids []uuid.UUID
	err := s.pool.InBackup(SystemContext(ctx), func(ctx context.Context, q *pgstore.Queries) error {
		ids = ids[:0]
		for _, req := range rows {
			if req.ID == uuid.Nil {
				id := uuid.Must(uuid.NewV7())
				ids = append(ids, id)
				if err := q.BackupRoleInsertFinishedRun(ctx, pgstore.BackupRoleInsertFinishedRunParams{
					ID: id, Kind: r.Kind, Outcome: &outcome, StartedAt: &started,
					FinishedAt: &finished, Bytes: r.Bytes, ErrorClass: optional(r.ErrorClass), Targets: empty}); err != nil {
					return err
				}
				continue
			}
			n, err := q.BackupRoleFinishRequestedRun(ctx, pgstore.BackupRoleFinishRequestedRunParams{ID: req.ID,
				Outcome: &outcome, StartedAt: &started, FinishedAt: &finished, Bytes: r.Bytes,
				ErrorClass: optional(r.ErrorClass), Targets: empty})
			if err != nil {
				return err
			}
			if n != 1 {
				return fmt.Errorf("backup run %s is no longer requested", req.ID)
			}
			ids = append(ids, req.ID)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ids, nil
}

// MirrorRuns is phase 2 (decisions-alpha9 item 79): every finished run whose mirror is still due, this round's and one
// an earlier round could not finish (the role stopped in between), gets the round's mirror results and its audit
// event (plan M15 §6.4); a target the set did not reach counts as targets_failed. completed_at is the run's local
// completion, which the event's own time may follow by the length of the mirror.
func (s *pgStore) MirrorRuns(ctx context.Context, results []backupset.RunTarget, skip []uuid.UUID) error {
	targets, err := json.Marshal(nonNilTargets(results))
	if err != nil {
		return err
	}
	ok, failed := 0, 0
	for _, t := range results {
		if t.OK {
			ok++
		} else {
			failed++
		}
	}
	// A shutdown must not split a run between a failure event and a retried one: the loop finishes on its own clock.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(SystemContext(ctx)), mirrorRunsTimeout)
	defer cancel()
	var due []pgstore.BackupRoleUnmirroredRunsRow
	if err := s.pool.InBackup(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		due, err = q.BackupRoleUnmirroredRuns(ctx)
		return err
	}); err != nil {
		return err
	}
	for _, r := range due {
		if slices.Contains(skip, r.ID) {
			continue
		}
		spec := SpecFailed
		succeeded := r.Outcome != nil && *r.Outcome == "succeeded"
		if succeeded {
			spec = SpecCompleted
		}
		var duration int64
		completed := ""
		if r.StartedAt != nil && r.FinishedAt != nil {
			duration = int64(r.FinishedAt.Sub(*r.StartedAt).Round(time.Second) / time.Second)
		}
		if r.FinishedAt != nil {
			completed = r.FinishedAt.UTC().Format(time.RFC3339)
		}
		errorClass := ""
		if r.ErrorClass != nil {
			errorClass = *r.ErrorClass
		}
		spec.Target = &audit.Target{Type: "backup_run", ID: r.ID.String(), Display: r.Kind}
		spec.Params = map[string]any{"run_id": r.ID.String(), "kind": r.Kind, "label": r.Label, "bytes": r.Bytes,
			"duration_s": duration, "completed_at": completed, "targets_ok": ok, "targets_failed": failed,
			"error_class": errorClass}
		id := r.ID
		write := func(ctx context.Context, q *pgstore.Queries, _ app.Recorder) error {
			n, err := q.BackupRoleSetRunMirrored(ctx, pgstore.BackupRoleSetRunMirroredParams{ID: id, Targets: targets})
			if err != nil {
				return err
			}
			if n != 1 {
				return fmt.Errorf("backup run %s is mirrored already", id)
			}
			return nil
		}
		if succeeded {
			err = s.runner.RunTx(ctx, app.ScopePlatform, spec, write)
		} else {
			err = s.runner.RunTxRefusal(ctx, app.ScopePlatform, spec, errRunFailed, write)
			if err == errRunFailed {
				err = nil
			}
		}
		if err != nil {
			// The runner recorded this attempt's failure event: the run is done, or the next round would record a
			// second event for it (decisions-alpha9 item 79: exactly one per run).
			if merr := s.pool.InBackup(ctx, func(ctx context.Context, q *pgstore.Queries) error {
				_, err := q.BackupRoleSetRunMirrored(ctx, pgstore.BackupRoleSetRunMirroredParams{ID: id, Targets: targets})
				return err
			}); merr != nil {
				err = errors.Join(err, merr)
			}
			return err
		}
	}
	return nil
}

// mirrorRunsTimeout bounds phase 2 of a round, which runs on even when the role shuts down.
const mirrorRunsTimeout = 2 * time.Minute

// errRunFailed is the refusal that records a failed run's event with outcome failure; the error class is a param.
var errRunFailed = fmt.Errorf("backup run failed")

func (s *pgStore) InstallationID(ctx context.Context) (string, error) {
	id, err := s.pool.SystemIdentifier(ctx)
	if err != nil {
		return "", err
	}
	return InstallationID(id), nil
}

// InstallationID derives a backup set's installation_id from PostgreSQL's system identifier: stable for the cluster,
// kept by a pgBackRest restore, new for a fresh installation.
func InstallationID(systemIdentifier int64) string {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("urn:paddock:postgres-system-identifier:"+
		strconv.FormatInt(systemIdentifier, 10))).String()
}

func (s *pgStore) SchemaVersion(ctx context.Context) (int, error) {
	var v int64
	err := s.platform.InPlatform(SystemContext(ctx), func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		v, err = q.UpgradeCheckSchemaVersion(ctx)
		return err
	})
	return int(v), err
}

func (s *pgStore) BundleSeqHighWater(ctx context.Context) (int64, error) {
	v, err := s.pool.BundleSeqHighWater(ctx)
	if err != nil {
		return 0, fmt.Errorf("read the bundle sequence high-water: %w", err)
	}
	return v, nil
}

// SystemContext carries the backup role's system principal.
func SystemContext(ctx context.Context) context.Context {
	return principalWith(ctx)
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nonNilTargets(t []backupset.RunTarget) []backupset.RunTarget {
	if t == nil {
		return []backupset.RunTarget{}
	}
	return t
}
