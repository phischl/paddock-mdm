package app

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// SpecBackupRunRequest is a backup now (plan M15 decision 14).
var SpecBackupRunRequest = ActionSpec{Code: audit.CodePlatformBackupRunRequested, AllowedRoles: RolesPlatform, RequiresStepUp: true}

// BackupRuns are the platform use cases of the backup runs and the backup overview (plan M15 decisions 13 and 14).
type BackupRuns struct {
	runner   *ActionRunner
	platform *db.PlatformPool
}

// NewBackupRuns creates the use cases.
func NewBackupRuns(runner *ActionRunner, platform *db.PlatformPool) *BackupRuns {
	return &BackupRuns{runner: runner, platform: platform}
}

// Run is one backup run of one kind. A requested run has no start, outcome or targets yet.
type Run struct {
	ID          uuid.UUID
	Kind        string
	Label       string
	State       string
	Outcome     *string
	RequestedBy *string
	StartedAt   *time.Time
	FinishedAt  *time.Time
	Bytes       int64
	ErrorClass  *string
	Targets     []backupset.RunTarget
	CreatedAt   time.Time
}

// BackupRunQuery selects one page of runs.
type BackupRunQuery struct {
	Page     ListPage
	Kinds    []string
	Outcomes []string
	TargetID *uuid.UUID
}

// Key is a backup key as every read shows it: never the ciphertext or the challenge (plan M15 decision 7).
type Key struct {
	KeyID       string
	Fingerprint string
	State       string
	CreatedAt   time.Time
	CreatedBy   string
	ConfirmedAt *time.Time
	ConfirmedBy *string
	RetiredAt   *time.Time
	Attempts    int
	Legacy      bool
}

// KeyStatus is the active key, the key waiting for its confirmation and the retired keys.
type KeyStatus struct {
	Active  *Key
	Pending *Key
	Retired []Key
}

// Repo is the local backup repository. The api cannot see the repository volume: the sizes stay nil until the backup
// role reports them, the stanzas show the last successful full backups the runs recorded.
type Repo struct {
	Path      *string
	BytesUsed *int64
	BytesFree *int64
	Stanzas   []Stanza
}

// Stanza is one pgBackRest stanza of the repository.
type Stanza struct {
	Name          string
	LastFullAt    *time.Time
	WALArchivedAt *time.Time
}

// BackupOverview is GET /api/platform/v1/backup (plan M15 decision 13).
type BackupOverview struct {
	Key      KeyStatus
	Schedule ScheduleView
	Targets  []Target
	Repo     Repo
	LastRuns []Run
}

// stanzaKinds maps the pgBackRest stanzas to the run kinds that back them up.
var stanzaKinds = []struct{ stanza, kind string }{{"paddock", "postgres"}, {"authentik", "authentik"}}

// Request requests a backup of kinds now (all kinds when empty; audited: platform.backup_run_requested). It inserts
// one requested run per kind, which the backup role runs in its next round; without a confirmed key no backup runs, so
// the request is refused (409 invalid_state).
func (r *BackupRuns) Request(ctx context.Context, kinds []string, label string) ([]Run, error) {
	var out []Run
	if len(kinds) == 0 {
		kinds = backupset.Kinds
	}
	kinds = uniqueKinds(kinds)
	spec := SpecBackupRunRequest
	spec.Target = &audit.Target{Type: "backup", ID: "platform"}
	spec.Params = map[string]any{}
	if backupset.ValidRunLabel(label) {
		spec.Params["label"] = label
	}
	err := r.runner.RunTx(ctx, ScopePlatform, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		for _, k := range kinds {
			if !backupset.ValidKind(k) {
				return problem.InvalidRequest.WithDetail("kinds may hold postgres, authentik, openbao, fleet and escrow only")
			}
		}
		// Only validated kinds reach the audit params: the caller's list is free text until here.
		rec.SetParam("kinds", kinds)
		if !backupset.ValidRunLabel(label) {
			return problem.InvalidRequest.WithDetail(fmt.Sprintf("label must hold at most %d characters and no control characters",
				backupset.MaxRunLabelChars))
		}
		if _, err := q.ActiveBackupKeyID(ctx); err != nil {
			if db.IsNoRows(err) {
				return problem.InvalidState.WithDetail("no backup key is confirmed: generate and confirm a key first")
			}
			return err
		}
		by := actorDisplay(ctx)
		out = make([]Run, 0, len(kinds))
		for _, k := range kinds {
			row, err := q.InsertBackupRun(ctx, pgstore.InsertBackupRunParams{
				ID: uuid.Must(uuid.NewV7()), Kind: k, Label: label, RequestedBy: &by,
			})
			if err != nil {
				return err
			}
			run, err := toRun(row)
			if err != nil {
				return err
			}
			out = append(out, run)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// uniqueKinds keeps the first occurrence of every kind; the use case validates them.
func uniqueKinds(kinds []string) []string {
	out := make([]string, 0, len(kinds))
	for _, k := range kinds {
		if !slices.Contains(out, k) {
			out = append(out, k)
		}
	}
	return out
}

// List returns one page of runs.
func (r *BackupRuns) List(ctx context.Context, query BackupRunQuery) (Listed[Run], error) {
	var out Listed[Run]
	if _, err := RequirePlatform(ctx); err != nil {
		return out, err
	}
	var target *string
	if query.TargetID != nil {
		s := query.TargetID.String()
		target = &s
	}
	err := r.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		kinds, outcomes := nilIfEmpty(query.Kinds), nilIfEmpty(query.Outcomes)
		n, err := q.CountBackupRuns(ctx, pgstore.CountBackupRunsParams{
			Kinds: kinds, Outcomes: outcomes, TargetID: target, CountLimit: countLimit,
		})
		if err != nil {
			return fmt.Errorf("count backup runs: %w", err)
		}
		out.Count = int(n)
		rows, err := q.ListBackupRuns(ctx, pgstore.ListBackupRunsParams{
			Kinds: kinds, Outcomes: outcomes, TargetID: target, Sort: query.Page.Sort,
			SkipRows: query.Page.Offset, MaxRows: query.Page.Limit,
		})
		if err != nil {
			return fmt.Errorf("list backup runs: %w", err)
		}
		out.Items, err = toRuns(rows)
		return err
	})
	return out, err
}

// Overview returns the key state, the schedule, every target, the repository and the newest run per kind.
func (r *BackupRuns) Overview(ctx context.Context) (BackupOverview, error) {
	var out BackupOverview
	if _, err := RequirePlatform(ctx); err != nil {
		return out, err
	}
	err := r.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		if out.Key, err = readKeyStatus(ctx, q); err != nil {
			return err
		}
		if out.Schedule, err = readSchedule(ctx, q); err != nil {
			return err
		}
		rows, err := q.AllBackupTargets(ctx)
		if err != nil {
			return fmt.Errorf("list backup targets: %w", err)
		}
		out.Targets = make([]Target, len(rows))
		for i, row := range rows {
			out.Targets[i] = toTarget(ctx, pgstore.GetBackupTargetRow(row))
		}
		if err := withTargetStatus(ctx, q, out.Targets); err != nil {
			return err
		}
		latest, err := q.LatestBackupRuns(ctx)
		if err != nil {
			return fmt.Errorf("latest backup runs: %w", err)
		}
		if out.LastRuns, err = toRuns(latest); err != nil {
			return err
		}
		succeeded, err := q.LastSucceededBackupRuns(ctx)
		if err != nil {
			return fmt.Errorf("last succeeded backup runs: %w", err)
		}
		out.Repo = repoOf(out.Key.Active, succeeded)
		return nil
	})
	return out, err
}

func repoOf(active *Key, succeeded []pgstore.BackupRun) Repo {
	repo := Repo{Stanzas: make([]Stanza, len(stanzaKinds))}
	if active != nil {
		path := backupset.RepoPath(active.KeyID)
		repo.Path = &path
	}
	for i, s := range stanzaKinds {
		repo.Stanzas[i].Name = s.stanza
		for _, run := range succeeded {
			if run.Kind == s.kind {
				repo.Stanzas[i].LastFullAt = run.FinishedAt
			}
		}
	}
	return repo
}

// readKeyStatus reads the key state without the ciphertext or the challenge.
func readKeyStatus(ctx context.Context, q *pgstore.Queries) (KeyStatus, error) {
	rows, err := q.ListBackupKeyStates(ctx)
	if err != nil {
		return KeyStatus{}, fmt.Errorf("list backup keys: %w", err)
	}
	out := KeyStatus{Retired: []Key{}}
	for _, r := range rows {
		k := Key{KeyID: r.KeyID, Fingerprint: r.Fingerprint, State: r.State, CreatedAt: r.CreatedAt,
			CreatedBy: r.CreatedBy, ConfirmedAt: r.ConfirmedAt, ConfirmedBy: r.ConfirmedBy, RetiredAt: r.RetiredAt,
			Attempts: int(r.Attempts), Legacy: r.Legacy}
		switch r.State {
		case "confirmed":
			out.Active = &k
		case "unconfirmed":
			out.Pending = &k
		default:
			out.Retired = append(out.Retired, k)
		}
	}
	return out, nil
}

func toRuns(rows []pgstore.BackupRun) ([]Run, error) {
	out := make([]Run, len(rows))
	for i, row := range rows {
		run, err := toRun(row)
		if err != nil {
			return nil, err
		}
		out[i] = run
	}
	return out, nil
}

func toRun(r pgstore.BackupRun) (Run, error) {
	targets, err := backupset.ParseRunTargets(r.Targets)
	if err != nil {
		return Run{}, err
	}
	return Run{ID: r.ID, Kind: r.Kind, Label: r.Label, State: r.State, Outcome: r.Outcome, RequestedBy: r.RequestedBy,
		StartedAt: r.StartedAt, FinishedAt: r.FinishedAt, Bytes: r.Bytes, ErrorClass: r.ErrorClass, Targets: targets,
		CreatedAt: r.CreatedAt}, nil
}
