package app

import (
	"context"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// SpecBackupScheduleChange is the change of the backup schedule (plan M15 decision 12).
var SpecBackupScheduleChange = ActionSpec{Code: audit.CodePlatformBackupScheduleChanged, AllowedRoles: RolesPlatform, RequiresStepUp: true}

// BackupSchedule are the platform use cases of the backup schedule and retention.
type BackupSchedule struct {
	runner   *ActionRunner
	platform *db.PlatformPool
}

// NewBackupSchedule creates the use cases.
func NewBackupSchedule(runner *ActionRunner, platform *db.PlatformPool) *BackupSchedule {
	return &BackupSchedule{runner: runner, platform: platform}
}

// ScheduleView is the schedule in force; UpdatedBy and UpdatedAt are nil while the defaults apply.
type ScheduleView struct {
	backupset.Schedule
	UpdatedBy *string
	UpdatedAt *time.Time
}

// Get returns the schedule; without a stored one the defaults of plan M15 decision 12.
func (s *BackupSchedule) Get(ctx context.Context) (ScheduleView, error) {
	var out ScheduleView
	if _, err := RequirePlatform(ctx); err != nil {
		return out, err
	}
	err := s.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		out, err = readSchedule(ctx, q)
		return err
	})
	return out, err
}

// Put replaces the schedule (audited: platform.backup_schedule_changed with every field).
func (s *BackupSchedule) Put(ctx context.Context, in backupset.Schedule) (ScheduleView, error) {
	var out ScheduleView
	spec := SpecBackupScheduleChange
	spec.Target = &audit.Target{Type: "setting", ID: "backup_schedule"}
	spec.Params = map[string]any{
		"full_interval_hours": in.FullIntervalHours, "openbao_interval_hours": in.OpenBaoIntervalHours,
		"fleet_interval_hours": in.FleetIntervalHours, "escrow_interval_hours": in.EscrowIntervalHours,
		"retention_full": in.RetentionFull, "openbao_keep_days": in.OpenBaoKeepDays, "fleet_keep_days": in.FleetKeepDays,
	}
	err := s.runner.RunTx(ctx, ScopePlatform, spec, func(ctx context.Context, q *pgstore.Queries, _ Recorder) error {
		if err := backupset.ValidateSchedule(in); err != nil {
			return problem.InvalidRequest.WithDetail(err.Error())
		}
		by := actorDisplay(ctx)
		//nolint:gosec // every field was validated against its bound (at most 365) above
		row, err := q.UpsertBackupSchedule(ctx, pgstore.UpsertBackupScheduleParams{
			FullIntervalHours: int32(in.FullIntervalHours), OpenbaoIntervalHours: int32(in.OpenBaoIntervalHours),
			FleetIntervalHours: int32(in.FleetIntervalHours), EscrowIntervalHours: int32(in.EscrowIntervalHours),
			RetentionFull: int32(in.RetentionFull), OpenbaoKeepDays: int32(in.OpenBaoKeepDays),
			FleetKeepDays: int32(in.FleetKeepDays), UpdatedBy: &by,
		})
		if err != nil {
			return err
		}
		out = toScheduleView(row)
		return nil
	})
	return out, err
}

func readSchedule(ctx context.Context, q *pgstore.Queries) (ScheduleView, error) {
	row, err := q.GetBackupSchedule(ctx)
	switch {
	case err == nil:
		return toScheduleView(row), nil
	case db.IsNoRows(err):
		return ScheduleView{Schedule: backupset.DefaultSchedule()}, nil
	}
	return ScheduleView{}, err
}

func toScheduleView(r pgstore.BackupSchedule) ScheduleView {
	at := r.UpdatedAt
	return ScheduleView{
		Schedule: backupset.Schedule{
			FullIntervalHours: int(r.FullIntervalHours), OpenBaoIntervalHours: int(r.OpenbaoIntervalHours),
			FleetIntervalHours: int(r.FleetIntervalHours), EscrowIntervalHours: int(r.EscrowIntervalHours),
			RetentionFull: int(r.RetentionFull), OpenBaoKeepDays: int(r.OpenbaoKeepDays), FleetKeepDays: int(r.FleetKeepDays),
		},
		UpdatedBy: r.UpdatedBy, UpdatedAt: &at,
	}
}
