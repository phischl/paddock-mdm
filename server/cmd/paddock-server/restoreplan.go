package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/config"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

// errPlanNotExecutable is the error (exit 1) of `backup plan <id>` for a plan the host must not execute (plan M15
// decision 24).
var errPlanNotExecutable = errors.New("restore plan not executable")

// hostPlan is a restore plan as `paddock-server backup plan <id>` prints it for restore.sh, which reads the fields
// with fixed patterns (no jq on the hosts): string values, null when absent.
type hostPlan struct {
	ID               string   `json:"id"`
	Kind             string   `json:"kind"`
	State            string   `json:"state"`
	ExpiresAt        *string  `json:"expires_at"`
	At               *string  `json:"at"`
	Source           string   `json:"source"`
	SourceTargetID   *string  `json:"source_target_id"`
	SourceTargetName *string  `json:"source_target_name"`
	Components       []string `json:"components"`
	CreatedBy        string   `json:"created_by"`
}

func toHostPlan(p app.Plan) hostPlan {
	out := hostPlan{ID: p.ID.String(), Kind: p.Kind, State: p.State, ExpiresAt: rfc3339Ptr(p.ExpiresAt),
		At: rfc3339Ptr(p.At), Source: p.Source, SourceTargetName: p.SourceTargetName, Components: p.Components,
		CreatedBy: p.CreatedBy}
	if p.SourceTargetID != nil {
		s := p.SourceTargetID.String()
		out.SourceTargetID = &s
	}
	return out
}

func rfc3339Ptr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format(time.RFC3339)
	return &s
}

// openRestoreReports opens the backup role's pool (role paddock_backup holds the UPDATE grant on backup_restore_plan,
// plan M15 §6.6) and the host's use cases that record through it.
func openRestoreReports(ctx context.Context, l *config.Loader) (*app.RestoreReports, func(), error) {
	dsn := l.SecretFile("PADDOCK_DB_BACKUP_URL_FILE")
	if err := l.Err(); err != nil {
		return nil, nil, err
	}
	pool, err := db.NewBackupPool(ctx, dsn, db.Options{ApplicationName: "paddock-restore-report", MaxConns: 2})
	if err != nil {
		return nil, nil, err
	}
	correlation := uuid.NewString()
	runner := app.NewActionRunner(nil, nil, func(context.Context) string { return correlation },
		app.WithPlatformScope(pool.InBackup))
	return app.NewRestoreReports(runner, pool.InBackup), pool.Close, nil
}

// backupPlan prints a restore plan as JSON and exits 1 unless it is approved and unexpired: restore.sh executes only
// such a plan.
func backupPlan(ctx context.Context, l *config.Loader, args []string, out io.Writer) error {
	if len(args) != 1 {
		return errUsage
	}
	id, err := uuid.Parse(args[0])
	if err != nil {
		return errUsage
	}
	reports, closePool, err := openRestoreReports(ctx, l)
	if err != nil {
		return err
	}
	defer closePool()
	p, err := reports.Plan(app.OperatorContext(ctx, "host"), id)
	if err != nil {
		return fmt.Errorf("restore plan %s: %w", id, err)
	}
	return printHostPlan(out, p)
}

// printHostPlan writes the plan and refuses one that is not approved.
func printHostPlan(out io.Writer, p app.Plan) error {
	if err := json.NewEncoder(out).Encode(toHostPlan(p)); err != nil {
		return err
	}
	if p.State != app.RestoreStateApproved {
		return fmt.Errorf("%w: the restore plan %s is %s, not approved", errPlanNotExecutable, p.ID, p.State)
	}
	// restore.sh reads a null source_target_id as the local repository; after ON DELETE SET NULL that would be a
	// source the administrator never approved (plan M15 decision 24).
	if p.Source == app.RestoreSourceTarget && p.SourceTargetID == nil {
		return fmt.Errorf("%w: the backup target of restore plan %s was deleted", errPlanNotExecutable, p.ID)
	}
	return nil
}

// parseRestoreReport reads the command line of `backup restore-report` (the contract restore.sh calls, plan M15
// decision 23 step 8).
func parseRestoreReport(args []string) (app.RestoreReport, error) {
	fs := flag.NewFlagSet("backup restore-report", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	outcome := fs.String("outcome", "", "")
	operator := fs.String("operator", "", "")
	source := fs.String("source", "", "")
	components := fs.String("components", "", "")
	plan := fs.String("plan", "", "")
	at := fs.String("at", "", "")
	component := fs.String("component", "", "")
	detail := fs.String("detail", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *outcome == "" || *operator == "" || *source == "" ||
		*components == "" {
		return app.RestoreReport{}, errUsage
	}
	in := app.RestoreReport{Outcome: *outcome, Operator: *operator, Source: *source,
		Components: strings.Split(*components, ","), Component: *component, Detail: *detail}
	if *plan != "" {
		id, err := uuid.Parse(*plan)
		if err != nil {
			return app.RestoreReport{}, errUsage
		}
		in.PlanID = &id
	}
	if *at != "" {
		t, err := time.Parse(time.RFC3339, *at)
		if err != nil {
			return app.RestoreReport{}, errUsage
		}
		in.At = &t
	}
	return in, nil
}

// backupRestoreReport records the host's restore run: running before the first step of a planned restore, completed
// or failed at its end.
func backupRestoreReport(ctx context.Context, l *config.Loader, args []string, out io.Writer) error {
	in, err := parseRestoreReport(args)
	if err != nil {
		return err
	}
	reports, closePool, err := openRestoreReports(ctx, l)
	if err != nil {
		return err
	}
	defer closePool()
	p, err := reports.Report(ctx, in)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "restore plan %s %s\n", p.ID, p.State)
	return err
}
