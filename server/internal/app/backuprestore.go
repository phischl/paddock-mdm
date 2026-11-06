package app

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Restore plans (plan M15 decisions 25–26): a platform administrator approves and cancels with a step-up; the host
// reports the run as a system principal through the backup role.
var (
	SpecRestorePlan    = ActionSpec{Code: audit.CodePlatformRestorePlanned, AllowedRoles: RolesPlatform, RequiresStepUp: true}
	SpecRestoreCancel  = ActionSpec{Code: audit.CodePlatformRestoreCancelled, AllowedRoles: RolesPlatform, RequiresStepUp: true}
	SpecRestoreAbandon = ActionSpec{Code: audit.CodePlatformRestoreAbandoned, AllowedRoles: RolesPlatform, RequiresStepUp: true}
	specRestoreStart   = ActionSpec{Code: audit.CodePlatformRestoreStarted}
	specRestoreDone    = ActionSpec{Code: audit.CodePlatformRestoreCompleted}
	specRestoreFailed  = ActionSpec{Code: audit.CodePlatformRestoreFailed}
)

// RestoreConfirmation is the word the administrator types to approve a restore plan; it is checked here, not only in
// the portal (ADR 0018).
const RestoreConfirmation = "restore"

// RestoreAbandonConfirmation is the word the administrator types to abandon a running plan (PDK-832).
const RestoreAbandonConfirmation = "abandon"

// Restore plan kinds, sources and states (plan M15 decisions 2 and 25).
const (
	RestoreKindPointInTime  = "point_in_time"
	RestoreKindComponents   = "components"
	RestoreKindFreshInstall = "fresh_install"

	RestoreSourceRepo   = "repo"
	RestoreSourceTarget = "target"
	RestoreSourceSet    = "set"

	RestoreStateApproved  = "approved"
	RestoreStateRunning   = "running"
	RestoreStateCompleted = "completed"
	RestoreStateFailed    = "failed"
	RestoreStateExpired   = "expired"
	RestoreStateAbandoned = "abandoned"
)

// RestoreComponents are what a plan restores, in the order of the restore (plan M15 decision 23).
var RestoreComponents = []string{"postgres", "openbao", "fleet", "escrow"}

// restoreComponentKinds are the backup kinds a component is restored from: PostgreSQL restores both stanzas.
var restoreComponentKinds = map[string][]string{
	"postgres": {"postgres", "authentik"}, "openbao": {"openbao"}, "fleet": {"fleet"}, "escrow": {"escrow"},
}

// reportedComponents are what a host report may name: the plan's components and the repository alone (plan M15,
// amendment 2026-11-05, A5), which needs no plan.
var reportedComponents = append(slices.Clone(RestoreComponents), "backup-repo")

// restoreAtSkew is how far a point in time may lie ahead of the server's clock: the portal's clock may run ahead.
const restoreAtSkew = time.Minute

// restoreOneOpenIdx is the unique index that admits one approved or running plan.
const restoreOneOpenIdx = "backup_restore_plan_one_open_idx"

// PlanInput is a restore plan as the administrator requests it. A nil SourceTargetID restores from the local backup
// repository, a nil At to the newest backups.
type PlanInput struct {
	Kind           string
	SourceTargetID *uuid.UUID
	At             *time.Time
	Components     []string
	Confirmation   string
}

// Plan is a restore plan. HostCommand is the command that executes it on the host.
type Plan struct {
	ID               uuid.UUID
	Kind             string
	Source           string
	SourceTargetID   *uuid.UUID
	SourceTargetName *string
	At               *time.Time
	Components       []string
	State            string
	CreatedBy        string
	CreatedAt        time.Time
	ExpiresAt        *time.Time
	StartedAt        *time.Time
	FinishedAt       *time.Time
	OutcomeDetail    *string
	HostCommand      string
}

// RestorePlanQuery selects one page of plans.
type RestorePlanQuery struct {
	Page   ListPage
	States []string
}

// BackupRestorePlans are the platform use cases of the restore plans.
type BackupRestorePlans struct {
	runner   *ActionRunner
	platform *db.PlatformPool
	now      func() time.Time
}

// NewBackupRestorePlans creates the use cases.
func NewBackupRestorePlans(runner *ActionRunner, platform *db.PlatformPool) *BackupRestorePlans {
	return &BackupRestorePlans{runner: runner, platform: platform, now: time.Now}
}

// Create approves a restore plan (audited: platform.restore_planned). The typed word must be restore (400
// invalid_request); only one plan may be approved or running (409 invalid_state); the source must hold a success of
// every chosen component at or before At (409 invalid_state naming the kind). The plan expires 24 hours after its
// approval.
func (p *BackupRestorePlans) Create(ctx context.Context, in PlanInput) (Plan, error) {
	var out Plan
	spec := SpecRestorePlan
	spec.Params = map[string]any{"at": rfc3339OrNil(in.At)}
	if in.Kind == RestoreKindPointInTime || in.Kind == RestoreKindComponents {
		spec.Params["kind"] = in.Kind
	}
	err := p.runner.RunTx(ctx, ScopePlatform, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		if in.Confirmation != RestoreConfirmation {
			return problem.InvalidRequest.WithDetail("confirmation must be the word restore")
		}
		components, err := p.validate(in)
		if err != nil {
			return err
		}
		rec.SetParam("components", components)
		source, target := RestoreSourceRepo, uuid.NullUUID{}
		if in.SourceTargetID != nil {
			source, target = RestoreSourceTarget, uuid.NullUUID{UUID: *in.SourceTargetID, Valid: true}
			rec.SetParam("source_target_id", in.SourceTargetID.String())
			if _, err := q.GetBackupTarget(ctx, *in.SourceTargetID); err != nil {
				if db.IsNoRows(err) {
					return problem.InvalidRequest.WithDetail("source_target_id names no backup target")
				}
				return err
			}
		}
		rec.SetParam("source", source)
		if err := q.ExpireLapsedBackupRestorePlans(ctx); err != nil {
			return err
		}
		if open, err := q.OpenBackupRestorePlan(ctx); err == nil {
			return problem.InvalidState.WithDetail(fmt.Sprintf("the restore plan %s is %s; cancel it or wait until it finished",
				open.ID, open.State))
		} else if !db.IsNoRows(err) {
			return err
		}
		if err := checkAvailable(ctx, q, target, in.At, components); err != nil {
			return err
		}
		id := uuid.Must(uuid.NewV7())
		rec.SetTarget(restorePlanAudit(id, in.Kind))
		rec.SetParam("plan_id", id.String())
		if err := q.InsertBackupRestorePlan(ctx, pgstore.InsertBackupRestorePlanParams{
			ID: id, Kind: in.Kind, SourceTargetID: target, Source: source, At: in.At, Components: components,
			CreatedBy: actorDisplay(ctx),
		}); err != nil {
			if db.IsUniqueViolation(err, restoreOneOpenIdx) {
				return problem.InvalidState.WithDetail("another restore plan is approved or running")
			}
			return err
		}
		out, err = getPlan(ctx, q, id)
		return err
	})
	return out, err
}

// validate checks the kind, the point in time and the components and returns the components in restore order. A
// point-in-time plan needs At.
func (p *BackupRestorePlans) validate(in PlanInput) ([]string, error) {
	switch in.Kind {
	case RestoreKindPointInTime:
		if in.At == nil {
			return nil, problem.InvalidRequest.WithDetail("at is required for a point_in_time plan")
		}
	case RestoreKindComponents:
		// A lost plan is re-inserted by the host report with its kind derived from --at (RestoreReports.finish).
		if in.At != nil {
			return nil, problem.InvalidRequest.WithDetail("at is allowed for a point_in_time plan only")
		}
	default:
		return nil, problem.InvalidRequest.WithDetail("kind must be point_in_time or components")
	}
	if in.At != nil && in.At.After(p.now().Add(restoreAtSkew)) {
		return nil, problem.InvalidRequest.WithDetail("at must not lie in the future")
	}
	return orderedComponents(in.Components, RestoreComponents)
}

// orderedComponents returns the distinct components in the order of allowed; an empty list or an unknown component
// is invalid_request.
func orderedComponents(in, allowed []string) ([]string, error) {
	if len(in) == 0 {
		return nil, problem.InvalidRequest.WithDetail("components must name at least one component")
	}
	for _, c := range in {
		if !slices.Contains(allowed, c) {
			return nil, problem.InvalidRequest.WithDetail("components may hold " + strings.Join(allowed, ", ") + " only")
		}
	}
	out := make([]string, 0, len(in))
	for _, c := range allowed {
		if slices.Contains(in, c) {
			out = append(out, c)
		}
	}
	return out, nil
}

// checkAvailable refuses a plan whose source lacks a successful backup of a chosen component's kind at or before at.
func checkAvailable(ctx context.Context, q *pgstore.Queries, target uuid.NullUUID, at *time.Time, components []string) error {
	kinds, err := q.BackupRestoreAvailableKinds(ctx, pgstore.BackupRestoreAvailableKindsParams{At: at, TargetID: target})
	if err != nil {
		return fmt.Errorf("backup restore available kinds: %w", err)
	}
	for _, c := range components {
		for _, k := range restoreComponentKinds[c] {
			if !slices.Contains(kinds, k) {
				when := "on"
				if at != nil {
					when = "at or before " + at.UTC().Format(time.RFC3339) + " on"
				}
				where := "the local backup repository"
				if target.Valid {
					where = "the backup target"
				}
				return problem.InvalidState.WithDetail(fmt.Sprintf("no successful %s backup %s %s", k, when, where))
			}
		}
	}
	return nil
}

// Get returns one plan; a missing one is not_found.
func (p *BackupRestorePlans) Get(ctx context.Context, id uuid.UUID) (Plan, error) {
	var out Plan
	if _, err := RequirePlatform(ctx); err != nil {
		return out, err
	}
	err := p.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		out, err = getPlan(ctx, q, id)
		return err
	})
	return out, err
}

// List returns one page of plans.
func (p *BackupRestorePlans) List(ctx context.Context, query RestorePlanQuery) (Listed[Plan], error) {
	var out Listed[Plan]
	if _, err := RequirePlatform(ctx); err != nil {
		return out, err
	}
	err := p.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		states := nilIfEmpty(query.States)
		n, err := q.CountBackupRestorePlans(ctx, pgstore.CountBackupRestorePlansParams{
			QPattern: query.Page.QPattern, States: states, CountLimit: countLimit,
		})
		if err != nil {
			return fmt.Errorf("count backup restore plans: %w", err)
		}
		out.Count = int(n)
		rows, err := q.ListBackupRestorePlans(ctx, pgstore.ListBackupRestorePlansParams{
			QPattern: query.Page.QPattern, States: states, Sort: query.Page.Sort, SkipRows: query.Page.Offset,
			MaxRows: query.Page.Limit,
		})
		if err != nil {
			return fmt.Errorf("list backup restore plans: %w", err)
		}
		out.Items = make([]Plan, len(rows))
		for i, r := range rows {
			out.Items[i] = toPlan(pgstore.GetBackupRestorePlanRow(r))
		}
		return nil
	})
	return out, err
}

// Cancel expires an approved plan (audited: platform.restore_cancelled); the host refuses it from then on. A plan that
// is not approved is invalid_state.
func (p *BackupRestorePlans) Cancel(ctx context.Context, id uuid.UUID) (Plan, error) {
	var out Plan
	err := p.runner.RunTx(ctx, ScopePlatform, SpecRestoreCancel, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		cur, err := q.LockBackupRestorePlan(ctx, id)
		if err != nil {
			return notFound(err)
		}
		recordPlan(rec, cur)
		rec.SetParam("kind", cur.Kind)
		if cur.State != RestoreStateApproved || cur.Lapsed {
			state := cur.State
			if cur.Lapsed {
				state = RestoreStateExpired
			}
			return problem.InvalidState.WithDetail("the restore plan is " + state + ", not approved")
		}
		if err := q.CancelBackupRestorePlan(ctx, id); err != nil {
			return err
		}
		out, err = getPlan(ctx, q, id)
		return err
	})
	return out, err
}

// Abandon marks a running plan as abandoned (audited: platform.restore_abandoned) when the host never reported its end,
// e.g. after a crash: only this frees the one open place for a new plan (PDK-832). The typed word must be abandon (400
// invalid_request); a plan that is not running is invalid_state. The host's later report for the plan is refused.
func (p *BackupRestorePlans) Abandon(ctx context.Context, id uuid.UUID, confirmation string) (Plan, error) {
	// The plan is named before RunTx, so a denied attempt or a wrong typed word still says which plan it was about.
	spec := SpecRestoreAbandon
	spec.Params = map[string]any{"plan_id": id.String()}
	spec.Target = new(restorePlanAudit(id, ""))
	var out Plan
	err := p.runner.RunTx(ctx, ScopePlatform, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		if confirmation != RestoreAbandonConfirmation {
			return problem.InvalidRequest.WithDetail("confirmation must be the word abandon")
		}
		cur, err := q.LockBackupRestorePlan(ctx, id)
		if err != nil {
			return notFound(err)
		}
		recordPlan(rec, cur)
		rec.SetParam("kind", cur.Kind)
		if cur.State != RestoreStateRunning {
			state := cur.State
			if cur.Lapsed {
				state = RestoreStateExpired
			}
			return problem.InvalidState.WithDetail("the restore plan is " + state + ", not running")
		}
		detail := "abandoned by " + actorDisplay(ctx)
		if err := q.AbandonBackupRestorePlan(ctx, pgstore.AbandonBackupRestorePlanParams{ID: id, OutcomeDetail: &detail}); err != nil {
			return err
		}
		out, err = getPlan(ctx, q, id)
		return err
	})
	return out, err
}

// RestoreReport is what the host reports about a restore run (paddock-server backup restore-report, plan M15
// decision 23 step 8).
type RestoreReport struct {
	// Outcome is running (before the first step, only with a plan), completed or failed.
	Outcome string
	// Operator is the login name of the operator on the host.
	Operator   string
	Source     string
	Components []string
	// PlanID is nil for a restore without a plan.
	PlanID *uuid.UUID
	At     *time.Time
	// Component names the failed step and Detail what happened, both only with outcome failed.
	Component string
	Detail    string
}

// RestoreReports are the host's side of the restore plans: it reads a plan and reports the run through the backup
// role's transactions (tx), which hold the UPDATE grant on backup_restore_plan (plan M15 §6.6).
type RestoreReports struct {
	runner *ActionRunner
	tx     func(ctx context.Context, fn func(ctx context.Context, q *pgstore.Queries) error) error
}

// NewRestoreReports creates the host's use cases; runner records into the same transactions (WithPlatformScope(tx)).
func NewRestoreReports(runner *ActionRunner, tx func(ctx context.Context, fn func(ctx context.Context, q *pgstore.Queries) error) error) *RestoreReports {
	return &RestoreReports{runner: runner, tx: tx}
}

// ErrRestorePlanNotExecutable marks a plan the host must not execute or report: missing, expired, running or
// finished.
var ErrRestorePlanNotExecutable = errors.New("the restore plan cannot be executed")

// operatorName is the operator's login name as restore.sh passes it.
var operatorName = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)

// stepName is a restore step as restore.sh names it.
var stepName = regexp.MustCompile(`^[a-z][a-z-]{0,31}$`)

// maxRestoreDetail bounds the detail of a failed run.
const maxRestoreDetail = 500

// OperatorContext carries the host operator as the system principal of the restore events.
func OperatorContext(ctx context.Context, operator string) context.Context {
	return principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: operator})
}

// Plan reads a plan for the host; an approved plan past its expiry reads as expired.
func (r *RestoreReports) Plan(ctx context.Context, id uuid.UUID) (Plan, error) {
	var out Plan
	err := r.tx(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		out, err = getPlan(ctx, q, id)
		return err
	})
	return out, err
}

// Report records a run. running moves an approved, unexpired plan to running (audited once per attempt, a refusal
// included: platform.restore_started). completed and failed finish the plan (audited: platform.restore_completed /
// platform.restore_failed) with the plan's own params. The plan may be approved as well as running, because a
// restored database holds the plan as it was at the backup, or not at all: then the plan is recorded again under its
// ID. Without a plan a row of kind fresh_install records the run.
func (r *RestoreReports) Report(ctx context.Context, in RestoreReport) (Plan, error) {
	if in.Outcome == RestoreStateRunning {
		return r.start(ctx, in)
	}
	in, detail, err := checkReport(in)
	if err != nil {
		return Plan{}, err
	}
	ctx = OperatorContext(ctx, in.Operator)
	switch in.Outcome {
	case RestoreStateCompleted, RestoreStateFailed:
		return r.finish(ctx, in, detail)
	default:
		return Plan{}, problem.InvalidRequest.WithDetail("outcome must be running, completed or failed")
	}
}

// checkReport validates the operator, the source, the components and the detail of a report and returns the report
// with its components in restore order, and the detail.
func checkReport(in RestoreReport) (RestoreReport, *string, error) {
	if !operatorName.MatchString(in.Operator) {
		return in, nil, problem.InvalidRequest.WithDetail("operator must be a login name of at most 64 characters")
	}
	if in.Source != RestoreSourceSet && in.Source != RestoreSourceRepo && in.Source != RestoreSourceTarget {
		return in, nil, problem.InvalidRequest.WithDetail("source must be set, repo or target")
	}
	components, err := orderedComponents(in.Components, reportedComponents)
	if err != nil {
		return in, nil, err
	}
	in.Components = components
	detail, err := restoreDetail(in)
	return in, detail, err
}

// restoreDetail is the outcome detail: "<step>: <text>" of a failed run, nil otherwise.
func restoreDetail(in RestoreReport) (*string, error) {
	if in.Component == "" && in.Detail == "" {
		return nil, nil
	}
	if in.Outcome != RestoreStateFailed {
		return nil, problem.InvalidRequest.WithDetail("component and detail belong to outcome failed")
	}
	if !stepName.MatchString(in.Component) {
		return nil, problem.InvalidRequest.WithDetail("component must name the failed step")
	}
	if len(in.Detail) > maxRestoreDetail || strings.ContainsFunc(in.Detail, unicode.IsControl) {
		return nil, problem.InvalidRequest.WithDetail(fmt.Sprintf("detail must hold at most %d characters and no control characters",
			maxRestoreDetail))
	}
	d := in.Component + ": " + in.Detail
	return &d, nil
}

// start moves an approved plan to running. From here the host stops the stack and overwrites data, so every attempt
// is recorded exactly once, a refusal included (M15 note of 2026-11-05).
func (r *RestoreReports) start(ctx context.Context, in RestoreReport) (Plan, error) {
	operator := in.Operator
	if !operatorName.MatchString(operator) {
		// A name restore.sh would never send is refused, so it must not become the actor of the event either.
		operator = "host"
	}
	spec := specRestoreStart
	spec.Params = map[string]any{"plan_id": ""}
	if in.PlanID != nil {
		spec.Params["plan_id"] = in.PlanID.String()
		spec.Target = new(restorePlanAudit(*in.PlanID, ""))
	}
	var out Plan
	err := r.runner.RunTx(OperatorContext(ctx, operator), ScopePlatform, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		if in.PlanID == nil {
			return problem.InvalidRequest.WithDetail("running needs a plan")
		}
		in, _, err := checkReport(in)
		if err != nil {
			return err
		}
		rec.SetParam("source", in.Source)
		rec.SetParam("components", in.Components)
		id := *in.PlanID
		cur, err := q.LockBackupRestorePlan(ctx, id)
		if err != nil {
			if db.IsNoRows(err) {
				return fmt.Errorf("%w: %w", ErrRestorePlanNotExecutable, problem.NotFound.WithDetail("no restore plan "+id.String()))
			}
			return err
		}
		recordStart(rec, cur)
		if cur.Lapsed {
			return notExecutable("the restore plan " + id.String() + " expired 24 hours after its approval")
		}
		if cur.State != RestoreStateApproved {
			return notExecutable("the restore plan " + id.String() + " is " + cur.State + ", not approved")
		}
		// ON DELETE SET NULL leaves a target plan without its target; restore.sh would read that as the local
		// repository, a source the administrator never approved (plan M15 decision 24).
		if cur.Source == RestoreSourceTarget && !cur.SourceTargetID.Valid {
			return notExecutable("the backup target of restore plan " + id.String() + " was deleted")
		}
		if err := q.BackupRoleStartRestorePlan(ctx, id); err != nil {
			return err
		}
		out, err = getPlan(ctx, q, id)
		return err
	})
	return out, err
}

// notExecutable is the refusal of a plan the host must not start: ErrRestorePlanNotExecutable for the CLI and
// invalid_state as the event's error code.
func notExecutable(detail string) error {
	return fmt.Errorf("%w: %w", ErrRestorePlanNotExecutable, problem.InvalidState.WithDetail(detail))
}

// recordStart puts the stored plan into the start event.
func recordStart(rec Recorder, cur pgstore.LockBackupRestorePlanRow) {
	rec.SetTarget(restorePlanAudit(cur.ID, cur.Kind))
	rec.SetParam("source", cur.Source)
	rec.SetParam("components", cur.Components)
	if cur.SourceTargetID.Valid {
		rec.SetParam("source_target_id", cur.SourceTargetID.UUID.String())
	}
}

func (r *RestoreReports) finish(ctx context.Context, in RestoreReport, detail *string) (Plan, error) {
	var out Plan
	spec, refusal := specRestoreDone, error(nil)
	if in.Outcome == RestoreStateFailed {
		spec, refusal = specRestoreFailed, errRestoreFailed
	}
	planID := ""
	if in.PlanID != nil {
		planID = in.PlanID.String()
	}
	spec.Params = map[string]any{"plan_id": planID, "source": in.Source, "at": rfc3339OrNil(in.At),
		"components": in.Components, "detail": deref(detail, "")}
	write := func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		id, kind := uuid.Must(uuid.NewV7()), RestoreKindFreshInstall
		if in.PlanID != nil {
			id, kind = *in.PlanID, RestoreKindComponents
			if in.At != nil {
				kind = RestoreKindPointInTime
			}
		}
		rec.SetTarget(restorePlanAudit(id, kind))
		cur, err := q.LockBackupRestorePlan(ctx, id)
		switch {
		case err == nil:
			recordPlan(rec, cur)
			rec.SetParam("plan_id", planID)
			if cur.StartedAt != nil {
				rec.SetParam("duration_s", int64(time.Since(*cur.StartedAt).Round(time.Second)/time.Second))
			}
			if cur.State == RestoreStateAbandoned {
				return problem.InvalidState.WithDetail("a platform administrator abandoned the restore plan")
			}
			if cur.State != RestoreStateApproved && cur.State != RestoreStateRunning {
				return problem.InvalidState.WithDetail("the restore plan is already " + cur.State)
			}
			err = q.BackupRoleFinishRestorePlan(ctx, pgstore.BackupRoleFinishRestorePlanParams{
				ID: id, State: in.Outcome, OutcomeDetail: detail})
		case db.IsNoRows(err):
			err = q.BackupRoleInsertFinishedRestorePlan(ctx, pgstore.BackupRoleInsertFinishedRestorePlanParams{
				ID: id, Kind: kind, Source: in.Source, At: in.At, Components: in.Components, State: in.Outcome,
				CreatedBy: in.Operator, OutcomeDetail: detail})
		}
		if err != nil {
			return err
		}
		out, err = getPlan(ctx, q, id)
		return err
	}
	var err error
	if refusal == nil {
		err = r.runner.RunTx(ctx, ScopePlatform, spec, write)
	} else if err = r.runner.RunTxRefusal(ctx, ScopePlatform, spec, refusal, write); errors.Is(err, refusal) {
		err = nil
	}
	return out, err
}

// errRestoreFailed is the refusal that records a failed run's event with outcome failure; the detail names the step.
var errRestoreFailed = errors.New("restore failed")

func getPlan(ctx context.Context, q *pgstore.Queries, id uuid.UUID) (Plan, error) {
	row, err := q.GetBackupRestorePlan(ctx, id)
	if err != nil {
		return Plan{}, notFound(err)
	}
	return toPlan(row), nil
}

func toPlan(r pgstore.GetBackupRestorePlanRow) Plan {
	p := Plan{
		ID: r.ID, Kind: r.Kind, Source: r.Source, SourceTargetName: r.SourceTargetName, At: r.At,
		Components: r.Components, State: r.State, CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt,
		StartedAt: r.StartedAt, FinishedAt: r.FinishedAt, OutcomeDetail: r.OutcomeDetail,
		HostCommand: "./paddock restore --plan " + r.ID.String(),
	}
	if r.SourceTargetID.Valid {
		id := r.SourceTargetID.UUID
		p.SourceTargetID = &id
	}
	if p.Components == nil {
		p.Components = []string{}
	}
	return p
}

func restorePlanAudit(id uuid.UUID, kind string) audit.Target {
	return audit.Target{Type: "backup_restore_plan", ID: id.String(), Display: kind}
}

// recordPlan puts the stored plan into the event: the params describe the plan, not the caller's input.
func recordPlan(rec Recorder, cur pgstore.LockBackupRestorePlanRow) {
	rec.SetTarget(restorePlanAudit(cur.ID, cur.Kind))
	rec.SetParam("plan_id", cur.ID.String())
	rec.SetParam("source", cur.Source)
	rec.SetParam("at", rfc3339OrNil(cur.At))
	rec.SetParam("components", cur.Components)
	if cur.SourceTargetID.Valid {
		rec.SetParam("source_target_id", cur.SourceTargetID.UUID.String())
	}
}

func rfc3339OrNil(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}
