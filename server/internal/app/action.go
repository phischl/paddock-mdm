// Package app holds the use cases. Every privileged action runs through ActionRunner, which records exactly one
// audit event per attempt — success, failure or denial (architecture §14.3, plan M0 §6.5).
package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/devicecommand"
	"github.com/phischl/paddock-mdm/server/internal/domain/revocation"
	"github.com/phischl/paddock-mdm/server/internal/domain/statechange"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// ErrForbidden is returned when the principal's role is not allowed; the attempt is recorded as denied.
var ErrForbidden = problem.Forbidden

// Scope selects the database role of an action.
type Scope int

const (
	ScopeOrg      Scope = iota // OrgPool.InOrg
	ScopePlatform              // PlatformPool.InPlatform
)

// ActionSpec describes one privileged action.
type ActionSpec struct {
	Code         audit.Code
	AllowedRoles []principal.Role // empty = any authenticated admin
	Target       *audit.Target    // MAY be completed by the callback via rec.SetTarget
	Params       map[string]any   // MUST NOT contain secrets
	// Actor overrides the actor derived from the principal (rejected logins record an anonymous actor).
	Actor *audit.Actor
	// RequiresStepUp refuses the action (denied, step_up_required) unless the administrator completed a step-up
	// within StepUpValidity (plan M4a decision 7).
	RequiresStepUp bool
}

// StepUpValidity is how long a step-up authentication satisfies RequiresStepUp (plan M4a decision 6).
const StepUpValidity = 300 * time.Second

// Recorder lets the use case complete the audit event.
type Recorder interface {
	SetTarget(t audit.Target)
	SetParam(key string, value any)
	SetOrganization(id uuid.UUID) // platform actions only, e.g. organization.created
	// StateChanged queues a state change for the compiler; it is written to the outbox in the same transaction,
	// only when the action succeeds (plan M2a §6.4). In RunExternal, changes queued by prepare are written with the
	// started action (before the external call), changes queued by finalize only on success.
	StateChanged(scope string, id uuid.UUID)
	// PriorityStateChanged is StateChanged on the compiler's priority lane (user lock and unlock, login suspension,
	// architecture §9.5).
	PriorityStateChanged(scope string, id uuid.UUID)
	// CommandIssued queues the command.issued message of a device command inserted by the action; like a state
	// change it is written to the outbox only when the action succeeds (plan M4a decision 2).
	CommandIssued(id uuid.UUID)
	// RevocationApproved queues the revocation.approved message of an approved revocation request for the
	// revocation-issuer; like a state change it is written to the outbox only when the action succeeds (plan M4c
	// decision 7).
	RevocationApproved(id uuid.UUID)
	// RequireStepUp is RequiresStepUp for actions that need a step-up only for some inputs (e.g. assigning a full
	// profile): it returns problem.StepUpRequired, recorded as denied, unless the step-up is fresh.
	RequireStepUp() error
}

// CorrelationIDFunc extracts the request ID from ctx (set by the httpx middleware).
type CorrelationIDFunc func(ctx context.Context) string

// ActionRunner records privileged actions.
type ActionRunner struct {
	org           *db.OrgPool
	platform      *db.PlatformPool
	correlationID CorrelationIDFunc
	now           func() time.Time
	// externalDelay is the development-only test hook PADDOCK_TEST_EXTERNAL_DELAY (plan M0 §8, A3).
	externalDelay time.Duration
	stepUpWindow  time.Duration
}

// RunnerOption configures an ActionRunner.
type RunnerOption func(*ActionRunner)

// WithExternalDelay delays every external call (development-only test hook; callers must check PADDOCK_ENV).
func WithExternalDelay(d time.Duration) RunnerOption {
	return func(r *ActionRunner) { r.externalDelay = d }
}

// WithStepUpWindow replaces StepUpValidity (development-only PADDOCK_STEPUP_WINDOW; callers must check
// PADDOCK_ENV).
func WithStepUpWindow(d time.Duration) RunnerOption {
	return func(r *ActionRunner) { r.stepUpWindow = d }
}

// StepUpWindow is how long a step-up satisfies RequiresStepUp.
func (r *ActionRunner) StepUpWindow() time.Duration { return r.stepUpWindow }

// WithClock replaces time.Now (tests).
func WithClock(now func() time.Time) RunnerOption { return func(r *ActionRunner) { r.now = now } }

// NewActionRunner creates a runner.
func NewActionRunner(org *db.OrgPool, platform *db.PlatformPool, correlationID CorrelationIDFunc, opts ...RunnerOption) *ActionRunner {
	r := &ActionRunner{org: org, platform: platform, correlationID: correlationID, now: time.Now, stepUpWindow: StepUpValidity}
	for _, o := range opts {
		o(r)
	}
	return r
}

type recorder struct {
	id         uuid.UUID
	code       audit.Code
	org        uuid.UUID
	actor      audit.Actor
	target     *audit.Target
	params     map[string]any
	correlated string
	startedAt  time.Time
	changes    []statechange.Event
	commands   []uuid.UUID
	approved   []uuid.UUID
	stepUp     func() error
}

func (r *recorder) SetTarget(t audit.Target) { r.target = &t }

func (r *recorder) SetParam(key string, value any) {
	mustBeSafeParam(key)
	r.params[key] = value
}

func (r *recorder) SetOrganization(id uuid.UUID) { r.org = id }

func (r *recorder) StateChanged(scope string, id uuid.UUID) {
	r.changes = append(r.changes, statechange.Event{OrganizationID: r.org, Scope: scope, ID: id})
}

func (r *recorder) PriorityStateChanged(scope string, id uuid.UUID) {
	r.changes = append(r.changes, statechange.Event{OrganizationID: r.org, Scope: scope, ID: id, Priority: true})
}

func (r *recorder) CommandIssued(id uuid.UUID) { r.commands = append(r.commands, id) }

func (r *recorder) RevocationApproved(id uuid.UUID) { r.approved = append(r.approved, id) }

func (r *recorder) RequireStepUp() error { return r.stepUp() }

var secretParamWords = []string{"password", "secret", "token"}

// mustBeSafeParam panics on parameter keys that look like secrets: audit events are immutable evidence and must
// never carry secrets. This is a programming error, caught by tests.
func mustBeSafeParam(key string) {
	k := strings.ToLower(key)
	for _, w := range secretParamWords {
		if strings.Contains(k, w) {
			panic(fmt.Sprintf("app: audit param %q looks like a secret", key))
		}
	}
}

func (r *ActionRunner) newRecorder(ctx context.Context, p principal.Principal, scope Scope, spec ActionSpec) *recorder {
	if !spec.Code.Registered() {
		panic(fmt.Sprintf("app: audit code %q is not in the registry", spec.Code))
	}
	params := make(map[string]any, len(spec.Params))
	for k, v := range spec.Params {
		mustBeSafeParam(k)
		params[k] = v
	}
	rec := &recorder{
		id:         uuid.Must(uuid.NewV7()),
		code:       spec.Code,
		params:     params,
		correlated: r.correlationID(ctx),
		startedAt:  audit.Timestamp(r.now()),
	}
	if spec.Target != nil {
		t := *spec.Target
		rec.target = &t
	}
	if scope == ScopeOrg {
		rec.org = p.OrganizationID
	} else {
		rec.org = audit.PlatformOrganizationID
	}
	if spec.Actor != nil {
		rec.actor = *spec.Actor
	} else {
		rec.actor = actorOf(p)
	}
	rec.stepUp = func() error {
		if err := r.checkStepUp(p); err != nil {
			return err
		}
		rec.actor.StepUp = true
		return nil
	}
	return rec
}

// checkStepUp reports problem.StepUpRequired unless an administrator's step-up is at most the step-up window old.
// System principals never step up.
func (r *ActionRunner) checkStepUp(p principal.Principal) error {
	if p.Kind == principal.KindSystem {
		return nil
	}
	age := r.now().Sub(p.StepUpAt)
	if p.StepUpAt.IsZero() || age > r.stepUpWindow || age < -time.Minute {
		return problem.StepUpRequired.WithDetail("this action needs a step-up authentication within the last 5 minutes")
	}
	return nil
}

func actorOf(p principal.Principal) audit.Actor {
	a := audit.Actor{Display: p.Display, IP: p.IP}
	switch p.Kind {
	case principal.KindAdmin:
		a.Type = audit.ActorAdmin
	case principal.KindPlatformAdmin:
		a.Type = audit.ActorPlatformAdmin
	default:
		a.Type = audit.ActorSystem
	}
	if p.ID != uuid.Nil {
		a.ID = p.ID.String()
	}
	return a
}

// authorize checks the principal against the scope and the allowed roles, then the step-up of RequiresStepUp.
func (r *ActionRunner) authorize(p principal.Principal, scope Scope, spec ActionSpec, rec *recorder) error {
	if err := authorizeRole(p, scope, spec); err != nil {
		return err
	}
	if spec.RequiresStepUp {
		return rec.stepUp()
	}
	return nil
}

// authorizeRole checks the principal against the scope and the allowed roles.
func authorizeRole(p principal.Principal, scope Scope, spec ActionSpec) error {
	if scope == ScopeOrg && p.OrganizationID == uuid.Nil {
		return problem.NoOrganization
	}
	if scope == ScopePlatform && p.Kind != principal.KindPlatformAdmin && p.Kind != principal.KindSystem {
		return ErrForbidden
	}
	if len(spec.AllowedRoles) > 0 && p.Kind != principal.KindSystem && !slices.Contains(spec.AllowedRoles, p.Role) {
		return ErrForbidden
	}
	return nil
}

// OutcomeOf maps an error to the audit outcome and error code (plan M0 §6.5).
func OutcomeOf(err error) (audit.Outcome, string) {
	if err == nil {
		return audit.OutcomeSuccess, ""
	}
	p := problem.From(err)
	if errors.Is(err, problem.Forbidden) || errors.Is(err, problem.NoOrganization) || errors.Is(err, problem.CSRFMissing) ||
		errors.Is(err, problem.StepUpRequired) || errors.Is(err, problem.RevocationDisabled) ||
		errors.Is(err, problem.RevocationFrozen) || errors.Is(err, problem.RevocationRejected) {
		return audit.OutcomeDenied, p.Code
	}
	return audit.OutcomeFailure, p.Code
}

// RunTx runs a pure database action. fn runs inside the scope's transaction.
//   - authorization check first; on failure: record outcome=denied, return the error.
//   - success: in the SAME transaction insert action(status=finished, outcome=success) + outbox row; commit.
//   - fn error or commit error: rollback, then in a NEW transaction insert action(finished, outcome=failure|denied,
//     error_code=<problem code>) + outbox row. The original error is returned.
func (r *ActionRunner) RunTx(ctx context.Context, scope Scope, spec ActionSpec,
	fn func(ctx context.Context, q *pgstore.Queries, rec Recorder) error) error {
	p, ok := principal.From(ctx)
	if !ok {
		return problem.Unauthenticated
	}
	rec := r.newRecorder(ctx, p, scope, spec)
	if err := r.authorize(p, scope, spec, rec); err != nil {
		r.recordFinal(ctx, p, scope, rec, err)
		return err
	}
	defer r.recordPanic(ctx, p, scope, rec)
	err := r.inScope(ctx, p, scope, func(ctx context.Context, q *pgstore.Queries) error {
		if err := fn(ctx, q, rec); err != nil {
			return err
		}
		return r.insertFinished(ctx, q, rec, nil)
	})
	if err != nil {
		r.recordFinal(ctx, p, scope, rec, err)
		return err
	}
	return nil
}

// RunTxRefusal records an action that was refused, with the outcome of refusal (denied or failure), in the same
// transaction as the changes fn makes because of the refusal, e.g. a revocation request the issuer rejects together
// with its rejected state (plan M4c decision 8). fn's own error rolls everything back and is recorded instead.
func (r *ActionRunner) RunTxRefusal(ctx context.Context, scope Scope, spec ActionSpec, refusal error,
	fn func(ctx context.Context, q *pgstore.Queries, rec Recorder) error) error {
	p, ok := principal.From(ctx)
	if !ok {
		return problem.Unauthenticated
	}
	rec := r.newRecorder(ctx, p, scope, spec)
	if err := r.authorize(p, scope, spec, rec); err != nil {
		r.recordFinal(ctx, p, scope, rec, err)
		return err
	}
	defer r.recordPanic(ctx, p, scope, rec)
	err := r.inScope(ctx, p, scope, func(ctx context.Context, q *pgstore.Queries) error {
		if err := fn(ctx, q, rec); err != nil {
			return err
		}
		return r.insertFinished(ctx, q, rec, refusal)
	})
	if err != nil {
		r.recordFinal(ctx, p, scope, rec, err)
		return err
	}
	return refusal
}

// RecordOnce records a successful event reported by a device exactly once per natural key: claim runs first in the
// same transaction and inserts the key with ON CONFLICT DO NOTHING; when the key existed (a redelivered message)
// nothing is recorded and RecordOnce returns false.
func (r *ActionRunner) RecordOnce(ctx context.Context, spec ActionSpec,
	claim func(ctx context.Context, q *pgstore.Queries) (bool, error)) (bool, error) {
	p, ok := principal.From(ctx)
	if !ok || p.Kind != principal.KindSystem {
		return false, problem.Unauthenticated
	}
	rec := r.newRecorder(ctx, p, ScopeOrg, spec)
	recorded := false
	err := r.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		fresh, err := claim(ctx, q)
		if err != nil || !fresh {
			return err
		}
		recorded = true
		return r.insertFinished(ctx, q, rec, nil)
	})
	if err != nil {
		return false, err
	}
	return recorded, nil
}

// RecordRejected records a privileged action that was rejected before its use case ran (malformed request, missing
// CSRF header): exactly one event, denied when the principal may not perform the action at all, otherwise with the
// rejection's outcome. It returns the error to send to the client.
func (r *ActionRunner) RecordRejected(ctx context.Context, scope Scope, spec ActionSpec, rejection error) error {
	return r.RunTx(ctx, scope, spec, func(context.Context, *pgstore.Queries, Recorder) error { return rejection })
}

// recordPanic records a panicking use case as failure (error_code internal) and re-panics for the HTTP recovery
// middleware, so even a crash inside a request leaves exactly one event.
func (r *ActionRunner) recordPanic(ctx context.Context, p principal.Principal, scope Scope, rec *recorder) {
	if v := recover(); v != nil {
		r.recordFinal(ctx, p, scope, rec, fmt.Errorf("panic: %v", v))
		panic(v)
	}
}

// RunExternal runs an action with side effects outside PostgreSQL.
//
//	tx1: prepare(ctx, q, rec) + insert action(status=started) + the state changes prepare queued; commit.
//	external(ctx) runs outside any transaction.
//	tx2: finalize(ctx, q, rec, externalErr) + update action to finished with outcome + outbox row; commit.
//
// A crash between tx1 and tx2 leaves a started action that the reaper finalizes as outcome=unknown.
func (r *ActionRunner) RunExternal(ctx context.Context, scope Scope, spec ActionSpec,
	prepare func(ctx context.Context, q *pgstore.Queries, rec Recorder) error,
	external func(ctx context.Context) error,
	finalize func(ctx context.Context, q *pgstore.Queries, rec Recorder, externalErr error) error) error {
	p, ok := principal.From(ctx)
	if !ok {
		return problem.Unauthenticated
	}
	rec := r.newRecorder(ctx, p, scope, spec)
	if err := r.authorize(p, scope, spec, rec); err != nil {
		r.recordFinal(ctx, p, scope, rec, err)
		return err
	}

	err := func() error {
		defer r.recordPanic(ctx, p, scope, rec)
		return r.inScope(ctx, p, scope, func(ctx context.Context, q *pgstore.Queries) error {
			if err := prepare(ctx, q, rec); err != nil {
				return err
			}
			return r.insertStarted(ctx, q, rec)
		})
	}()
	if err != nil {
		r.recordFinal(ctx, p, scope, rec, err)
		return err
	}

	if r.externalDelay > 0 {
		slog.WarnContext(ctx, "development test hook: delaying external call", "delay", r.externalDelay, "action_id", rec.id)
		select {
		case <-time.After(r.externalDelay):
		case <-ctx.Done():
		}
	}
	externalErr := external(ctx)

	// The outcome must be recorded even if the request was canceled meanwhile.
	finCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	var finalizeErr error
	err = r.inScope(finCtx, p, scope, func(ctx context.Context, q *pgstore.Queries) error {
		if finalizeErr = finalize(ctx, q, rec, externalErr); finalizeErr != nil {
			return finalizeErr
		}
		return r.finishStarted(ctx, q, rec, externalErr)
	})
	if err != nil {
		// tx2 failed: finalize the action as failure in a new transaction; if that fails too, the reaper does it.
		cause := err
		if externalErr != nil {
			cause = externalErr
		}
		if ferr := r.inScope(finCtx, p, scope, func(ctx context.Context, q *pgstore.Queries) error {
			return r.finishStarted(ctx, q, rec, cause)
		}); ferr != nil {
			slog.ErrorContext(ctx, "audit: could not finalize action; the reaper will record it as unknown",
				"action_id", rec.id, "code", rec.code, "error", ferr)
		}
		if externalErr != nil {
			return externalErr
		}
		return err
	}
	return externalErr
}

func (r *ActionRunner) inScope(ctx context.Context, p principal.Principal, scope Scope,
	fn func(ctx context.Context, q *pgstore.Queries) error) error {
	if scope == ScopeOrg && p.OrganizationID != uuid.Nil {
		return r.org.InOrg(ctx, fn)
	}
	return r.platform.InPlatform(ctx, fn)
}

// recordFinal writes action(finished, failure|denied) + outbox in a new transaction after a failed attempt.
func (r *ActionRunner) recordFinal(ctx context.Context, p principal.Principal, scope Scope, rec *recorder, cause error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	// Denials of organization actions by principals without an organization go to the platform pseudo-organization.
	if scope == ScopeOrg && p.OrganizationID == uuid.Nil {
		rec.org = audit.PlatformOrganizationID
	}
	// An organization principal may not use the platform scope; its denied platform action is recorded in its own
	// organization, where its auditors can see it.
	if scope == ScopePlatform && p.Kind == principal.KindAdmin && p.OrganizationID != uuid.Nil {
		scope = ScopeOrg
		rec.org = p.OrganizationID
	}
	err := r.inScope(ctx, p, scope, func(ctx context.Context, q *pgstore.Queries) error {
		return r.insertFinished(ctx, q, rec, cause)
	})
	if err != nil {
		slog.ErrorContext(ctx, "audit: could not record failed action", "action_id", rec.id, "code", rec.code,
			"cause", cause, "error", err)
	}
}

// insertStarted records the started action and writes the state changes prepare queued: they must not wait for the
// external call (e.g. a lock reaches the devices even when Authentik is down, architecture §9.5).
func (r *ActionRunner) insertStarted(ctx context.Context, q *pgstore.Queries, rec *recorder) error {
	actor, target, params, err := encodeParts(rec)
	if err != nil {
		return err
	}
	if err := q.InsertAction(ctx, pgstore.InsertActionParams{
		ID: rec.id, OrganizationID: rec.org, Code: string(rec.code), Status: "started",
		Actor: actor, Target: target, Params: params, CorrelationID: rec.correlated, StartedAt: rec.startedAt,
	}); err != nil {
		return err
	}
	if err := insertStateChanges(ctx, q, rec); err != nil {
		return err
	}
	rec.changes, rec.commands, rec.approved = nil, nil, nil
	return nil
}

func (r *ActionRunner) insertFinished(ctx context.Context, q *pgstore.Queries, rec *recorder, cause error) error {
	outcome, code := OutcomeOf(cause)
	finished := audit.Timestamp(r.now())
	actor, target, params, err := encodeParts(rec)
	if err != nil {
		return err
	}
	o := string(outcome)
	if err := q.InsertAction(ctx, pgstore.InsertActionParams{
		ID: rec.id, OrganizationID: rec.org, Code: string(rec.code), Status: "finished", Outcome: &o,
		Actor: actor, Target: target, Params: params, ErrorCode: nonEmpty(code), CorrelationID: rec.correlated,
		StartedAt: rec.startedAt, FinishedAt: &finished,
	}); err != nil {
		return err
	}
	if outcome == audit.OutcomeSuccess {
		if err := insertStateChanges(ctx, q, rec); err != nil {
			return err
		}
	}
	return insertOutbox(ctx, q, rec, outcome, code, finished)
}

// insertStateChanges writes the queued state changes, command.issued and revocation.approved messages of a
// successful action to the outbox.
func insertStateChanges(ctx context.Context, q *pgstore.Queries, rec *recorder) error {
	for _, ev := range rec.changes {
		payload, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		if err := q.InsertOutbox(ctx, pgstore.InsertOutboxParams{
			OrganizationID: ev.OrganizationID, Subject: statechange.Subject(ev),
			MsgID: uuid.Must(uuid.NewV7()).String(), Payload: payload,
		}); err != nil {
			return err
		}
	}
	for _, id := range rec.commands {
		payload, err := json.Marshal(devicecommand.Issued{OrganizationID: rec.org, CommandID: id})
		if err != nil {
			return err
		}
		if err := q.InsertOutbox(ctx, pgstore.InsertOutboxParams{
			OrganizationID: rec.org, Subject: devicecommand.Subject(rec.org), MsgID: id.String(), Payload: payload,
		}); err != nil {
			return err
		}
	}
	for _, id := range rec.approved {
		payload, err := json.Marshal(revocation.Approved{OrganizationID: rec.org, RequestID: id})
		if err != nil {
			return err
		}
		if err := q.InsertOutbox(ctx, pgstore.InsertOutboxParams{
			OrganizationID: rec.org, Subject: revocation.Subject(rec.org), MsgID: "revocation:" + id.String(), Payload: payload,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (r *ActionRunner) finishStarted(ctx context.Context, q *pgstore.Queries, rec *recorder, cause error) error {
	outcome, code := OutcomeOf(cause)
	finished := audit.Timestamp(r.now())
	_, target, params, err := encodeParts(rec)
	if err != nil {
		return err
	}
	o := string(outcome)
	n, err := q.FinishAction(ctx, pgstore.FinishActionParams{
		ID: rec.id, Outcome: &o, ErrorCode: nonEmpty(code), Target: target, Params: params,
		OrganizationID: rec.org, FinishedAt: &finished,
	})
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("app: action %s is not in state started", rec.id)
	}
	if outcome == audit.OutcomeSuccess {
		if err := insertStateChanges(ctx, q, rec); err != nil {
			return err
		}
	}
	return insertOutbox(ctx, q, rec, outcome, code, finished)
}

func insertOutbox(ctx context.Context, q *pgstore.Queries, rec *recorder, outcome audit.Outcome, errorCode string, at time.Time) error {
	ev := audit.Event{
		Schema: audit.Schema, EventID: rec.id, OrganizationID: rec.org, OccurredAt: at, Code: rec.code,
		Outcome: outcome, Actor: rec.actor, Target: rec.target, Source: audit.SourceForActor(rec.actor.Type),
		Params: maps.Clone(rec.params), ErrorCode: errorCode, CorrelationID: rec.correlated,
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	return q.InsertOutbox(ctx, pgstore.InsertOutboxParams{
		OrganizationID: rec.org, Subject: audit.Subject(rec.org, ev.Source), MsgID: rec.id.String(), Payload: payload,
	})
}

func encodeParts(rec *recorder) (actor, target, params json.RawMessage, err error) {
	if actor, err = json.Marshal(rec.actor); err != nil {
		return nil, nil, nil, err
	}
	if rec.target != nil {
		if target, err = json.Marshal(rec.target); err != nil {
			return nil, nil, nil, err
		}
	}
	if params, err = json.Marshal(rec.params); err != nil {
		return nil, nil, nil, err
	}
	return actor, target, params, nil
}

func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
