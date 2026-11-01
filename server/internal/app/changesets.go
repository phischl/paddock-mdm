package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/configrollout"
	"github.com/phischl/paddock-mdm/server/internal/domain/declarative"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Rollout modes of a change set (plan M11 decision 4).
const (
	// RolloutImmediate: every device receives the change at once (rollouts disabled, or nothing rollout-able changed).
	RolloutImmediate = "immediate"
	// RolloutStaged: the change set started a configuration rollout.
	RolloutStaged = "staged"
	// RolloutUrgent: the change would have been staged, the caller opted out with a reason.
	RolloutUrgent = "urgent"
)

// WriteOptions are the urgent opt-out of a configuration write (plan M11 decision 26): Urgent skips the staged
// rollout and needs Reason (2–500 characters) and a fresh step-up. Reason without Urgent is stored as the change set's
// reason.
type WriteOptions struct {
	Urgent bool
	Reason string
}

// writeOptions returns the options of a use case whose options are optional.
func writeOptions(opts []WriteOptions) WriteOptions {
	if len(opts) == 0 {
		return WriteOptions{}
	}
	return opts[0]
}

// withChangeSet makes a configuration write record its change set (plan M11 decisions 18 and 19, ADR 0011): it reads
// the configuration before fn runs, and afterwards, in the same transaction, diffs it against the configuration fn
// left and stores one change set with the before-states of what changed. The diff covers whatever fn wrote, so a
// device group deletion lists every definition that went with the group. A write that changes nothing records none.
func withChangeSet(fn func(ctx context.Context, q *pgstore.Queries, rec Recorder) error) func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
	return withStagedChangeSet(WriteOptions{}, fn)
}

// withStagedChangeSet is withChangeSet for the writes that take the urgent opt-out (plan M11 decision 26). Both apply
// the conflict and staging rules of the organization's rollouts (decisions 25 and 29) to the recorded plan.
func withStagedChangeSet(opts WriteOptions, fn func(ctx context.Context, q *pgstore.Queries, rec Recorder) error) func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
	return func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		// The lock of the declarative apply: it keeps the before-state equal to what fn replaces, and it is taken first
		// everywhere, so the writers cannot deadlock on each other's later locks.
		if err := q.LockConfigApply(ctx); err != nil {
			return err
		}
		w, err := startRolloutWrite(ctx, q, rec, opts)
		if err != nil {
			return err
		}
		before, err := loadConfig(ctx, q)
		if err != nil {
			return fmt.Errorf("read the configuration before the change: %w", err)
		}
		if err := fn(ctx, q, rec); err != nil {
			return err
		}
		return recordChangeSet(ctx, q, rec, before, w)
	}
}

// recordChangeSet stores the change set of what turned before into the transaction's current configuration and names
// it in the audit event (param change_set_id). The action's own audit event is the only one: a change set is evidence
// next to it, not an action. Staged keys come from the recorded plan (plan M11 amendment R6.10), so a write that
// touches a key of the open rollout is refused here and rolled back with everything fn wrote.
func recordChangeSet(ctx context.Context, q *pgstore.Queries, rec Recorder, before configState, w rolloutWrite) error {
	after, err := loadConfig(ctx, q)
	if err != nil {
		return fmt.Errorf("read the configuration after the change: %w", err)
	}
	plan := declarative.Diff(before.doc, after.doc)
	if len(plan.Changes) == 0 {
		return nil
	}
	p, ok := principal.From(ctx)
	if !ok {
		return fmt.Errorf("record change set: no principal")
	}
	st, err := w.stage(ctx, q, plan, uuid.Nil)
	if err != nil {
		return err
	}
	id := uuid.Must(uuid.NewV7())
	if err := insertChangeSet(ctx, q, id, p, false, plan, plan.SectionsOf(), before, w.meta(st.mode)); err != nil {
		return err
	}
	rec.SetParam("change_set_id", id.String())
	return w.finish(ctx, q, rec, id, st)
}

// rolloutWrite carries the urgent opt-out and the rollout settings of one configuration write from its start to the
// recording of its change set.
type rolloutWrite struct {
	opts     WriteOptions
	settings RolloutConfig
}

// startRolloutWrite checks the urgent opt-out inside the action, so a refusal is audited (plan M11 decision 26): a
// reason of 2–500 characters, urgent only with a reason and only while rollouts are enabled, and a fresh step-up. rec
// is nil for dry runs: they change nothing, so they need no step-up and record nothing.
func startRolloutWrite(ctx context.Context, q *pgstore.Queries, rec Recorder, opts WriteOptions) (rolloutWrite, error) {
	if _, err := writeMeta(opts); err != nil {
		return rolloutWrite{}, err
	}
	if opts.Urgent && rec != nil {
		rec.SetParam("urgent_reason", opts.Reason)
	}
	settings, err := LoadRolloutSettings(ctx, q)
	if err != nil {
		return rolloutWrite{}, err
	}
	if opts.Urgent {
		if !settings.Enabled {
			return rolloutWrite{}, problem.InvalidRequest.WithDetail("rollouts are disabled for this organization")
		}
		if rec != nil {
			if err := rec.RequireStepUp(); err != nil {
				return rolloutWrite{}, err
			}
		}
	}
	return rolloutWrite{opts: opts, settings: settings}, nil
}

// staging is the rollout decision of one change set.
type staging struct {
	mode string
	// ends is the open rollout the write reverts the change set of; it ends with the write (plan M11 decision 21.3).
	ends *pgstore.GetOpenConfigRolloutRow
}

// stage applies the conflict rule (plan M11 decision 29) and the staging rule (decision 25) to plan. reverts is the
// change set a revert undoes (uuid.Nil otherwise): the revert of the open rollout's change set is always immediate,
// touches exactly the staged keys and ends the rollout.
func (w rolloutWrite) stage(ctx context.Context, q *pgstore.Queries, plan declarative.Plan, reverts uuid.UUID) (staging, error) {
	open, err := q.GetOpenConfigRollout(ctx)
	switch {
	case db.IsNoRows(err):
		return staging{mode: rolloutModeFor(w.settings.Settings, plan, w.opts.Urgent)}, nil
	case err != nil:
		return staging{}, err
	case reverts != uuid.Nil && reverts == open.ChangeSetID:
		return staging{mode: RolloutImmediate, ends: &open}, nil
	}
	staged, err := stagedKeysOf(open)
	if err != nil {
		return staging{}, err
	}
	if err := requireNotStaged(open.ID, staged, plan); err != nil {
		return staging{}, err
	}
	if w.opts.Urgent {
		return staging{mode: rolloutModeFor(w.settings.Settings, plan, true)}, nil
	}
	// One open rollout per organization (ADR 0033 E1, amendment 2026-11-01): a change of a section the rollout stages
	// would be a second staged change set and is refused as a whole, even after rollouts were switched off; a change of
	// only other sections is not a rollout and reaches every device.
	stagedSections := map[string]bool{}
	for section := range staged {
		stagedSections[configrollout.SectionGroup(section)] = true
	}
	if slices.ContainsFunc(plan.Changes, func(c declarative.Change) bool { return stagedSections[configrollout.SectionGroup(c.Section)] }) {
		return staging{}, problem.RolloutRunning.WithDetail("complete or revert rollout " + open.ID.String() + " first")
	}
	return staging{mode: RolloutImmediate}, nil
}

// stagedKeysOf returns the staged keys of the open rollout by section.
func stagedKeysOf(open pgstore.GetOpenConfigRolloutRow) (map[string]map[string]bool, error) {
	var plan declarative.Plan
	if err := json.Unmarshal(open.Plan, &plan); err != nil {
		return nil, fmt.Errorf("decode the plan of rollout %s: %w", open.ID, err)
	}
	return configrollout.StagedKeys(plan), nil
}

// meta returns the change set columns of the write's options and rollout mode.
func (w rolloutWrite) meta(mode string) changeSetMeta {
	m, _ := writeMeta(w.opts) // checked by startRolloutWrite
	m.Rollout = mode
	return m
}

// finish names the rollout mode in the audit event and starts the staged rollout (plan M11 decision 31) or ends the
// reverted one, in the transaction of change set id.
func (w rolloutWrite) finish(ctx context.Context, q *pgstore.Queries, rec Recorder, id uuid.UUID, st staging) error {
	rec.SetParam("rollout", st.mode)
	switch {
	case st.mode == RolloutStaged:
		p, _ := principal.From(ctx)
		waves := make([]int32, len(w.settings.Waves))
		for i, v := range w.settings.Waves {
			waves[i] = int32(v) //nolint:gosec // 1..100 (ValidateWaves)
		}
		canary := uuid.NullUUID{}
		if w.settings.CanaryDeviceGroupID != nil {
			canary = uuid.NullUUID{UUID: *w.settings.CanaryDeviceGroupID, Valid: true}
		}
		r, err := q.InsertConfigRollout(ctx, pgstore.InsertConfigRolloutParams{
			ID: uuid.Must(uuid.NewV7()), OrganizationID: p.OrganizationID, ChangeSetID: id, Waves: waves,
			MinWaveMinutes: int32(w.settings.MinWaveMinutes), FailureThresholdPercent: int32(w.settings.FailureThresholdPercent), //nolint:gosec // validated settings
			FailureThresholdMin: int32(w.settings.FailureThresholdMin), CanaryDeviceGroupID: canary, StartedBy: actorName(ctx), //nolint:gosec // validated settings
		})
		if err != nil {
			return fmt.Errorf("start the rollout of change set %s: %w", id, err)
		}
		rec.SetParam("rollout_id", r.ID.String())
	case st.ends != nil:
		reason := "reverted by change set " + id.String()
		n, err := q.EndConfigRolloutReverted(ctx, pgstore.EndConfigRolloutRevertedParams{ID: st.ends.ID, EndedReason: &reason})
		if err != nil {
			return fmt.Errorf("end rollout %s: %w", st.ends.ID, err)
		}
		if n != 1 {
			return errors.New("the rollout ended concurrently")
		}
		rec.SetParam("rollout_id", st.ends.ID.String())
		rec.SetParam("rollout_status", configrollout.StatusReverted)
	}
	return nil
}

// rolloutModeFor is the staging rule (plan M11 decision 25): staged when rollouts are enabled and plan changes a
// rollout-able section, urgent when the caller opted out of that, else immediate.
func rolloutModeFor(settings configrollout.Settings, plan declarative.Plan, urgent bool) string {
	switch {
	case !settings.Enabled || !configrollout.Touches(plan):
		return RolloutImmediate
	case urgent:
		return RolloutUrgent
	default:
		return RolloutStaged
	}
}

// requireNotStaged refuses a plan that changes a key of staged, the staged keys of the open rollout (plan M11 decision
// 29), with rollout_conflict, naming the rollout and the first conflicting key.
func requireNotStaged(rollout uuid.UUID, staged map[string]map[string]bool, plan declarative.Plan) error {
	i := slices.IndexFunc(plan.Changes, func(c declarative.Change) bool { return staged[c.Section][c.Key] })
	if i < 0 {
		return nil
	}
	c := plan.Changes[i]
	what := c.Section
	if c.Key != "" {
		what += " " + c.Key
	}
	return problem.RolloutConflict.WithDetail(fmt.Sprintf("%s is staged by rollout %s; complete or revert the rollout first", what, rollout))
}

// beforeStates is the "before" column of a change set: for every update and deletion of plan the item as GET
// /api/v1/config exports it, plus its row ID when it has one, by section and key (plan M11 decision 18).
func beforeStates(st configState, plan declarative.Plan) (json.RawMessage, error) {
	out := map[string]map[string]json.RawMessage{}
	for section, items := range declarative.BeforeItems(st.doc, plan) {
		out[section] = map[string]json.RawMessage{}
		for key, item := range items {
			raw, err := json.Marshal(item)
			if err != nil {
				return nil, err
			}
			if id, ok := st.ids[section][key]; ok {
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(raw, &fields); err != nil {
					return nil, err
				}
				fields["id"], _ = json.Marshal(id.String())
				if raw, err = json.Marshal(fields); err != nil {
					return nil, err
				}
			}
			out[section][key] = raw
		}
	}
	return json.Marshal(out)
}
