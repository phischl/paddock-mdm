package app

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/declarative"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// RolloutImmediate is the rollout of a change set every device receives at once; staging and the urgent opt-out
// (plan M11 decisions 25 and 26) replace it for the change sets they apply to.
const RolloutImmediate = "immediate"

// withChangeSet makes a configuration write record its change set (plan M11 decisions 18 and 19, ADR 0011): it reads
// the configuration before fn runs, and afterwards, in the same transaction, diffs it against the configuration fn
// left and stores one change set with the before-states of what changed. The diff covers whatever fn wrote, so a
// device group deletion lists every definition that went with the group. A write that changes nothing records none.
func withChangeSet(fn func(ctx context.Context, q *pgstore.Queries, rec Recorder) error) func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
	return func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		// The lock of the declarative apply: it keeps the before-state equal to what fn replaces, and it is taken first
		// everywhere, so the writers cannot deadlock on each other's later locks.
		if err := q.LockConfigApply(ctx); err != nil {
			return err
		}
		before, err := loadConfig(ctx, q)
		if err != nil {
			return fmt.Errorf("read the configuration before the change: %w", err)
		}
		if err := fn(ctx, q, rec); err != nil {
			return err
		}
		return recordChangeSet(ctx, q, rec, before)
	}
}

// recordChangeSet stores the change set of what turned before into the transaction's current configuration and names
// it in the audit event (param change_set_id). The action's own audit event is the only one: a change set is evidence
// next to it, not an action.
func recordChangeSet(ctx context.Context, q *pgstore.Queries, rec Recorder, before configState) error {
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
	id := uuid.Must(uuid.NewV7())
	if err := insertChangeSet(ctx, q, id, p, false, plan, plan.SectionsOf(), before, changeSetMeta{}); err != nil {
		return err
	}
	rec.SetParam("change_set_id", id.String())
	rec.SetParam("rollout", RolloutImmediate)
	return nil
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
