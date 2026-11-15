package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/offboarding"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// FinalizeWaitAlert is how long the tombstone waits for organization transactions that were open when the deletion
// started before it records organization.deletion_step_failed with finalize_waiting (plan M17 amendment j addendum
// point 5): a transaction open for an hour is an anomaly an operator must see.
const FinalizeWaitAlert = time.Hour

// offboardingBatch is the max_rows of one paddock_offboard_delete_batch call (plan M17 decision 7).
const offboardingBatch = 1000

// ErrOffboardingWaiting means the tombstone waits for organization transactions that started before the deletion was
// visible to every process (paddock_offboard_quiesce returned false); the job asks again next round. It is no failure.
var ErrOffboardingWaiting = errors.New("offboarding: the tombstone waits for older organization transactions")

// OffboardingIdentity deletes the organization's identity provider objects (ports.IdentityProvider).
type OffboardingIdentity interface {
	DeleteOrganization(ctx context.Context, slug string) (ports.OrgIdentityDeletion, error)
}

// OffboardingInventory deletes Fleet hosts (ports.InventoryAdmin).
type OffboardingInventory interface {
	DeleteHost(ctx context.Context, ref ports.HostRef) error
}

// OffboardingCache deletes the organization's device keys in Valkey (devicecache.Cache).
type OffboardingCache interface {
	DeleteOrganization(ctx context.Context, org uuid.UUID, devices []uuid.UUID, keyIDs []string) (int64, error)
}

// OffboardingSessions ends the portal and MCP sessions of an administrator account (sessions.Store).
type OffboardingSessions interface {
	RevokeAccount(ctx context.Context, accountID uuid.UUID) (int, error)
}

// OffboardingDeps are what the deletion's steps need besides the object store. Worker is the pool of paddock_worker:
// the steps enter the deleting organization through its InOrgOffboarding only.
type OffboardingDeps struct {
	Runner    *ActionRunner
	Worker    *db.OrgPool
	Platform  *db.PlatformPool
	Identity  OffboardingIdentity
	Inventory OffboardingInventory
	Cache     OffboardingCache
	Sessions  OffboardingSessions
}

// WithDeps returns the deletion with the dependencies of its steps; NewOffboarding takes only the object-store
// credentials, which reach nothing else (amendment k point 2).
func (o *Offboarding) WithDeps(d OffboardingDeps) *Offboarding {
	c := *o
	c.deps = d
	return &c
}

// WithStubbedSteps makes steps complete at once without work: devices until PDK-1016 and audit_final until PDK-1017
// implement them (plan M17 §7 step 3). Those tickets remove the option.
func (o *Offboarding) WithStubbedSteps(steps ...string) *Offboarding {
	c := *o
	c.stubbed = maps.Clone(c.stubbed)
	if c.stubbed == nil {
		c.stubbed = map[string]bool{}
	}
	for _, s := range steps {
		c.stubbed[s] = true
	}
	return &c
}

// WithClock replaces time.Now for the finalize wait alert (tests).
func (o *Offboarding) WithClock(now func() time.Time) *Offboarding {
	c := *o
	c.now = now
	return &c
}

// offboardingSystem is the principal of the deletion's platform transactions and events.
func offboardingSystem(ctx context.Context) context.Context {
	return principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "organization-offboarding"})
}

// StartDue moves every organization whose grace period ended into status deleting at its first step (plan M17
// decision 5) and returns their IDs. A request still issuing its uninstalls is not due (ListDueOrganizationDeletions).
func (o *Offboarding) StartDue(ctx context.Context) ([]uuid.UUID, error) {
	ctx = offboardingSystem(ctx)
	var started []uuid.UUID
	err := o.deps.Platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		due, err := q.ListDueOrganizationDeletions(ctx)
		if err != nil {
			return err
		}
		first := offboarding.Steps()[0]
		for _, id := range due {
			if _, err := q.StartOrganizationDeletion(ctx, pgstore.StartOrganizationDeletionParams{ID: id, Step: &first}); err != nil {
				if db.IsNoRows(err) {
					continue
				}
				return err
			}
			started = append(started, id)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("start the due organization deletions: %w", err)
	}
	return started, nil
}

// Pending lists the organizations the deletion works on: every deleting one and every tombstone whose
// organization.deleted is not recorded yet.
func (o *Offboarding) Pending(ctx context.Context) ([]pgstore.Organization, error) {
	var orgs []pgstore.Organization
	err := o.deps.Platform.InPlatform(offboardingSystem(ctx), func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		orgs, err = q.ListOffboardingOrganizations(ctx)
		return err
	})
	return orgs, err
}

// Advance runs the next step of the organization's deletion (plan M17 decisions 5 and 6) and reports whether the
// deletion is complete. The step resumes from organization.offboarding_step; each step is idempotent and its
// checkpoint is written with its organization.deletion_step_completed event, so a crash between two steps repeats at
// most the step that was running. A failed step returns an *OffboardingError with its code, stored on the
// organization; organization.deletion_step_failed is recorded only when the code differs from the stored one. While
// the tombstone waits for older transactions Advance returns ErrOffboardingWaiting.
func (o *Offboarding) Advance(ctx context.Context, org uuid.UUID) (done bool, err error) {
	row, err := o.organization(ctx, org)
	if err != nil {
		return false, err
	}
	if row.Status == organization.StatusDeleted {
		if row.OffboardingStep != nil && *row.OffboardingStep == offboarding.StepTombstone {
			return true, o.recordDeleted(ctx, row)
		}
		return true, nil
	}
	if row.Status != organization.StatusDeleting {
		return false, nil
	}
	step := offboarding.Steps()[0]
	if row.OffboardingStep != nil {
		step = *row.OffboardingStep
	}
	if step == offboarding.StepTombstone {
		return o.tombstone(ctx, row)
	}
	count, err := o.run(ctx, row, step)
	if err != nil {
		if ctx.Err() != nil {
			return false, err
		}
		return false, o.fail(ctx, row, step, count, err)
	}
	return false, o.complete(ctx, row, step, count)
}

func (o *Offboarding) organization(ctx context.Context, org uuid.UUID) (pgstore.Organization, error) {
	var row pgstore.Organization
	err := o.deps.Platform.InPlatform(offboardingSystem(ctx), func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		row, err = q.GetOrganization(ctx, org)
		return err
	})
	if err != nil {
		return row, fmt.Errorf("read organization %s: %w", org, err)
	}
	return row, nil
}

// stepError wraps err with the step error code it fails with.
func stepError(code string, err error) error {
	if err == nil {
		return nil
	}
	return &OffboardingError{Code: code, Err: err}
}

// run executes one step and returns what it removed, also when it fails after partial progress.
func (o *Offboarding) run(ctx context.Context, row pgstore.Organization, step string) (int, error) {
	if o.stubbed[step] {
		return 0, nil
	}
	switch step {
	case offboarding.StepSessions:
		return o.sessions(ctx, row.ID)
	case offboarding.StepOutbox:
		return 0, o.outbox(ctx, row.ID)
	case offboarding.StepAuthentik:
		d, err := o.deps.Identity.DeleteOrganization(ctx, row.Slug)
		return d.Total(), stepError(offboarding.ErrorAuthentikUnavailable, err)
	case offboarding.StepFleet:
		return o.fleet(ctx, row.ID)
	case offboarding.StepObjects:
		return o.DeleteObjects(ctx, row.ID)
	case offboarding.StepValkey:
		return o.valkey(ctx, row.ID)
	case offboarding.StepDatabase:
		return o.database(ctx, row.ID)
	}
	return 0, stepError(offboarding.ErrorDatabase, fmt.Errorf("step %q has no implementation", step))
}

// sessions ends the portal and MCP sessions of every administrator account of the organization and revokes its API
// tokens (plan M17 decision 14). The accounts belong to this organization only, so no other organization's session
// ends.
func (o *Offboarding) sessions(ctx context.Context, org uuid.UUID) (int, error) {
	var accounts []uuid.UUID
	err := o.deps.Worker.InOrgOffboarding(offboardingContext(ctx, org), func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		accounts, err = q.ListOffboardingAdminAccounts(ctx)
		return err
	})
	if err != nil {
		return 0, stepError(offboarding.ErrorDatabase, fmt.Errorf("list the administrator accounts: %w", err))
	}
	ended := 0
	for _, a := range accounts {
		n, err := o.deps.Sessions.RevokeAccount(ctx, a)
		ended += n
		if err != nil {
			return ended, stepError(offboarding.ErrorValkeyUnavailable, fmt.Errorf("end the sessions of account %s: %w", a, err))
		}
	}
	var revoked int64
	err = o.deps.Worker.InOrgOffboarding(offboardingContext(ctx, org), func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		revoked, err = q.OffboardRevokeAPITokens(ctx)
		return err
	})
	if err != nil {
		return ended, stepError(offboarding.ErrorDatabase, fmt.Errorf("revoke the API tokens: %w", err))
	}
	return ended + int(revoked), nil
}

// outbox completes only when the organization has no unpublished outbox row (plan M17 decision 9): no audit event of
// the organization may be lost, so unpublished rows are waited for, never deleted.
func (o *Offboarding) outbox(ctx context.Context, org uuid.UUID) error {
	var pending int64
	err := o.deps.Worker.InOrgOffboarding(offboardingContext(ctx, org), func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		pending, err = q.OffboardOutboxPending(ctx)
		return err
	})
	if err != nil {
		return stepError(offboarding.ErrorDatabase, fmt.Errorf("count the unpublished outbox rows: %w", err))
	}
	if pending > 0 {
		return stepError(offboarding.ErrorOutboxPending, fmt.Errorf("%d outbox rows of organization %s are unpublished", pending, org))
	}
	return nil
}

// fleet deletes the Fleet hosts of the organization's devices unless a device of another organization uses them
// (plan M17 decision 11, the rule of device.inventory_purged). A host that Fleet no longer knows counts as deleted.
func (o *Offboarding) fleet(ctx context.Context, org uuid.UUID) (int, error) {
	var refs []pgstore.ListOffboardingInventoryRefsRow
	err := o.deps.Worker.InOrgOffboarding(offboardingContext(ctx, org), func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		refs, err = q.ListOffboardingInventoryRefs(ctx)
		return err
	})
	if err != nil {
		return 0, stepError(offboarding.ErrorDatabase, fmt.Errorf("list the inventory references: %w", err))
	}
	deleted := 0
	seen := map[string]bool{}
	for _, r := range refs {
		if r.ExternalID == "" || seen[r.ExternalID] {
			continue
		}
		seen[r.ExternalID] = true
		use, err := o.deps.Platform.FleetHostInUse(offboardingSystem(ctx), r.DeviceID, r.ExternalID)
		if err != nil {
			return deleted, stepError(offboarding.ErrorDatabase, err)
		}
		if use != db.FleetHostUnused {
			slog.InfoContext(ctx, "organization deletion keeps a Fleet host another device uses", "organization", org,
				"device", r.DeviceID, "fleet_host_in_use", use)
			continue
		}
		if err := o.deps.Inventory.DeleteHost(ctx, ports.HostRef(r.ExternalID)); err != nil {
			return deleted, stepError(offboarding.ErrorFleetUnavailable, fmt.Errorf("delete Fleet host of device %s: %w", r.DeviceID, err))
		}
		deleted++
	}
	return deleted, nil
}

// valkey deletes the cached keys of the organization's devices and its time ticket (plan M17 decision 13).
func (o *Offboarding) valkey(ctx context.Context, org uuid.UUID) (int, error) {
	var rows []pgstore.ListOffboardingDeviceKeysRow
	err := o.deps.Worker.InOrgOffboarding(offboardingContext(ctx, org), func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		rows, err = q.ListOffboardingDeviceKeys(ctx)
		return err
	})
	if err != nil {
		return 0, stepError(offboarding.ErrorDatabase, fmt.Errorf("list the device keys: %w", err))
	}
	var devices []uuid.UUID
	var keyIDs []string
	for _, r := range rows {
		if !slices.Contains(devices, r.DeviceID) {
			devices = append(devices, r.DeviceID)
		}
		if r.KeyID != "" {
			keyIDs = append(keyIDs, r.KeyID)
		}
	}
	n, err := o.deps.Cache.DeleteOrganization(ctx, org, devices, keyIDs)
	return int(n), stepError(offboarding.ErrorValkeyUnavailable, err)
}

// database deletes the organization's rows in batches until paddock_offboard_delete_batch reports nothing left (plan
// M17 decision 7). Each batch is its own transaction, so a failure keeps what was deleted.
func (o *Offboarding) database(ctx context.Context, org uuid.UUID) (int, error) {
	total := 0
	for {
		var n int64
		err := o.deps.Worker.InOrgOffboarding(offboardingContext(ctx, org), func(ctx context.Context, q *pgstore.Queries) error {
			var err error
			n, err = q.OffboardDeleteBatch(ctx, offboardingBatch)
			return err
		})
		if err != nil {
			return total, stepError(offboarding.ErrorDatabase, fmt.Errorf("delete a batch of rows: %w", err))
		}
		if n == 0 {
			return total, nil
		}
		total += int(n)
	}
}

// tombstone asks paddock_offboard_quiesce whether every transaction that could have passed the gate on a stale status
// has ended (plan M17 amendment j addendum point 4). While it has not, the step stays and the job asks again next
// round; after FinalizeWaitAlert it records finalize_waiting once. Once it has, paddock_offboard_finalize re-counts the
// rows and writes the tombstone: rows a straggler wrote (40001) send the deletion back to the database step, keeping
// the stored wait set.
func (o *Offboarding) tombstone(ctx context.Context, row pgstore.Organization) (bool, error) {
	orgCtx := offboardingContext(ctx, row.ID)
	var ready bool
	err := o.deps.Worker.InOrgOffboarding(orgCtx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		ready, err = q.OffboardQuiesce(ctx)
		return err
	})
	if err != nil {
		return false, o.fail(ctx, row, offboarding.StepTombstone, 0, stepError(offboarding.ErrorDatabase, err))
	}
	if !ready {
		return false, o.waiting(ctx, row.ID)
	}
	err = o.deps.Worker.InOrgOffboarding(orgCtx, func(ctx context.Context, q *pgstore.Queries) error {
		return q.OffboardFinalize(ctx)
	})
	switch {
	case db.IsSerializationFailure(err):
		slog.InfoContext(ctx, "organization deletion found rows written after its delete loop; deleting them again",
			"organization", row.ID)
		back := offboarding.StepDatabase
		return false, o.deps.Platform.InPlatform(offboardingSystem(ctx), func(ctx context.Context, q *pgstore.Queries) error {
			_, err := q.AdvanceOrganizationOffboardingStep(ctx, pgstore.AdvanceOrganizationOffboardingStepParams{
				ID: row.ID, CurrentStep: row.OffboardingStep, NextStep: &back})
			if db.IsNoRows(err) {
				return nil
			}
			return err
		})
	case db.IsNotInPrerequisiteState(err):
		return false, o.waiting(ctx, row.ID)
	case err != nil:
		return false, o.fail(ctx, row, offboarding.StepTombstone, 0, stepError(offboarding.ErrorDatabase, err))
	}
	deleted, err := o.organization(ctx, row.ID)
	if err != nil {
		return false, err
	}
	return true, o.recordDeleted(ctx, deleted)
}

// waiting records finalize_waiting once the wait set has been waited on longer than FinalizeWaitAlert, and returns
// ErrOffboardingWaiting.
func (o *Offboarding) waiting(ctx context.Context, org uuid.UUID) error {
	row, err := o.organization(ctx, org)
	if err != nil {
		return err
	}
	if row.OffboardingWaitTakenAt != nil && o.now().Sub(*row.OffboardingWaitTakenAt) > FinalizeWaitAlert {
		waited := stepError(offboarding.ErrorFinalizeWaiting,
			fmt.Errorf("organization transactions open since %s still run", row.OffboardingWaitTakenAt.UTC().Format(time.RFC3339)))
		if err := o.fail(ctx, row, offboarding.StepTombstone, 0, waited); !errors.As(err, new(*OffboardingError)) {
			return err
		}
	}
	return ErrOffboardingWaiting
}

// codeOf is the step error code of err; an error without one is a database error.
func codeOf(err error) string {
	var oe *OffboardingError
	if errors.As(err, &oe) {
		return oe.Code
	}
	return offboarding.ErrorDatabase
}

// counts are the per-step counts stored on the organization.
func counts(row pgstore.Organization) map[string]int64 {
	out := map[string]int64{}
	if len(row.OffboardingCounts) > 0 {
		_ = json.Unmarshal(row.OffboardingCounts, &out)
	}
	return out
}

func orgTarget(row pgstore.Organization) *audit.Target {
	return &audit.Target{Type: "organization", ID: row.ID.String(), Display: row.Slug}
}

// fail stores the step's error code and partial count. organization.deletion_step_failed is recorded in the same
// transaction only when the code differs from the stored one (plan M17 decision 6, main's amendment of 2026-11-15): a
// step that keeps failing with the same code records nothing more. It returns the step's error.
func (o *Offboarding) fail(ctx context.Context, row pgstore.Organization, step string, count int, stepErr error) error {
	code := codeOf(stepErr)
	params := pgstore.FailOrganizationOffboardingStepParams{ID: row.ID, Step: step, Added: int64(count), ErrorCode: &code}
	write := func(ctx context.Context, q *pgstore.Queries) error {
		_, err := q.FailOrganizationOffboardingStep(ctx, params)
		if db.IsNoRows(err) {
			return nil
		}
		return err
	}
	sys := offboardingSystem(ctx)
	if row.OffboardingErrorCode != nil && *row.OffboardingErrorCode == code {
		if count == 0 {
			return stepErr
		}
		if err := o.deps.Platform.InPlatform(sys, write); err != nil {
			return errors.Join(stepErr, fmt.Errorf("store the step's progress: %w", err))
		}
		return stepErr
	}
	spec := ActionSpec{Code: audit.CodeOrganizationDeletionStepFailed, Target: orgTarget(row),
		Params: map[string]any{"slug": row.Slug, "step": step, "error_code": code}}
	refusal := &problem.Error{Code: code, Status: http.StatusServiceUnavailable}
	err := o.deps.Runner.RunTxRefusal(sys, ScopePlatform, spec, refusal,
		func(ctx context.Context, q *pgstore.Queries, _ Recorder) error { return write(ctx, q) })
	if err != nil && !errors.Is(err, refusal) {
		return errors.Join(stepErr, fmt.Errorf("record the failed step: %w", err))
	}
	slog.WarnContext(ctx, "organization deletion step failed; retried", "organization", row.ID, "step", step,
		"error_code", code, "error", stepErr)
	return stepErr
}

// complete writes the step's checkpoint together with organization.deletion_step_completed (count: everything the step
// removed over its attempts), exactly once.
func (o *Offboarding) complete(ctx context.Context, row pgstore.Organization, step string, count int) error {
	next, ok := offboarding.Next(step)
	if !ok {
		return fmt.Errorf("step %q has no successor", step)
	}
	total := counts(row)[step] + int64(count)
	spec := ActionSpec{Code: audit.CodeOrganizationDeletionStepCompleted, Target: orgTarget(row),
		Params: map[string]any{"slug": row.Slug, "step": step, "count": total}}
	_, err := o.deps.Runner.RecordOnceInScope(offboardingSystem(ctx), ScopePlatform, spec,
		func(ctx context.Context, q *pgstore.Queries, _ Recorder) (bool, error) {
			_, err := q.CompleteOrganizationOffboardingStep(ctx, pgstore.CompleteOrganizationOffboardingStepParams{
				ID: row.ID, CurrentStep: step, NextStep: &next, Added: int64(count)})
			if db.IsNoRows(err) {
				return false, nil
			}
			return err == nil, err
		})
	if err != nil {
		return fmt.Errorf("complete step %s: %w", step, err)
	}
	return nil
}

// recordDeleted records the tombstone step's completion and organization.deleted with the counts per store, exactly
// once after paddock_offboard_finalize committed (plan M17 decision 17, amendment d point 3): a crash in between
// leaves offboarding_step at tombstone, and the next round records them.
func (o *Offboarding) recordDeleted(ctx context.Context, row pgstore.Organization) error {
	c := counts(row)
	specs := []ActionSpec{
		{Code: audit.CodeOrganizationDeletionStepCompleted, Target: orgTarget(row),
			Params: map[string]any{"slug": row.Slug, "step": offboarding.StepTombstone, "count": 0}},
		{Code: audit.CodeOrganizationDeleted, Target: orgTarget(row), Params: map[string]any{
			"slug": row.Slug, "devices_offboarded": c[offboarding.StepDevices], "rows_deleted": c[offboarding.StepDatabase],
			"objects_deleted": c[offboarding.StepObjects], "authentik_objects_deleted": c[offboarding.StepAuthentik],
			"fleet_hosts_deleted": c[offboarding.StepFleet]}},
	}
	_, err := o.deps.Runner.RecordAllOnce(offboardingSystem(ctx), ScopePlatform, specs,
		func(ctx context.Context, q *pgstore.Queries) (bool, error) {
			_, err := q.CloseOrganizationOffboarding(ctx, row.ID)
			if db.IsNoRows(err) {
				return false, nil
			}
			return err == nil, err
		})
	if err != nil {
		return fmt.Errorf("record the deletion of organization %s: %w", row.ID, err)
	}
	slog.InfoContext(ctx, "organization deleted", "organization", row.ID, "slug", row.Slug)
	return nil
}
