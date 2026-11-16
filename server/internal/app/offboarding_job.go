package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/commandsign"
	"github.com/phischl/paddock-mdm/server/internal/devicecache"
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

// offboardingBatch is the max_rows of one paddock_offboard_delete_batch_from call (plan M17 decision 7, amendment
// 2026-11-16 q point 6).
const offboardingBatch = 1000

// OffboardingStepSlice is how long a resumable step runs inside a round before it yields to the next organization
// (plan M17 amendment p point 2a, main §61, amendment 2026-11-16 s point 1.1): the round's passes then interleave the
// organizations, so a large deletion takes one slice per pass instead of the whole remaining budget. It is checked
// after every unit of work, and every call completes at least one unit.
const OffboardingStepSlice = 5 * time.Second

// The page sizes of the resumable steps devices, fleet and valkey (amendment 2026-11-16 s point 1.3): one page is one
// unit of work.
const (
	offboardingDevicePage = 500
	offboardingFleetPage  = 200
	offboardingValkeyPage = 2000
)

// AuditFinalWaitAlert is how long step audit_final waits for the audit writer's acknowledgement before it records
// organization.deletion_step_failed with audit_writer_pending (plan M17 amendment 2026-11-15 o point 6).
const AuditFinalWaitAlert = time.Hour

// ErrOffboardingPolling means step audit_final waits for the audit writer's acknowledgement (amendment 2026-11-16 s
// point 2.2): no failure; the round asks again after its poll interval instead of in a tight loop.
var ErrOffboardingPolling = errors.New("offboarding: the step waits for an acknowledgement and is polled again")

// OffboardingYield is the answer of a resumable step that reached its slice (OffboardingStepSlice or the round's
// deadline) after a unit of work and stored its count and position (amendment 2026-11-16 s point 1.7): the step stays
// current and continues from there at the next call, without a failure. The round keeps the organization in its pass.
type OffboardingYield struct {
	Step string
}

func (y OffboardingYield) Error() string {
	return "offboarding: step " + y.Step + " yields at its slice"
}

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

// OffboardingCache hands devices over in Valkey and deletes the organization's device keys (devicecache.Cache).
type OffboardingCache interface {
	PutOffboardedDevice(ctx context.Context, d devicecache.OffboardedDevice, lastSeq int64) error
	DeleteCommand(ctx context.Context, device, id uuid.UUID) error
	DeleteOrganization(ctx context.Context, org uuid.UUID, devices []devicecache.OffboardDevice, refs devicecache.OffboardOrgKeys) (int64, error)
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
	// Signer signs the uninstall commands of the step devices with command-signing.
	Signer commandsign.Signer
}

// WithDeps returns the deletion with the dependencies of its steps; NewOffboarding takes only the object-store
// credentials, which reach nothing else (amendment k point 2).
func (o *Offboarding) WithDeps(d OffboardingDeps) *Offboarding {
	c := *o
	c.deps = d
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
// organization; organization.deletion_step_failed is recorded once per code and deletion. While the tombstone waits
// for older transactions Advance returns ErrOffboardingWaiting, while audit_final waits for the audit writer
// ErrOffboardingPolling. Advance has no round budget: every resumable step runs until it is done; the round uses
// AdvanceWithin.
func (o *Offboarding) Advance(ctx context.Context, org uuid.UUID) (done bool, err error) {
	return o.AdvanceWithin(ctx, org, time.Time{})
}

// AdvanceWithin is Advance inside a round whose shared budget ends at deadline (plan M17 amendment 2026-11-16 q point
// 6, amendment s point 1): a resumable step (devices, fleet, objects, valkey, database) stops after a unit of work once
// the deadline or OffboardingStepSlice from the call's start is reached, whichever comes first, stores its count and
// position and returns OffboardingYield; the step continues from that position at the next call. The other steps are
// not cut short. A zero deadline means no budget.
func (o *Offboarding) AdvanceWithin(ctx context.Context, org uuid.UUID, deadline time.Time) (done bool, err error) {
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
	var until time.Time
	if !deadline.IsZero() {
		until = o.now().Add(OffboardingStepSlice)
		if deadline.Before(until) {
			until = deadline
		}
	}
	var count int
	var totals map[string]string
	if step == offboarding.StepDevices {
		count, err = o.devices(ctx, row, until)
		totals = map[string]string{"uninstalls_reissued": countUninstallsReissued, "disarms_issued": countDisarmsIssued}
	} else {
		count, err = o.run(ctx, row, step, until)
	}
	var yield OffboardingYield
	if errors.Is(err, ErrOffboardingWaiting) || errors.Is(err, ErrOffboardingPolling) || errors.As(err, &yield) {
		return false, err
	}
	if err != nil {
		if ctx.Err() != nil {
			return false, err
		}
		return false, o.fail(ctx, row, step, count, err)
	}
	return false, o.complete(ctx, row, step, count, totals)
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

// yieldDue reports whether a resumable step stops after the unit it just finished.
func (o *Offboarding) yieldDue(until time.Time) bool {
	return !until.IsZero() && !o.now().Before(until)
}

// saveProgress stores the count of a unit of a resumable step and the cursor the step resumes at (amendment
// 2026-11-16 s point 1.3), right after the unit and before the slice check, so neither a crash nor a yield loses the
// count or the position. It applies only while the organization is deleting at step.
func (o *Offboarding) saveProgress(ctx context.Context, org uuid.UUID, step string, added int, cursor *string) error {
	err := o.deps.Platform.InPlatform(offboardingSystem(ctx), func(ctx context.Context, q *pgstore.Queries) error {
		return q.SaveOrganizationOffboardingProgress(ctx, pgstore.SaveOrganizationOffboardingProgressParams{
			ID: org, Step: step, Added: int64(added), Cursor: cursor})
	})
	if err != nil {
		return stepError(offboarding.ErrorDatabase, fmt.Errorf("store the progress of step %s: %w", step, err))
	}
	return nil
}

// stepError wraps err with the step error code it fails with.
func stepError(code string, err error) error {
	if err == nil {
		return nil
	}
	return &OffboardingError{Code: code, Err: err}
}

// run executes one step and returns what it removed and has not stored yet, also when it fails after partial
// progress. A resumable step stops at until (zero: never).
func (o *Offboarding) run(ctx context.Context, row pgstore.Organization, step string, until time.Time) (int, error) {
	switch step {
	case offboarding.StepSessions:
		return o.sessions(ctx, row.ID)
	case offboarding.StepOutbox:
		return 0, o.outbox(ctx, row.ID)
	case offboarding.StepAuthentik:
		d, err := o.deps.Identity.DeleteOrganization(ctx, row.Slug)
		return d.Total(), stepError(offboarding.ErrorAuthentikUnavailable, err)
	case offboarding.StepFleet:
		return o.fleet(ctx, row, until)
	case offboarding.StepObjects:
		return o.objectsStep(ctx, row.ID, until)
	case offboarding.StepValkey:
		return o.valkey(ctx, row, until)
	case offboarding.StepAuditFinal:
		return 0, o.auditFinal(ctx, row)
	case offboarding.StepDatabase:
		return o.database(ctx, row, until)
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

// The counts of the step devices that paddock_offboard_reissue_uninstalls adds to offboarding_counts on every call
// (migration 00135): organization.deletion_step_completed reports the totals of all attempts.
const (
	countUninstallsReissued = "devices.uninstalls_reissued"
	countPendingDropped     = "devices.pending_dropped"
	countDisarmsIssued      = "devices.disarms_issued"
)

// devices hands every device of the organization that may still contact the server over to offboarded_device (plan
// M17 decision 15, amendments e point 10, m point 2 and n) and returns how many it recorded and has not stored yet.
// Its first unit waits, like the tombstone, until no transaction that passed the gate on a stale status is open
// (amendment j addendum): such a transaction may still insert or approve a device, which then gets its record too.
// paddock_offboard_reissue_uninstalls (migration 00135) then locks the devices, gives each the disarm of its dead
// man's switch and an uninstall valid for the retention, in one transaction with a constant number of statements. Both
// run only while the step's cursor is NULL; afterwards the cursor is the last device handed over (the nil UUID right
// after the reissue), and every further unit hands over one page of devices after it (amendment 2026-11-16 s point
// 1.3). A crash between the reissue and its stored cursor repeats it, which issues nothing new.
func (o *Offboarding) devices(ctx context.Context, row pgstore.Organization, until time.Time) (int, error) {
	orgCtx := offboardingContext(ctx, row.ID)
	cursor := row.OffboardingCursor
	if cursor == nil {
		var ready bool
		err := o.deps.Worker.InOrgOffboarding(orgCtx, func(ctx context.Context, q *pgstore.Queries) error {
			var err error
			ready, err = q.OffboardQuiesce(ctx)
			return err
		})
		if err != nil {
			return 0, stepError(offboarding.ErrorDatabase, fmt.Errorf("wait for older organization transactions: %w", err))
		}
		if !ready {
			return 0, o.waiting(ctx, row.ID, offboarding.StepDevices)
		}
		began := time.Now()
		var issued int64
		err = o.deps.Worker.InOrgOffboarding(orgCtx, func(ctx context.Context, q *pgstore.Queries) error {
			var err error
			issued, err = q.OffboardReissueUninstalls(ctx)
			return err
		})
		if err != nil {
			return 0, stepError(offboarding.ErrorDatabase, fmt.Errorf("issue the disarms and uninstalls: %w", err))
		}
		// The reissue is one transaction over every device of the organization; its duration at 20 000 devices is a stop
		// condition of amendment 2026-11-16 s (main §81), measured from this line.
		slog.InfoContext(ctx, "organization deletion issued the disarms and uninstalls", "organization", row.ID,
			"uninstalls_issued", issued, "duration", time.Since(began))
		start := uuid.Nil.String()
		if err := o.saveProgress(ctx, row.ID, offboarding.StepDevices, 0, &start); err != nil {
			return 0, err
		}
		if o.yieldDue(until) {
			return 0, OffboardingYield{Step: offboarding.StepDevices}
		}
		cursor = &start
	}
	after, err := uuid.Parse(*cursor)
	if err != nil {
		return 0, stepError(offboarding.ErrorDatabase, fmt.Errorf("the stored position %q of step devices: %w", *cursor, err))
	}
	for {
		n, last, more, err := o.handOver(ctx, row, after)
		if err != nil || !more {
			return n, err
		}
		next := last.String()
		if err := o.saveProgress(ctx, row.ID, offboarding.StepDevices, n, &next); err != nil {
			return n, err
		}
		if o.yieldDue(until) {
			return 0, OffboardingYield{Step: offboarding.StepDevices}
		}
		after = last
	}
}

// handOver hands one page of the devices after the device after over and returns how many records it added, the last
// device of the page and whether the page was full, so another may follow. Signing, the cache and the platform record
// follow the page's transaction, each idempotent: a repeated page keeps the commands it issued, re-adds them to the
// cache and adds only missing records, so the count never grows twice. The cache is written before the record, so a
// device's final report, which deletes both, cannot run before the keys it deletes exist. Nothing here waits for a
// device: a device that never comes back is purged with its record after OffboardedDeviceRetention.
func (o *Offboarding) handOver(ctx context.Context, row pgstore.Organization, after uuid.UUID) (n int, last uuid.UUID, more bool, err error) {
	var cmds []pgstore.DeviceCommand
	var keys []pgstore.ListOffboardingDeviceIdentitiesRow
	var cancelled []pgstore.ListOffboardingCancelledUninstallsRow
	err = o.deps.Worker.InOrgOffboarding(offboardingContext(ctx, row.ID), func(ctx context.Context, q *pgstore.Queries) error {
		page, err := q.ListOffboardingHandedDevicesPage(ctx, pgstore.ListOffboardingHandedDevicesPageParams{
			AfterDevice: after, MaxDevices: offboardingDevicePage})
		if err != nil || len(page) == 0 {
			return err
		}
		last, more = page[len(page)-1], len(page) == offboardingDevicePage
		if cmds, err = q.ListOffboardingHandoverCommands(ctx, page); err != nil {
			return fmt.Errorf("list the commands: %w", err)
		}
		if keys, err = q.ListOffboardingDeviceIdentities(ctx, page); err != nil {
			return fmt.Errorf("list identity keys: %w", err)
		}
		if cancelled, err = q.ListOffboardingCancelledUninstalls(ctx, page); err != nil {
			return fmt.Errorf("list cancelled uninstalls: %w", err)
		}
		return nil
	})
	if err != nil {
		return 0, last, false, stepError(offboarding.ErrorDatabase, fmt.Errorf("list the devices to hand over: %w", err))
	}
	if len(cmds) == 0 {
		return 0, last, more, nil
	}
	payloads := make([]command.Command, len(cmds))
	for i, c := range cmds {
		payloads[i] = Payload(c)
	}
	envelopes, err := commandsign.SignAll(ctx, o.deps.Signer, payloads)
	if err != nil {
		return 0, last, false, stepError(offboarding.ErrorSigningUnavailable, err)
	}
	byDevice := map[uuid.UUID][]pgstore.ListOffboardingDeviceIdentitiesRow{}
	for _, k := range keys {
		byDevice[k.DeviceID] = append(byDevice[k.DeviceID], k)
	}
	in := pgstore.InsertOffboardedDevicesParams{OrganizationID: row.ID}
	// The commands are ordered by device, so a device's commands follow each other.
	for start := 0; start < len(cmds); {
		end := start
		for end < len(cmds) && cmds[end].DeviceID == cmds[start].DeviceID {
			end++
		}
		dev := cmds[start].DeviceID
		d := devicecache.OffboardedDevice{ID: dev, OrganizationID: row.ID}
		var stored []offboardedCommand
		for i := start; i < end; i++ {
			d.Commands = append(d.Commands, devicecache.OffboardedCommand{ID: cmds[i].ID,
				Command: devicecache.Command{ExpiresAt: cmds[i].ExpiresAt, Envelope: envelopes[i]}})
			stored = append(stored, offboardedCommand{CommandID: cmds[i].ID, Envelope: envelopes[i]})
		}
		var lastSeq int64
		storedKeys := []offboardedKey{}
		for _, k := range byDevice[dev] {
			d.Keys = append(d.Keys, devicecache.OffboardedKey{KeyID: k.KeyID, PublicKey: k.PublicKey})
			storedKeys = append(storedKeys, offboardedKey{KeyID: k.KeyID, PublicKey: k.PublicKey})
			lastSeq = k.LastSeq
		}
		if err := o.deps.Cache.PutOffboardedDevice(ctx, d, lastSeq); err != nil {
			return 0, last, false, stepError(offboarding.ErrorValkeyUnavailable, err)
		}
		rawKeys, err := json.Marshal(storedKeys)
		if err != nil {
			return 0, last, false, err
		}
		rawCmds, err := json.Marshal(stored)
		if err != nil {
			return 0, last, false, err
		}
		in.DeviceIds = append(in.DeviceIds, dev)
		in.Keys = append(in.Keys, string(rawKeys))
		in.CommandEnvelopes = append(in.CommandEnvelopes, string(rawCmds))
		start = end
	}
	// A cancelled uninstall, such as the predecessor an administrator's renewed uninstall replaced (amendment m point 2),
	// would otherwise still be served next to its replacement until it expires.
	for _, c := range cancelled {
		if err := o.deps.Cache.DeleteCommand(ctx, c.DeviceID, c.ID); err != nil {
			return 0, last, false, stepError(offboarding.ErrorValkeyUnavailable, err)
		}
	}
	var added int64
	err = o.deps.Platform.InPlatform(offboardingSystem(ctx), func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		added, err = q.InsertOffboardedDevices(ctx, in)
		return err
	})
	if err != nil {
		return 0, last, false, stepError(offboarding.ErrorDatabase, fmt.Errorf("record the offboarded devices: %w", err))
	}
	return int(added), last, more, nil
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

// auditFinal hands the organization's audit log over to the audit writer for its final verification (plan M17
// decision 16, amendment 2026-11-15 o). The worker has no connection to the audit database: it records
// organization.audit_retirement_requested once through ActionRunner in the platform pseudo-organization, which reaches
// the audit writer through the outbox, and the step completes when the writer's acknowledgement on paddock.offboarding
// has set audit_final_verified_at (RecordAuditFinal). A failed outcome completes it too; after AuditFinalWaitAlert
// without acknowledgement the step fails with audit_writer_pending, recorded once, and keeps waiting.
func (o *Offboarding) auditFinal(ctx context.Context, row pgstore.Organization) error {
	if row.AuditFinalVerifiedAt != nil {
		return nil
	}
	if row.AuditRetirementRequestedAt == nil {
		spec := ActionSpec{Code: audit.CodeOrganizationAuditRetirementRequested, Target: orgTarget(row),
			Params: map[string]any{"organization_id": row.ID.String(), "slug": row.Slug}}
		_, err := o.deps.Runner.RecordOnceInScope(offboardingSystem(ctx), ScopePlatform, spec,
			func(ctx context.Context, q *pgstore.Queries, _ Recorder) (bool, error) {
				_, err := q.ClaimOrganizationAuditRetirement(ctx, row.ID)
				if db.IsNoRows(err) {
					return false, nil
				}
				return err == nil, err
			})
		if err != nil {
			return stepError(offboarding.ErrorDatabase, fmt.Errorf("request the final audit verification: %w", err))
		}
		return ErrOffboardingPolling
	}
	if waited := o.now().Sub(*row.AuditRetirementRequestedAt); waited > AuditFinalWaitAlert {
		return stepError(offboarding.ErrorAuditWriterPending,
			fmt.Errorf("the audit writer has not acknowledged the final verification requested %s ago", waited.Round(time.Second)))
	}
	return ErrOffboardingPolling
}

// RecordAuditFinal applies the audit writer's acknowledgement of the organization's final verification (plan M17
// amendment 2026-11-15 o point 6) through the platform pool, once and only while the organization is deleting. A
// repeated acknowledgement, or one of an organization that is not deleting, changes nothing and is no error.
func (o *Offboarding) RecordAuditFinal(ctx context.Context, ack offboarding.AuditRetired) error {
	if err := ack.Validate(); err != nil {
		return err
	}
	var applied int64
	err := o.deps.Platform.InPlatform(offboardingSystem(ctx), func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		applied, err = q.SetOrganizationAuditFinal(ctx, pgstore.SetOrganizationAuditFinalParams{
			ID: ack.OrganizationID, FinalVerifiedAt: &ack.FinalVerifiedAt, FinalOutcome: &ack.FinalOutcome})
		return err
	})
	if err != nil {
		return fmt.Errorf("record the final audit verification of %s: %w", ack.OrganizationID, err)
	}
	slog.InfoContext(ctx, "final audit verification acknowledged", "organization", ack.OrganizationID,
		"outcome", ack.FinalOutcome, "applied", applied == 1)
	return nil
}

// fleet deletes the Fleet hosts of the organization's devices unless a device of another organization uses them
// (plan M17 decision 11, the rule of device.inventory_purged), one page of hosts per unit after the host in the step's
// cursor (amendment 2026-11-16 s point 1.3); each host is listed once, whichever devices reference it. A host that
// Fleet no longer knows counts as deleted. It returns how many hosts it deleted and has not stored yet.
func (o *Offboarding) fleet(ctx context.Context, row pgstore.Organization, until time.Time) (int, error) {
	after := ""
	if row.OffboardingCursor != nil {
		after = *row.OffboardingCursor
	}
	for {
		var refs []pgstore.ListOffboardingInventoryRefsPageRow
		err := o.deps.Worker.InOrgOffboarding(offboardingContext(ctx, row.ID), func(ctx context.Context, q *pgstore.Queries) error {
			var err error
			refs, err = q.ListOffboardingInventoryRefsPage(ctx, pgstore.ListOffboardingInventoryRefsPageParams{
				AfterExternalID: after, MaxHosts: offboardingFleetPage})
			return err
		})
		if err != nil {
			return 0, stepError(offboarding.ErrorDatabase, fmt.Errorf("list the inventory references: %w", err))
		}
		deleted := 0
		for _, r := range refs {
			use, err := o.deps.Platform.FleetHostInUseOutside(offboardingSystem(ctx), row.ID, r.ExternalID)
			if err != nil {
				return deleted, stepError(offboarding.ErrorDatabase, err)
			}
			if use != db.FleetHostUnused {
				slog.InfoContext(ctx, "organization deletion keeps a Fleet host another device uses", "organization", row.ID,
					"device", r.DeviceID, "fleet_host_in_use", use)
				continue
			}
			if err := o.deps.Inventory.DeleteHost(ctx, ports.HostRef(r.ExternalID)); err != nil {
				return deleted, stepError(offboarding.ErrorFleetUnavailable, fmt.Errorf("delete Fleet host of device %s: %w", r.DeviceID, err))
			}
			deleted++
		}
		if len(refs) < offboardingFleetPage {
			return deleted, nil
		}
		next := refs[len(refs)-1].ExternalID
		if err := o.saveProgress(ctx, row.ID, offboarding.StepFleet, deleted, &next); err != nil {
			return deleted, err
		}
		if o.yieldDue(until) {
			return 0, OffboardingYield{Step: offboarding.StepFleet}
		}
		after = next
	}
}

// objectsStep runs DeleteObjects with until and, when it yields, stores what it deleted before it returns the yield
// (amendment 2026-11-16 s point 1.4): the step has no cursor, as the next call lists from the start again.
func (o *Offboarding) objectsStep(ctx context.Context, org uuid.UUID, until time.Time) (int, error) {
	n, err := o.DeleteObjects(ctx, org, until)
	var yield OffboardingYield
	if !errors.As(err, &yield) {
		return n, err
	}
	if serr := o.saveProgress(ctx, org, offboarding.StepObjects, n, nil); serr != nil {
		return n, serr
	}
	return 0, err
}

// valkey deletes the cached keys of the organization's devices, enrollment tokens and escrow uploads and its time
// ticket (plan M17 decision 13, amendment l point 2), one page of devices per unit after the device in the step's
// cursor (amendment 2026-11-16 s point 1.3). The unit that reads the last page, shorter than a full one, also reads the
// token hashes and escrow IDs, here because the database step deletes the rows. A device with an offboarded_device
// record keeps what its uninstall needs (amendment l point 3, devicecache.DeleteOrganization). It returns how many keys
// it deleted and has not stored yet.
func (o *Offboarding) valkey(ctx context.Context, row pgstore.Organization, until time.Time) (int, error) {
	after := uuid.Nil
	if row.OffboardingCursor != nil {
		var err error
		if after, err = uuid.Parse(*row.OffboardingCursor); err != nil {
			return 0, stepError(offboarding.ErrorDatabase, fmt.Errorf("the stored position %q of step valkey: %w", *row.OffboardingCursor, err))
		}
	}
	for {
		var devices []devicecache.OffboardDevice
		var refs devicecache.OffboardOrgKeys
		err := o.deps.Worker.InOrgOffboarding(offboardingContext(ctx, row.ID), func(ctx context.Context, q *pgstore.Queries) error {
			rows, err := q.ListOffboardingDeviceKeysPage(ctx, pgstore.ListOffboardingDeviceKeysPageParams{
				AfterDevice: after, MaxDevices: offboardingValkeyPage})
			if err != nil {
				return err
			}
			// The rows are ordered by device, so a device's keys follow each other.
			devices = nil
			for _, r := range rows {
				if len(devices) == 0 || devices[len(devices)-1].ID != r.DeviceID {
					devices = append(devices, devicecache.OffboardDevice{ID: r.DeviceID})
				}
				if r.KeyID != "" {
					last := &devices[len(devices)-1]
					last.KeyIDs = append(last.KeyIDs, r.KeyID)
				}
			}
			if len(devices) == offboardingValkeyPage {
				return nil
			}
			if refs.TokenHashes, err = q.ListOffboardingEnrollmentTokenHashes(ctx); err != nil {
				return err
			}
			refs.EscrowIDs, err = q.ListOffboardingEscrowIDs(ctx)
			return err
		})
		if err != nil {
			return 0, stepError(offboarding.ErrorDatabase, fmt.Errorf("list the device keys: %w", err))
		}
		ids := make([]uuid.UUID, len(devices))
		for i, d := range devices {
			ids[i] = d.ID
		}
		var offboarded []uuid.UUID
		if len(ids) > 0 {
			err = o.deps.Platform.InPlatform(offboardingSystem(ctx), func(ctx context.Context, q *pgstore.Queries) error {
				var err error
				offboarded, err = q.ListPresentOffboardedDevices(ctx, ids)
				return err
			})
			if err != nil {
				return 0, stepError(offboarding.ErrorDatabase, fmt.Errorf("list the offboarded devices: %w", err))
			}
		}
		keep := make(map[uuid.UUID]bool, len(offboarded))
		for _, id := range offboarded {
			keep[id] = true
		}
		for i := range devices {
			devices[i].Offboarded = keep[devices[i].ID]
		}
		n, err := o.deps.Cache.DeleteOrganization(ctx, row.ID, devices, refs)
		if err != nil || len(devices) < offboardingValkeyPage {
			return int(n), stepError(offboarding.ErrorValkeyUnavailable, err)
		}
		next := devices[len(devices)-1].ID
		cursor := next.String()
		if err := o.saveProgress(ctx, row.ID, offboarding.StepValkey, int(n), &cursor); err != nil {
			return int(n), err
		}
		if o.yieldDue(until) {
			return 0, OffboardingYield{Step: offboarding.StepValkey}
		}
		after = next
	}
}

// database deletes the organization's rows in batches until paddock_offboard_delete_batch_from reports nothing left
// (plan M17 decision 7, amendment 2026-11-16 q point 6). Each batch is its own transaction; its count and the
// delete_order it reached are stored right after it, so neither a failure, a crash nor a yield loses the count of
// what is gone or where the step continues. It starts at the stored position and, inside a round (non-zero until),
// yields between two batches (OffboardingYield) once until is reached; at least one batch runs per call, so the step
// always progresses. When nothing
// is left the position is cleared, so a return from the tombstone (40001 on a straggler row in a table the step had
// passed) starts again at the first table. A batch from a stored position that fails on a foreign key starts again at
// the first table once per call: a row written into a table the step had passed can reference a row of the table it
// deletes now, and only a pass in registry order removes the referencing row first, as paddock_offboard_delete_batch
// did on every call. It returns 0, as nothing is left to add.
func (o *Offboarding) database(ctx context.Context, row pgstore.Organization, until time.Time) (int, error) {
	from := row.OffboardingDbOrder
	restarted := false
	for {
		var b pgstore.OffboardDeleteBatchFromRow
		err := o.deps.Worker.InOrgOffboarding(offboardingContext(ctx, row.ID), func(ctx context.Context, q *pgstore.Queries) error {
			var err error
			b, err = q.OffboardDeleteBatchFrom(ctx, pgstore.OffboardDeleteBatchFromParams{MaxRows: offboardingBatch, FromOrder: from})
			return err
		})
		if err != nil && from != nil && !restarted && db.IsForeignKeyViolation(err) {
			slog.InfoContext(ctx, "organization deletion found a row referencing the table it deletes; starting again at the first table",
				"organization", row.ID, "delete_order", *from)
			from, restarted = nil, true
			continue
		}
		if err != nil {
			return 0, stepError(offboarding.ErrorDatabase, fmt.Errorf("delete a batch of rows: %w", err))
		}
		from = nil
		if b.Deleted > 0 {
			from = &b.AtOrder
		}
		err = o.deps.Platform.InPlatform(offboardingSystem(ctx), func(ctx context.Context, q *pgstore.Queries) error {
			return q.SaveOrganizationOffboardingDatabaseBatch(ctx, pgstore.SaveOrganizationOffboardingDatabaseBatchParams{
				ID: row.ID, Added: b.Deleted, DbOrder: from})
		})
		if err != nil {
			return 0, stepError(offboarding.ErrorDatabase, fmt.Errorf("store the deleted rows: %w", err))
		}
		if b.Deleted == 0 {
			return 0, nil
		}
		if o.yieldDue(until) {
			return 0, OffboardingYield{Step: offboarding.StepDatabase}
		}
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
		return false, o.waiting(ctx, row.ID, offboarding.StepTombstone)
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
		return false, o.waiting(ctx, row.ID, offboarding.StepTombstone)
	case err != nil:
		return false, o.fail(ctx, row, offboarding.StepTombstone, 0, stepError(offboarding.ErrorDatabase, err))
	}
	deleted, err := o.organization(ctx, row.ID)
	if err != nil {
		return false, err
	}
	return true, o.recordDeleted(ctx, deleted)
}

// waiting records finalize_waiting for step once the wait set has been waited on longer than FinalizeWaitAlert, and
// returns ErrOffboardingWaiting.
func (o *Offboarding) waiting(ctx context.Context, org uuid.UUID, step string) error {
	row, err := o.organization(ctx, org)
	if err != nil {
		return err
	}
	if row.OffboardingWaitTakenAt != nil && o.now().Sub(*row.OffboardingWaitTakenAt) > FinalizeWaitAlert {
		waited := stepError(offboarding.ErrorFinalizeWaiting,
			fmt.Errorf("organization transactions open since %s still run", row.OffboardingWaitTakenAt.UTC().Format(time.RFC3339)))
		// fail logs a failure to record; the code then stays unstored and the next round records it.
		_ = o.fail(ctx, row, step, 0, waited)
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
// transaction only for a code not in offboarding_failures_recorded, which it appends (plan M17 decision 6, main §32,
// amendment 2026-11-16 s point 3): once per code and deletion, whichever step fails with it, also when progress
// cleared the stored code in between or another code came first. The stored code still feeds the gauge
// paddock_offboarding_step_failing and the portal. It returns the step's error.
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
	if slices.Contains(row.OffboardingFailuresRecorded, code) {
		if count == 0 && row.OffboardingErrorCode != nil && *row.OffboardingErrorCode == code {
			return stepErr
		}
		if err := o.deps.Platform.InPlatform(sys, write); err != nil {
			slog.WarnContext(ctx, "storing the progress of a failed organization deletion step failed", "organization", row.ID,
				"step", step, "error", err)
			return errors.Join(stepErr, fmt.Errorf("store the step's progress: %w", err))
		}
		return stepErr
	}
	spec := ActionSpec{Code: audit.CodeOrganizationDeletionStepFailed, Target: orgTarget(row),
		Params: map[string]any{"slug": row.Slug, "step": step, "error_code": code}}
	refusal := &problem.Error{Code: code, Status: http.StatusServiceUnavailable}
	err := o.deps.Runner.RunTxRefusal(sys, ScopePlatform, spec, refusal,
		func(ctx context.Context, q *pgstore.Queries, _ Recorder) error {
			if err := write(ctx, q); err != nil {
				return err
			}
			_, err := q.MarkOrganizationOffboardingFailureRecorded(ctx, pgstore.MarkOrganizationOffboardingFailureRecordedParams{
				ID: row.ID, Code: code})
			return err
		})
	if err != nil && !errors.Is(err, refusal) {
		slog.WarnContext(ctx, "recording a failed organization deletion step failed; retried next round", "organization", row.ID,
			"step", step, "error_code", code, "error", err)
		return errors.Join(stepErr, fmt.Errorf("record the failed step: %w", err))
	}
	slog.WarnContext(ctx, "organization deletion step failed; retried", "organization", row.ID, "step", step,
		"error_code", code, "error", stepErr)
	return stepErr
}

// complete writes the step's checkpoint together with organization.deletion_step_completed (count: everything the step
// removed over its attempts; totals: further params of the step, each read from its key in offboarding_counts, such as
// uninstalls_reissued and disarms_issued of devices), exactly once.
func (o *Offboarding) complete(ctx context.Context, row pgstore.Organization, step string, count int, totals map[string]string) error {
	next, ok := offboarding.Next(step)
	if !ok {
		return fmt.Errorf("step %q has no successor", step)
	}
	spec := ActionSpec{Code: audit.CodeOrganizationDeletionStepCompleted, Target: orgTarget(row),
		Params: map[string]any{"slug": row.Slug, "step": step}}
	_, err := o.deps.Runner.RecordOnceInScope(offboardingSystem(ctx), ScopePlatform, spec,
		func(ctx context.Context, q *pgstore.Queries, rec Recorder) (bool, error) {
			done, err := q.CompleteOrganizationOffboardingStep(ctx, pgstore.CompleteOrganizationOffboardingStepParams{
				ID: row.ID, CurrentStep: step, NextStep: &next, Added: int64(count)})
			if db.IsNoRows(err) {
				return false, nil
			}
			if err != nil {
				return false, err
			}
			// The total includes what earlier attempts and batches stored, read in the checkpoint's own statement.
			c := counts(done)
			rec.SetParam("count", c[step])
			for param, key := range totals {
				rec.SetParam(param, c[key])
			}
			return true, nil
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
			"slug": row.Slug, "devices_offboarded": c[offboarding.StepDevices], "devices_pending_dropped": c[countPendingDropped],
			"rows_deleted":    c[offboarding.StepDatabase],
			"objects_deleted": c[offboarding.StepObjects], "authentik_objects_deleted": c[offboarding.StepAuthentik],
			"fleet_hosts_deleted": c[offboarding.StepFleet], "audit_final_outcome": deref(row.AuditFinalOutcome, "")}},
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
