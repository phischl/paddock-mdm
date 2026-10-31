package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/finding"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Specs of the finding actions (plan M9 decision 33). Closing as accepted_risk needs an administrator; the use case
// checks that, since it depends on the input.
var (
	SpecFindingAcknowledge = ActionSpec{Code: audit.CodeFindingAcknowledged, AllowedRoles: RolesWrite}
	SpecFindingAssign      = ActionSpec{Code: audit.CodeFindingAssigned, AllowedRoles: RolesWrite}
	SpecFindingClose       = ActionSpec{Code: audit.CodeFindingClosed, AllowedRoles: RolesWrite}
	SpecFindingReopen      = ActionSpec{Code: audit.CodeFindingReopened, AllowedRoles: RolesWrite}
)

// tamperFindingCodes are the audit codes that open tamper findings, each with the param that is the finding's
// subject ("" for codes without one, plan M9 decision 31). device.event_gap and device.clock_drift are not tamper
// sources: they surface as attention findings through their attention kinds.
var tamperFindingCodes = map[audit.Code]string{
	audit.CodeDeviceTamperSudoGroupMember:      "group",
	audit.CodeDeviceTamperSudoersDFile:         "file",
	audit.CodeDeviceTamperSudoersChanged:       "",
	audit.CodeDeviceTamperProtectedFileChanged: "file",
	audit.CodeDeviceTamperLocalAdminChanged:    "field",
	audit.CodeDeviceTamperKeyslotChanged:       "volume",
	audit.CodeDeviceTamperServiceStopped:       "unit",
	audit.CodeDeviceCloneSuspected:             "",
	audit.CodeDeviceTamperAgentNotRunning:      "",
}

// UpsertTamperFinding opens the tamper finding of a device, code and subject for the audit event eventID at at, or
// counts the event against the one still open (plan M9 decision 31). It runs in the event's transaction.
func UpsertTamperFinding(ctx context.Context, q *pgstore.Queries, org, device uuid.UUID, code audit.Code, subject string, eventID uuid.UUID, at time.Time) error {
	err := q.UpsertTamperFinding(ctx, pgstore.UpsertTamperFindingParams{
		ID: uuid.Must(uuid.NewV7()), OrganizationID: org, Key: finding.TamperKey(device, string(code), subject),
		DeviceID: device, Code: string(code), Subject: subject, At: at, EventID: uuid.NullUUID{UUID: eventID, Valid: true},
	})
	if err != nil {
		return fmt.Errorf("upsert tamper finding: %w", err)
	}
	return nil
}

// tamperFindingAfter is the AfterFunc that opens or counts the tamper finding of a device event; nil for a code that
// opens none.
func tamperFindingAfter(device uuid.UUID, code audit.Code, params map[string]any, at time.Time) AfterFunc {
	param, ok := tamperFindingCodes[code]
	if !ok {
		return nil
	}
	subject := ""
	if param != "" {
		subject, _ = params[param].(string)
	}
	return func(ctx context.Context, q *pgstore.Queries, eventID uuid.UUID) error {
		org, err := orgOf(ctx)
		if err != nil {
			return err
		}
		return UpsertTamperFinding(ctx, q, org, device, code, subject, eventID, at)
	}
}

// Findings are the use cases of findings: the list, the four status changes of administrators and operators, and
// the worker's materialization of attention conditions (plan M9 decisions 32 and 33).
type Findings struct {
	runner *ActionRunner
	org    *db.OrgPool
	now    func() time.Time
}

// NewFindings creates the use cases.
func NewFindings(runner *ActionRunner, org *db.OrgPool) *Findings {
	return &Findings{runner: runner, org: org, now: time.Now}
}

// FindingAssignee is the account a finding is assigned to.
type FindingAssignee struct {
	ID                    uuid.UUID
	Username, DisplayName string
}

// FindingItem is one finding with its device's hostname and its assignee.
type FindingItem struct {
	ID                                  uuid.UUID
	Kind                                finding.Kind
	Key, Code, Subject                  string
	DeviceID                            uuid.UUID
	Hostname                            string
	Status                              finding.Status
	Assignee                            *FindingAssignee
	OpenedAt, LastSeenAt                time.Time
	Occurrences                         int
	FirstEventID, LastEventID           *uuid.UUID
	AcknowledgedAt, ClosedAt, ClearedAt *time.Time
	ClosedBy, Reason, ExternalRef       *string
}

// FindingQuery selects a page of findings. Cleared selects the attention findings whose condition is gone instead
// of the others.
type FindingQuery struct {
	Page       ListPage
	Statuses   []string
	Kind       *string
	DeviceID   *uuid.UUID
	AssigneeID *uuid.UUID
	Cleared    bool
}

// List returns one page of findings.
func (f *Findings) List(ctx context.Context, query FindingQuery) (Listed[FindingItem], error) {
	var out Listed[FindingItem]
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := f.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		statuses := nilIfEmpty(query.Statuses)
		n, err := q.CountFindings(ctx, pgstore.CountFindingsParams{
			QPattern: query.Page.QPattern, Statuses: statuses, Kind: query.Kind, DeviceID: nullID(query.DeviceID),
			AssigneeID: nullID(query.AssigneeID), Cleared: query.Cleared, CountLimit: countLimit,
		})
		if err != nil {
			return fmt.Errorf("count findings: %w", err)
		}
		out.Count = int(n)
		rows, err := q.ListFindings(ctx, pgstore.ListFindingsParams{
			QPattern: query.Page.QPattern, Statuses: statuses, Kind: query.Kind, DeviceID: nullID(query.DeviceID),
			AssigneeID: nullID(query.AssigneeID), Cleared: query.Cleared, Sort: query.Page.Sort,
			SkipRows: query.Page.Offset, MaxRows: query.Page.Limit,
		})
		if err != nil {
			return fmt.Errorf("list findings: %w", err)
		}
		out.Items = make([]FindingItem, len(rows))
		for i, r := range rows {
			out.Items[i] = findingItem(pgstore.GetFindingRow(r))
		}
		return nil
	})
	return out, err
}

// Get returns one finding; not_found for another organization's.
func (f *Findings) Get(ctx context.Context, id uuid.UUID) (FindingItem, error) {
	var out FindingItem
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := f.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		out, err = loadFinding(ctx, q, id)
		return err
	})
	return out, err
}

func loadFinding(ctx context.Context, q *pgstore.Queries, id uuid.UUID) (FindingItem, error) {
	row, err := q.GetFinding(ctx, id)
	if err != nil {
		return FindingItem{}, notFound(err)
	}
	return findingItem(row), nil
}

func findingItem(r pgstore.GetFindingRow) FindingItem {
	item := FindingItem{
		ID: r.ID, Kind: finding.Kind(r.Kind), Key: r.Key, Code: r.Code, Subject: r.Subject, DeviceID: r.DeviceID,
		Hostname: r.Hostname, Status: finding.Status(r.Status), OpenedAt: r.OpenedAt, LastSeenAt: r.LastSeenAt,
		Occurrences: int(r.Occurrences), FirstEventID: idOf(r.FirstEventID), LastEventID: idOf(r.LastEventID),
		AcknowledgedAt: r.AcknowledgedAt, ClosedAt: r.ClosedAt, ClearedAt: r.ClearedAt, ClosedBy: r.ClosedBy,
		Reason: r.Reason, ExternalRef: r.ExternalRef,
	}
	if r.AssigneeAccountID.Valid {
		item.Assignee = &FindingAssignee{
			ID: r.AssigneeAccountID.UUID, Username: deref(r.AssigneeUsername, ""), DisplayName: deref(r.AssigneeDisplayName, ""),
		}
	}
	return item
}

func idOf(id uuid.NullUUID) *uuid.UUID {
	if !id.Valid {
		return nil
	}
	return &id.UUID
}

// Acknowledge moves an open finding to acknowledged (finding.acknowledged).
func (f *Findings) Acknowledge(ctx context.Context, id uuid.UUID) (FindingItem, error) {
	return f.change(ctx, SpecFindingAcknowledge, id, func(ctx context.Context, q *pgstore.Queries, _ Recorder, row pgstore.LockFindingRow) error {
		if !finding.CanAcknowledge(finding.Status(row.Status)) {
			return problem.InvalidState.WithDetail("only an open finding can be acknowledged")
		}
		at := f.now()
		return q.AcknowledgeFinding(ctx, pgstore.AcknowledgeFindingParams{ID: id, At: &at})
	})
}

// Assign assigns a live finding to an administrator or operator of the organization, or removes its assignee (nil);
// either way it is in progress afterwards (finding.assigned). Any other account is not_found.
func (f *Findings) Assign(ctx context.Context, id uuid.UUID, assignee *uuid.UUID) (FindingItem, error) {
	return f.change(ctx, SpecFindingAssign, id, func(ctx context.Context, q *pgstore.Queries, rec Recorder, row pgstore.LockFindingRow) error {
		rec.SetParam("assignee", "")
		if !finding.CanAssign(finding.Status(row.Status)) {
			return problem.InvalidState.WithDetail("a closed finding cannot be assigned")
		}
		if assignee != nil {
			account, err := q.GetAssignableAccount(ctx, *assignee)
			if err != nil {
				if db.IsNoRows(err) {
					return problem.NotFound.WithDetail("the assignee is not an administrator or operator of this organization")
				}
				return err
			}
			rec.SetParam("assignee", account.Username)
		}
		return q.AssignFinding(ctx, pgstore.AssignFindingParams{ID: id, AssigneeID: nullID(assignee)})
	})
}

// Close closes a live finding with a resolution, a reason and an optional external reference (finding.closed).
// accepted_risk is reserved to administrators (forbidden otherwise, recorded as denied).
func (f *Findings) Close(ctx context.Context, id uuid.UUID, resolution finding.Status, reason, externalRef string) (FindingItem, error) {
	return f.change(ctx, SpecFindingClose, id, func(ctx context.Context, q *pgstore.Queries, rec Recorder, row pgstore.LockFindingRow) error {
		rec.SetParam("resolution", string(resolution))
		rec.SetParam("reason", reason)
		rec.SetParam("external_ref", externalRef)
		if !resolution.Resolution() {
			return problem.InvalidRequest.WithDetail("resolution must be resolved, accepted_risk or false_positive")
		}
		p, _ := principal.From(ctx)
		if resolution == finding.StatusAcceptedRisk && p.Role != principal.RoleOrgAdmin {
			return problem.Forbidden.WithDetail("only an administrator can accept a risk")
		}
		if !finding.ValidReason(reason) {
			return problem.InvalidRequest.WithDetail(fmt.Sprintf("reason is required (1 to %d characters)", finding.MaxReason))
		}
		if !finding.ValidExternalRef(externalRef) {
			return problem.InvalidRequest.WithDetail(fmt.Sprintf("external_ref has at most %d characters", finding.MaxExternalRef))
		}
		if !finding.CanClose(finding.Status(row.Status)) {
			return problem.InvalidState.WithDetail("the finding is closed already")
		}
		at := f.now()
		by := actorOf(p).Display
		return q.CloseFinding(ctx, pgstore.CloseFindingParams{
			ID: id, Status: string(resolution), At: &at, ClosedBy: &by, Reason: &reason, ExternalRef: nonEmpty(externalRef),
		})
	})
}

// Reopen reopens a closed finding with a reason (finding.reopened): a tamper finding always, an attention finding
// only while its condition is still open. A tamper finding whose subject has a newer open finding stays closed.
func (f *Findings) Reopen(ctx context.Context, id uuid.UUID, reason string) (FindingItem, error) {
	return f.change(ctx, SpecFindingReopen, id, func(ctx context.Context, q *pgstore.Queries, rec Recorder, row pgstore.LockFindingRow) error {
		rec.SetParam("reason", reason)
		if !finding.ValidReason(reason) {
			return problem.InvalidRequest.WithDetail(fmt.Sprintf("reason is required (1 to %d characters)", finding.MaxReason))
		}
		if !finding.CanReopen(finding.Status(row.Status), finding.Kind(row.Kind), row.ClearedAt != nil) {
			return problem.InvalidState.WithDetail("only a closed finding whose condition is still open can be reopened")
		}
		err := q.ReopenFinding(ctx, pgstore.ReopenFindingParams{ID: id, Reason: &reason})
		if db.IsUniqueViolation(err, "finding_live_tamper_idx") {
			return problem.InvalidState.WithDetail("a newer finding of the same device and subject is open")
		}
		return err
	})
}

// change runs one status change of a finding: it locks the row, records the common params (plan M9 §6.3) and returns
// the finding as changed.
func (f *Findings) change(ctx context.Context, spec ActionSpec, id uuid.UUID,
	apply func(ctx context.Context, q *pgstore.Queries, rec Recorder, row pgstore.LockFindingRow) error) (FindingItem, error) {
	var out FindingItem
	spec.Target = &audit.Target{Type: "finding", ID: id.String()}
	err := f.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		row, err := q.LockFinding(ctx, id)
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(audit.Target{Type: "finding", ID: id.String(), Display: row.Code})
		rec.SetParam("kind", row.Kind)
		rec.SetParam("code", row.Code)
		rec.SetParam("hostname", row.Hostname)
		rec.SetParam("subject", row.Subject)
		rec.SetParam("previous_status", row.Status)
		if err := apply(ctx, q, rec, row); err != nil {
			return err
		}
		out, err = loadFinding(ctx, q, id)
		return err
	})
	return out, err
}

// Materialize turns the open attention conditions of the organization in ctx into findings and clears the findings
// whose condition is gone, at now (plan M9 decision 32). It records no audit events (ADR 0031 decision 15), changes
// single rows only, so a concurrent status change is kept, and is idempotent.
func (f *Findings) Materialize(ctx context.Context, now time.Time) error {
	org, err := orgOf(ctx)
	if err != nil {
		return err
	}
	var conditions []pgstore.ListAttentionConditionKeysRow
	var live []pgstore.ListLiveAttentionFindingsRow
	err = f.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		if conditions, err = q.ListAttentionConditionKeys(ctx); err != nil {
			return fmt.Errorf("list attention conditions: %w", err)
		}
		live, err = q.ListLiveAttentionFindings(ctx)
		return err
	})
	if err != nil {
		return err
	}
	open := make(map[string]bool, len(conditions))
	for _, c := range conditions {
		open[finding.AttentionKey(c.ID)] = true
	}
	materialized := make(map[string]bool, len(live))
	var errs []error
	for _, l := range live {
		materialized[l.Key] = true
		if open[l.Key] {
			continue
		}
		if err := f.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
			_, err := q.ClearAttentionFinding(ctx, pgstore.ClearAttentionFindingParams{ID: l.ID, ClearedAt: &now})
			return err
		}); err != nil {
			errs = append(errs, f.findingFailed(ctx, l.Key, err))
		}
	}
	for _, c := range conditions {
		key := finding.AttentionKey(c.ID)
		if materialized[key] {
			continue
		}
		if err := f.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
			_, err := q.InsertAttentionFinding(ctx, pgstore.InsertAttentionFindingParams{
				ID: uuid.Must(uuid.NewV7()), OrganizationID: org, Key: key, DeviceID: c.DeviceID, Code: c.Kind,
				Subject: c.Detail, OpenedAt: c.Since, LastSeenAt: now,
			})
			return err
		}); err != nil {
			errs = append(errs, f.findingFailed(ctx, key, err))
		}
	}
	return errors.Join(errs...)
}

// findingFailed logs an attention finding the round could not write; the round goes on with the others.
func (f *Findings) findingFailed(ctx context.Context, key string, err error) error {
	slog.WarnContext(ctx, "attention finding not materialized; retried next round", "key", key, "error", err)
	return fmt.Errorf("finding %s: %w", key, err)
}
