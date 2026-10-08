package app

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/device"
	"github.com/phischl/paddock-mdm/server/internal/domain/revocation"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Specs of the revocation actions of administrators (plan M4c decision 7): organization administrators only, each
// with a fresh step-up and the device's hostname typed as confirmation.
var (
	SpecRevocationRequest = ActionSpec{Code: audit.CodeRevocationRequested, AllowedRoles: RolesAdmin, RequiresStepUp: true}
	SpecRevocationApprove = ActionSpec{Code: audit.CodeRevocationApproved, AllowedRoles: RolesAdmin, RequiresStepUp: true}
	SpecRevocationReject  = ActionSpec{Code: audit.CodeRevocationRejected, AllowedRoles: RolesAdmin, RequiresStepUp: true}
	SpecRevocationCancel  = ActionSpec{Code: audit.CodeRevocationCancelled, AllowedRoles: RolesAdmin, RequiresStepUp: true}
)

// Revocations are the administrators' use cases of Lock and Destroy: request, approve, reject, cancel and list. They
// record requests and approvals with the raw step-up ID token of each administrator; only the revocation-issuer
// verifies the tokens, enforces the limits and signs (plan M4c decisions 5–8).
type Revocations struct {
	runner  *ActionRunner
	org     *db.OrgPool
	tokens  StepUpTokens
	enabled bool
	now     func() time.Time
}

// NewRevocations creates the use cases; enabled is PADDOCK_REVOCATION_ENABLED.
func NewRevocations(runner *ActionRunner, org *db.OrgPool, tokens StepUpTokens, enabled bool) *Revocations {
	return &Revocations{runner: runner, org: org, tokens: tokens, enabled: enabled, now: time.Now}
}

// Enabled reports PADDOCK_REVOCATION_ENABLED.
func (r *Revocations) Enabled() bool { return r.enabled }

// RevocationInput is a Lock or Destroy request.
type RevocationInput struct {
	DeviceID        uuid.UUID
	Action          string // revocation.ActionLock or revocation.ActionDestroy
	ConfirmHostname string
	Reason          string
}

// Request records a Lock (approved at once) or a Destroy (waiting for a second administrator) with the requester's
// approval (audited: revocation.requested).
func (r *Revocations) Request(ctx context.Context, in RevocationInput) (pgstore.RevocationRequest, error) {
	spec := SpecRevocationRequest
	spec.Target = &audit.Target{Type: "device", ID: in.DeviceID.String()}
	spec.Params = map[string]any{"action": in.Action}
	if !r.enabled {
		return pgstore.RevocationRequest{}, r.runner.RecordRejected(ctx, ScopeOrg, spec, disabled())
	}
	var out pgstore.RevocationRequest
	err := r.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		if in.Action != revocation.ActionLock && in.Action != revocation.ActionDestroy {
			return problem.InvalidRequest.WithDetail("action must be lock or destroy")
		}
		if !revocation.ValidReason(in.Reason) {
			return problem.InvalidRequest.WithDetail("reason must have at most 500 characters")
		}
		dev, err := r.confirmedDevice(ctx, q, rec, in.DeviceID, in.ConfirmHostname)
		if err != nil {
			return err
		}
		if dev.State != device.StateActive && dev.State != device.StateQuarantined {
			return problem.InvalidState.WithDetail("only active or quarantined devices can be revoked")
		}
		p, _ := principal.From(ctx)
		token, jti, err := r.stepUpToken(ctx, q, p)
		if err != nil {
			return err
		}
		now := r.now().UTC()
		status, approvedAt := revocation.StatusRequested, (*time.Time)(nil)
		if revocation.Approvals(in.Action) == 1 {
			status, approvedAt = revocation.StatusApproved, &now
		}
		out, err = q.InsertRevocationRequest(ctx, pgstore.InsertRevocationRequestParams{
			ID: uuid.Must(uuid.NewV7()), OrganizationID: p.OrganizationID, DeviceID: dev.ID, Action: in.Action,
			Status: status, RequestedBy: uuid.NullUUID{UUID: p.ID, Valid: true}, RequestedAt: now, Reason: in.Reason,
			ApprovedAt: approvedAt,
		})
		if db.IsUniqueViolation(err, "revocation_request_open_idx") {
			return problem.AlreadyExists.WithDetail("the device has an open " + in.Action + " request")
		}
		if err != nil {
			return err
		}
		rec.SetParam("request_id", out.ID.String())
		if err := q.InsertRevocationApproval(ctx, pgstore.InsertRevocationApprovalParams{
			RequestID: out.ID, OrganizationID: p.OrganizationID, Role: revocation.RoleRequester, AdminID: p.ID,
			Subject: p.Subject, StepupJti: jti, StepupIDToken: &token, ApprovedAt: now,
		}); err != nil {
			return err
		}
		if status == revocation.StatusApproved {
			rec.RevocationApproved(out.ID)
		}
		return nil
	})
	return out, err
}

// Approve records the second approval of a Destroy by another administrator — another account and another
// Authentik subject than the requester (two-person rule) — and hands it to the issuer (audited: revocation.approved).
func (r *Revocations) Approve(ctx context.Context, id uuid.UUID, confirmHostname string) (pgstore.RevocationRequest, error) {
	spec := SpecRevocationApprove
	spec.Params = map[string]any{"request_id": id.String()}
	if !r.enabled {
		return pgstore.RevocationRequest{}, r.runner.RecordRejected(ctx, ScopeOrg, spec, disabled())
	}
	var out pgstore.RevocationRequest
	err := r.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		req, err := r.openRequest(ctx, q, rec, id, confirmHostname)
		if err != nil {
			return err
		}
		if req.Status != revocation.StatusRequested {
			return problem.InvalidState.WithDetail("the request does not wait for an approval")
		}
		p, _ := principal.From(ctx)
		approvals, err := q.ListRevocationApprovals(ctx, []uuid.UUID{id})
		if err != nil {
			return err
		}
		for _, a := range approvals {
			if a.AdminID == p.ID || a.Subject == p.Subject {
				return problem.Forbidden.WithDetail("a second administrator must approve the request")
			}
		}
		token, jti, err := r.stepUpToken(ctx, q, p)
		if err != nil {
			return err
		}
		now := r.now().UTC()
		if err := q.InsertRevocationApproval(ctx, pgstore.InsertRevocationApprovalParams{
			RequestID: id, OrganizationID: p.OrganizationID, Role: revocation.RoleApprover, AdminID: p.ID,
			Subject: p.Subject, StepupJti: jti, StepupIDToken: &token, ApprovedAt: now,
		}); err != nil {
			return err
		}
		if out, err = q.ApproveRevocationRequest(ctx, pgstore.ApproveRevocationRequestParams{ID: id, ApprovedAt: now}); err != nil {
			return err
		}
		rec.RevocationApproved(id)
		return nil
	})
	return out, err
}

// Reject closes a request that waits for its second approval (audited: revocation.rejected).
func (r *Revocations) Reject(ctx context.Context, id uuid.UUID, confirmHostname string) (pgstore.RevocationRequest, error) {
	return r.close(ctx, SpecRevocationReject, id, confirmHostname, revocation.StatusRejected)
}

// Cancel closes a request of the caller before it is issued (audited: revocation.cancelled).
func (r *Revocations) Cancel(ctx context.Context, id uuid.UUID, confirmHostname string) (pgstore.RevocationRequest, error) {
	return r.close(ctx, SpecRevocationCancel, id, confirmHostname, revocation.StatusCancelled)
}

func (r *Revocations) close(ctx context.Context, spec ActionSpec, id uuid.UUID, confirmHostname, status string) (pgstore.RevocationRequest, error) {
	spec.Params = map[string]any{"request_id": id.String()}
	if !r.enabled {
		return pgstore.RevocationRequest{}, r.runner.RecordRejected(ctx, ScopeOrg, spec, disabled())
	}
	var out pgstore.RevocationRequest
	err := r.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		req, err := r.openRequest(ctx, q, rec, id, confirmHostname)
		if err != nil {
			return err
		}
		p, _ := principal.From(ctx)
		switch {
		case status == revocation.StatusRejected && req.Status != revocation.StatusRequested:
			return problem.InvalidState.WithDetail("only a request that waits for its second approval can be rejected")
		case status == revocation.StatusCancelled && (!req.RequestedBy.Valid || req.RequestedBy.UUID != p.ID):
			return problem.Forbidden.WithDetail("only the requester can cancel a request")
		}
		out, err = q.CloseRevocationRequest(ctx, pgstore.CloseRevocationRequestParams{ID: id, Status: status, FinishedAt: r.now().UTC()})
		if db.IsNoRows(err) {
			return problem.InvalidState.WithDetail("the request was issued or closed already")
		}
		return err
	})
	return out, err
}

// RevocationQuery selects a page of revocation requests.
type RevocationQuery struct {
	Page     ListPage
	Statuses []string
	Actions  []string
	DeviceID *uuid.UUID
}

// RevocationItem is a request with its device's hostname, the requester's username and its approvals (never their
// step-up tokens).
type RevocationItem struct {
	Request             pgstore.RevocationRequest
	Hostname            string
	RequestedByUsername string
	Approvals           []pgstore.ListRevocationApprovalsRow
}

// Get returns one request of the organization (organization administrators); an unknown or foreign request is
// not_found.
func (r *Revocations) Get(ctx context.Context, id uuid.UUID) (RevocationItem, error) {
	var out RevocationItem
	if _, err := RequireOrg(ctx, RolesAdmin); err != nil {
		return out, err
	}
	err := r.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		row, err := q.GetRevocationRequestRow(ctx, id)
		if err != nil {
			return notFound(err)
		}
		out = RevocationItem{Request: row.RevocationRequest, Hostname: row.Hostname, RequestedByUsername: row.RequestedByUsername}
		out.Approvals, err = q.ListRevocationApprovals(ctx, []uuid.UUID{id})
		return err
	})
	return out, err
}

// List returns one page of the organization's revocation requests (organization administrators).
func (r *Revocations) List(ctx context.Context, query RevocationQuery) (Listed[RevocationItem], error) {
	var out Listed[RevocationItem]
	if _, err := RequireOrg(ctx, RolesAdmin); err != nil {
		return out, err
	}
	err := r.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var dev uuid.NullUUID
		if query.DeviceID != nil {
			dev = uuid.NullUUID{UUID: *query.DeviceID, Valid: true}
		}
		statuses, actions := nilIfEmpty(query.Statuses), nilIfEmpty(query.Actions)
		n, err := q.CountRevocationRequests(ctx, pgstore.CountRevocationRequestsParams{
			QPattern: query.Page.QPattern, Statuses: statuses, Actions: actions, DeviceID: dev, CountLimit: countLimit,
		})
		if err != nil {
			return fmt.Errorf("count revocation requests: %w", err)
		}
		out.Count = int(n)
		rows, err := q.ListRevocationRequests(ctx, pgstore.ListRevocationRequestsParams{
			QPattern: query.Page.QPattern, Statuses: statuses, Actions: actions, DeviceID: dev,
			Sort: query.Page.Sort, SkipRows: query.Page.Offset, MaxRows: query.Page.Limit,
		})
		if err != nil {
			return fmt.Errorf("list revocation requests: %w", err)
		}
		ids := make([]uuid.UUID, len(rows))
		for i, row := range rows {
			ids[i] = row.RevocationRequest.ID
		}
		approvals, err := q.ListRevocationApprovals(ctx, ids)
		if err != nil {
			return fmt.Errorf("list approvals: %w", err)
		}
		out.Items = make([]RevocationItem, len(rows))
		for i, row := range rows {
			out.Items[i] = RevocationItem{Request: row.RevocationRequest, Hostname: row.Hostname, RequestedByUsername: row.RequestedByUsername}
			for _, a := range approvals {
				if a.RequestID == row.RevocationRequest.ID {
					out.Items[i].Approvals = append(out.Items[i].Approvals, a)
				}
			}
		}
		return nil
	})
	return out, err
}

// confirmedDevice loads the device, records it as target and checks the typed hostname.
func (r *Revocations) confirmedDevice(ctx context.Context, q *pgstore.Queries, rec Recorder, id uuid.UUID, confirmHostname string) (pgstore.Device, error) {
	dev, err := q.GetDevice(ctx, id)
	if err != nil {
		return dev, notFound(err)
	}
	rec.SetTarget(audit.Target{Type: "device", ID: id.String(), Display: dev.Hostname})
	rec.SetParam("hostname", dev.Hostname)
	if confirmHostname != dev.Hostname {
		return dev, problem.InvalidRequest.WithDetail("confirm_hostname does not match the device's hostname")
	}
	return dev, nil
}

// openRequest loads a request for update with its device, records both and checks the typed hostname.
func (r *Revocations) openRequest(ctx context.Context, q *pgstore.Queries, rec Recorder, id uuid.UUID, confirmHostname string) (pgstore.RevocationRequest, error) {
	req, err := q.GetRevocationRequestForUpdate(ctx, id)
	if err != nil {
		return req, notFound(err)
	}
	rec.SetParam("action", req.Action)
	if _, err := r.confirmedDevice(ctx, q, rec, req.DeviceID, confirmHostname); err != nil {
		return req, err
	}
	return req, nil
}

// stepUpToken returns the raw step-up ID token of the session and its jti. The caller must not be frozen, and each
// token approves at most one request (plan M4c decision 8).
func (r *Revocations) stepUpToken(ctx context.Context, q *pgstore.Queries, p principal.Principal) (string, string, error) {
	until, err := q.ActiveRevocationFreeze(ctx, pgstore.ActiveRevocationFreezeParams{AdminID: p.ID, Now: r.now()})
	if err != nil && !db.IsNoRows(err) {
		return "", "", err
	}
	if err == nil {
		return "", "", problem.RevocationFrozen.WithDetail("your revocations are frozen until " + until.UTC().Format(time.RFC3339) +
			" because a revocation limit was exceeded")
	}
	if p.StepUpJTI == "" {
		return "", "", problem.StepUpRequired
	}
	used, err := q.StepUpUsedForRevocation(ctx, p.StepUpJTI)
	if err != nil {
		return "", "", err
	}
	if used {
		return "", "", problem.StepUpRequired.WithDetail("each revocation approval needs a new step-up authentication")
	}
	raw, ok, err := r.tokens.Get(ctx, p.StepUpJTI)
	if err != nil {
		slog.ErrorContext(ctx, "reading the step-up token failed", "error", err)
		return "", "", problem.UpstreamUnavailable.WithDetail("the step-up proof could not be read")
	}
	if !ok {
		return "", "", problem.StepUpRequired.WithDetail("the step-up proof expired; authenticate again")
	}
	return raw, p.StepUpJTI, nil
}

func disabled() error {
	return problem.RevocationDisabled.WithDetail("revocation is not enabled on this installation (pending acceptance)")
}

// RevocationReports are the worker's use cases of issued revocation tokens, which travel like device commands
// (cmd:<device_id>, /v1/commands/{id}/result): the device's confirmation and the expiry (plan M4c decision 10).
type RevocationReports struct {
	runner *ActionRunner
	org    *db.OrgPool
}

// NewRevocationReports creates the use cases.
func NewRevocationReports(runner *ActionRunner, org *db.OrgPool) *RevocationReports {
	return &RevocationReports{runner: runner, org: org}
}

// Finish records the result of a revocation token: confirmed when the device reports success, failed otherwise
// (audited once: device.revocation_confirmed, actor the device). It reports false when the result belongs to no
// open revocation (a device command, or a duplicate).
func (r *RevocationReports) Finish(ctx context.Context, res ingest.CommandResult) (bool, error) {
	// A malformed result is recorded as it is, with zero values in the audit event.
	c := revocation.ParseConfirmation(res.Result)
	status := revocation.StatusConfirmed
	if res.Status != protocol.CommandSucceeded {
		status = revocation.StatusFailed
	}
	result := res.Result
	if len(result) == 0 {
		result = json.RawMessage(`{}`)
	}
	spec := ActionSpec{
		Code:   audit.CodeDeviceRevocationConfirmed,
		Actor:  &audit.Actor{Type: audit.ActorDevice, ID: res.DeviceID.String()},
		Target: &audit.Target{Type: "device", ID: res.DeviceID.String()},
		Params: map[string]any{"request_id": res.CommandID.String(), "status": res.Status, "erased": c.AllErased(),
			"slots_before": c.SlotsBefore, "slots_after": c.SlotsAfter, "volumes": len(c.Volumes),
			"unresolved": len(c.Unresolved), "skipped_not_escrowed": len(c.SkippedNotEscrowed),
			"shared_uuid": len(c.SharedUUID)},
	}
	open := false
	if err := r.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		req, err := q.GetRevocationRequest(ctx, res.CommandID)
		if db.IsNoRows(err) {
			return nil
		}
		open = err == nil && req.DeviceID == res.DeviceID &&
			(req.Status == revocation.StatusIssued || req.Status == revocation.StatusDelivered)
		spec.Params["action"] = req.Action
		return err
	}); err != nil || !open {
		return false, err
	}
	err := r.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, _ Recorder) error {
		_, err := q.FinishRevocation(ctx, pgstore.FinishRevocationParams{
			ID: res.CommandID, DeviceID: res.DeviceID, Status: status, Result: result, ConfirmedAt: res.ReceivedAt,
		})
		return err
	})
	return err == nil, err
}

// Expire marks the issued tokens of the context's organization whose lifetime ended at now as expired and returns
// them; the device would refuse them anyway (plan M4c decision 10).
func (r *RevocationReports) Expire(ctx context.Context, now time.Time) ([]pgstore.ExpireRevocationsRow, error) {
	var out []pgstore.ExpireRevocationsRow
	err := r.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		out, err = q.ExpireRevocations(ctx, now)
		return err
	})
	return out, err
}
