package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/software"
	"github.com/phischl/paddock-mdm/server/internal/domain/statechange"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Specs of the decisions on software requests (plan M13c decision 9): organization administrators only, without a
// step-up of their own, because trusting the entry's source needed one (architect-lead decision Q15).
var (
	SpecSoftwareRequestApprove = ActionSpec{Code: audit.CodeSoftwareRequestApproved, AllowedRoles: RolesAdmin}
	SpecSoftwareRequestDeny    = ActionSpec{Code: audit.CodeSoftwareRequestDenied, AllowedRoles: RolesAdmin}
)

// SoftwareRequest is a software request as the API shows it, with its entry's name and approval and the device's
// hostname.
type SoftwareRequest = pgstore.GetSoftwareRequestRow

// SoftwareRequests are the use cases of the organization's software requests (plan M13c decisions 8 to 10): the list
// and the decisions of the administrators, and the worker's expiry.
type SoftwareRequests struct {
	runner *ActionRunner
	org    *db.OrgPool
	now    func() time.Time
}

// NewSoftwareRequests creates the use cases.
func NewSoftwareRequests(runner *ActionRunner, org *db.OrgPool) *SoftwareRequests {
	return &SoftwareRequests{runner: runner, org: org, now: time.Now}
}

// SoftwareRequestQuery selects a page of software requests; q matches the user name.
type SoftwareRequestQuery struct {
	Page           ListPage
	States         []string
	CatalogEntryID *uuid.UUID
	DeviceID       *uuid.UUID
}

// List returns one page of software requests.
func (s *SoftwareRequests) List(ctx context.Context, query SoftwareRequestQuery) (Listed[SoftwareRequest], error) {
	var out Listed[SoftwareRequest]
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		states := nilIfEmpty(query.States)
		n, err := q.CountSoftwareRequests(ctx, pgstore.CountSoftwareRequestsParams{
			QPattern: query.Page.QPattern, States: states, CatalogEntryID: nullID(query.CatalogEntryID),
			DeviceID: nullID(query.DeviceID), CountLimit: countLimit,
		})
		if err != nil {
			return fmt.Errorf("count software requests: %w", err)
		}
		out.Count = int(n)
		rows, err := q.ListSoftwareRequests(ctx, pgstore.ListSoftwareRequestsParams{
			QPattern: query.Page.QPattern, States: states, CatalogEntryID: nullID(query.CatalogEntryID),
			DeviceID: nullID(query.DeviceID), Sort: query.Page.Sort, SkipRows: query.Page.Offset, MaxRows: query.Page.Limit,
		})
		for _, r := range rows {
			out.Items = append(out.Items, SoftwareRequest(r))
		}
		return err
	})
	return out, err
}

// Get returns one software request; another organization's is not found.
func (s *SoftwareRequests) Get(ctx context.Context, id uuid.UUID) (SoftwareRequest, error) {
	var out SoftwareRequest
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		out, err = q.GetSoftwareRequest(ctx, id)
		return notFound(err)
	})
	return out, err
}

// Approve approves an open request with an optional reason (audited: software_request.approved). The compiler renders
// the user into the approved users of the device's next bundle, after the rollout overlay like every other software
// change, so an approval never reaches a device by another way.
func (s *SoftwareRequests) Approve(ctx context.Context, id uuid.UUID, reason string) (SoftwareRequest, error) {
	return s.decide(ctx, SpecSoftwareRequestApprove, id, software.RequestApproved, reason)
}

// Deny denies an open request with a reason, which is required (audited: software_request.denied). The user may ask
// again after software.RerequestAfterDenial; until then the compiler renders the denial with its reason into the
// device's bundle (architect decision A10-27).
func (s *SoftwareRequests) Deny(ctx context.Context, id uuid.UUID, reason string) (SoftwareRequest, error) {
	return s.decide(ctx, SpecSoftwareRequestDeny, id, software.RequestDenied, reason)
}

func (s *SoftwareRequests) decide(ctx context.Context, spec ActionSpec, id uuid.UUID, state, reason string) (SoftwareRequest, error) {
	var out SoftwareRequest
	reason = software.NormalizeDecisionReason(reason)
	spec.Target = &audit.Target{Type: "software_request", ID: id.String()}
	spec.Params = map[string]any{"reason": software.DisplayParam(reason, software.MaxReasonLength)}
	err := s.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		locked, err := q.GetSoftwareRequestForUpdate(ctx, id)
		if err != nil {
			return notFound(err)
		}
		cur, err := q.GetSoftwareRequest(ctx, id)
		if err != nil {
			return notFound(err)
		}
		for k, v := range requestParams(cur) {
			rec.SetParam(k, v)
		}
		if err := software.ValidateDecisionReason(reason, state == software.RequestDenied); err != nil {
			return problem.InvalidRequest.WithDetail(err.Error())
		}
		if cur.State != software.RequestRequested {
			return problem.InvalidState.WithDetail("the request is " + cur.State + ", not open")
		}
		now := s.now()
		// The expiry round may not have run yet: a request past its validity, or of an entry that no longer requires
		// approval or changed it since, is decided as the round would expire it, so no approval outlives either.
		if !now.Before(locked.ExpiresAt) {
			return problem.InvalidState.WithDetail("the request's validity ended")
		}
		if cur.EntryApproval != software.ApprovalRequired || !locked.Current {
			return problem.InvalidState.WithDetail("the entry no longer requires approval as it did when the request was opened")
		}
		p, _ := principal.From(ctx)
		decidedBy := software.DisplayParam(p.Display, 256)
		var why *string
		if reason != "" {
			why = &reason
		}
		n, err := q.DecideSoftwareRequest(ctx, pgstore.DecideSoftwareRequestParams{
			ID: id, State: state, DecidedBy: &decidedBy, DecidedAt: &now, DecisionReason: why,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return problem.InvalidState.WithDetail("the request is no longer open")
		}
		// A denial recompiles the device too: its bundle names the denial with the reason while the re-request lock
		// holds (architect decision A10-27).
		rec.StateChanged(statechange.ScopeDevice, cur.DeviceID)
		out, err = q.GetSoftwareRequest(ctx, id)
		return err
	})
	return out, err
}

// requestParams are the audit params that name a request: its entry, device and user.
func requestParams(r SoftwareRequest) map[string]any {
	return map[string]any{
		"catalog_entry_id": r.CatalogEntryID.String(), "app": software.DisplayParam(r.EntryName, software.MaxNameLength),
		"device_id": r.DeviceID.String(), "hostname": r.Hostname, "user": r.Username,
	}
}

// expireBatch bounds the requests one expiry pass handles per organization; the next round takes the rest.
const expireBatch = 500

// Expire expires the context's organization's open requests whose validity ended at now (system principal, plan M13c
// §3.7), and its open and approved requests whose entry no longer requires approval or changed its approval since
// (§3.8 L4) or that no available assignment of the entry offers to the device and user any longer, so the approval no
// longer holds (architect decision A10-17); each with one software_request.expired event. A request a decision or
// another replica ended first, or whose cause no longer holds, is skipped. It returns the number of expired requests.
func (s *SoftwareRequests) Expire(ctx context.Context, now time.Time) (int, error) {
	if p, ok := principal.From(ctx); !ok || p.Kind != principal.KindSystem {
		return 0, problem.Unauthenticated
	}
	var due []pgstore.ListSoftwareRequestsToExpireRow
	if err := s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		due, err = q.ListSoftwareRequestsToExpire(ctx, pgstore.ListSoftwareRequestsToExpireParams{Now: now, MaxRows: expireBatch})
		return err
	}); err != nil {
		return 0, fmt.Errorf("list software requests to expire: %w", err)
	}
	expired := 0
	var errs []error
	for _, r := range due {
		spec := ActionSpec{
			Code:   audit.CodeSoftwareRequestExpired,
			Target: &audit.Target{Type: "software_request", ID: r.ID.String()},
			Params: map[string]any{"catalog_entry_id": r.CatalogEntryID.String(), "device_id": r.DeviceID.String(),
				"user": r.Username, "cause": r.Cause},
		}
		done, err := s.runner.RecordOnceInScope(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, _ Recorder) (bool, error) {
			n, err := q.ExpireSoftwareRequest(ctx, pgstore.ExpireSoftwareRequestParams{ID: r.ID, DecidedAt: &now, Now: now,
				Cause: r.Cause})
			return n == 1, err
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("expire software request %s: %w", r.ID, err))
			continue
		}
		if done {
			expired++
		}
	}
	return expired, errors.Join(errs...)
}

// openedRequest is the request a device's software.request opened, for its software_request.opened event.
type openedRequest struct {
	spec ActionSpec
}

// openSoftwareRequest opens the request a software.request event of the device reports, received at receivedAt (plan
// M13c decision 9), in the transaction of its claim: one per device, entry and user while it is open, with the user's
// justification as untrusted plain text (maintainer answer Q7). It opens none — and returns nil — for malformed data,
// a justification that fails software.ValidJustification, an entry that is not the organization's or does not require approval, an
// entry no available assignment offers to the user on the device (architect decision A10-17), a user who holds an
// approval of it on the device already, a repeat while the request is open, or a request within
// software.RerequestAfterDenial of a denial (§3.7).
func openSoftwareRequest(ctx context.Context, q *pgstore.Queries, org, deviceID uuid.UUID, data json.RawMessage,
	receivedAt time.Time) (*openedRequest, error) {
	var ev protocol.SoftwareRequest
	if json.Unmarshal(data, &ev) != nil || !software.ValidRequestUsername(ev.User) || !software.ValidJustification(ev.Justification) {
		return nil, nil
	}
	entry, err := uuid.Parse(ev.EntryID)
	if err != nil {
		return nil, nil //nolint:nilerr // a malformed entry ID opens nothing; the event itself is still recorded
	}
	approval, err := q.GetSoftwareCatalogEntryApproval(ctx, entry)
	if db.IsNoRows(err) || err == nil && approval.Approval != software.ApprovalRequired {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	offered, err := q.SoftwareRequestOffered(ctx, pgstore.SoftwareRequestOfferedParams{
		CatalogEntryID: entry, DeviceID: deviceID, Username: ev.User,
	})
	if err != nil || !offered {
		return nil, err
	}
	// A second request beside an approval could be denied while the approval still holds.
	holds, err := q.SoftwareRequestApprovalHolds(ctx, pgstore.SoftwareRequestApprovalHoldsParams{
		DeviceID: deviceID, CatalogEntryID: entry, Username: ev.User,
	})
	if err != nil || holds {
		return nil, err
	}
	denied, err := q.LastSoftwareRequestDenial(ctx, pgstore.LastSoftwareRequestDenialParams{
		DeviceID: deviceID, CatalogEntryID: entry, Username: ev.User,
	})
	switch {
	case err == nil && receivedAt.Before(denied.Add(software.RerequestAfterDenial)):
		return nil, nil
	case err != nil && !db.IsNoRows(err):
		return nil, err
	}
	user, err := q.GetUserIDByUsername(ctx, ev.User)
	if err != nil && !db.IsNoRows(err) {
		return nil, err
	}
	id := uuid.Must(uuid.NewV7())
	expires := receivedAt.Add(software.RequestValidity)
	n, err := q.InsertSoftwareRequest(ctx, pgstore.InsertSoftwareRequestParams{
		ID: id, OrganizationID: org, CatalogEntryID: entry, DeviceID: deviceID,
		UserID: uuid.NullUUID{UUID: user, Valid: user != uuid.Nil}, Username: ev.User, RequestedAt: receivedAt, ExpiresAt: expires,
		ApprovalEpoch: approval.ApprovalEpoch, Justification: ev.Justification,
	})
	if err != nil || n != 1 {
		return nil, err
	}
	row, err := q.GetSoftwareRequest(ctx, id)
	if err != nil {
		return nil, err
	}
	params := requestParams(row)
	params["expires_at"] = expires.UTC().Format(time.RFC3339)
	return &openedRequest{spec: ActionSpec{
		Code: audit.CodeSoftwareRequestOpened, Target: &audit.Target{Type: "software_request", ID: id.String()}, Params: params,
	}}, nil
}

// withdrawSoftwareRequest closes the open request a software.request_withdrawn event of the device reports, received
// at receivedAt (PDK-811b), in the transaction of its claim. Malformed data, or no open request of that device, entry
// and user (an administrator decided it or it expired first), changes nothing. No event of its own is recorded: the
// device's device.software_request_withdrawn is the one audit event of the withdrawal.
func withdrawSoftwareRequest(ctx context.Context, q *pgstore.Queries, deviceID uuid.UUID, data json.RawMessage, receivedAt time.Time) error {
	var ev protocol.SoftwareRequestWithdrawn
	if json.Unmarshal(data, &ev) != nil || !software.ValidRequestUsername(ev.User) {
		return nil
	}
	entry, err := uuid.Parse(ev.EntryID)
	if err != nil {
		return nil //nolint:nilerr // a malformed entry ID closes nothing; the event itself is still recorded
	}
	_, err = q.WithdrawSoftwareRequest(ctx, pgstore.WithdrawSoftwareRequestParams{
		DecidedAt: &receivedAt, DeviceID: deviceID, CatalogEntryID: entry, Username: ev.User,
	})
	return err
}

// softwareRequestEntry adds to the once-entry of a software.request event the opening of its request and, when it
// opened one, the software_request.opened event in the same transaction; to that of a software.request_withdrawn event
// the closing of the open request. Every other entry is returned unchanged.
func (d *DeviceReports) softwareRequestEntry(entry OnceEntry, deviceID uuid.UUID, ev protocol.Event, receivedAt time.Time) OnceEntry {
	code, ok := map[string]audit.Code{
		protocol.EventSoftwareRequest:          audit.CodeDeviceSoftwareRequested,
		protocol.EventSoftwareRequestWithdrawn: audit.CodeDeviceSoftwareRequestWithdrawn,
	}[ev.Type]
	if !ok {
		return entry
	}
	// Only the documented fields: whatever else a device sends, such as the justification, never reaches the audit log;
	// openSoftwareRequest stores the justification in the request alone (maintainer answer Q7).
	def, _ := audit.Lookup(code)
	maps.DeleteFunc(entry.Spec.Params, func(k string, _ any) bool { return !slices.Contains(def.Params, k) })
	if ev.Type == protocol.EventSoftwareRequestWithdrawn {
		claim := entry.Claim
		entry.Claim = func(ctx context.Context, q *pgstore.Queries) (bool, error) {
			fresh, err := claim(ctx, q)
			if err != nil || !fresh {
				return fresh, err
			}
			return true, withdrawSoftwareRequest(ctx, q, deviceID, ev.Data, receivedAt)
		}
		return entry
	}
	claim := entry.Claim
	var opened *openedRequest
	entry.Claim = func(ctx context.Context, q *pgstore.Queries) (bool, error) {
		opened = nil
		fresh, err := claim(ctx, q)
		if err != nil || !fresh {
			return fresh, err
		}
		org, err := orgOf(ctx)
		if err != nil {
			return false, err
		}
		opened, err = openSoftwareRequest(ctx, q, org, deviceID, ev.Data, receivedAt)
		return true, err
	}
	entry.After = func(ctx context.Context, q *pgstore.Queries, _ uuid.UUID) error {
		if opened == nil {
			return nil
		}
		return d.runner.recordInTx(ctx, q, opened.spec)
	}
	return entry
}
