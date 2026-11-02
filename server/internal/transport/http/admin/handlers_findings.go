package admin

import (
	"context"
	"fmt"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/finding"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/listing"
)

// findingRecordList is the list definition of GET /api/v1/findings (plan M9 decision 34); findingList is the one of
// a device's vulnerability findings.
var findingRecordList = listing.Spec{Sort: []string{"last_seen_at", "opened_at", "status", "hostname", "code"}, DefaultSort: "-last_seen_at"}

func toFindingRecord(f app.FindingItem) adminapi.Finding {
	out := adminapi.Finding{
		Id: f.ID, Kind: adminapi.FindingKind(f.Kind), Key: f.Key, Code: f.Code, Subject: f.Subject, DeviceId: f.DeviceID,
		Hostname: f.Hostname, Status: adminapi.FindingStatus(f.Status), OpenedAt: f.OpenedAt.UTC(),
		LastSeenAt: f.LastSeenAt.UTC(), Occurrences: f.Occurrences, FirstEventId: f.FirstEventID, LastEventId: f.LastEventID,
		AcknowledgedAt: utcPtr(f.AcknowledgedAt), ClosedAt: utcPtr(f.ClosedAt), ClosedBy: f.ClosedBy, Reason: f.Reason,
		ExternalRef: f.ExternalRef, ClearedAt: utcPtr(f.ClearedAt),
	}
	if f.Assignee != nil {
		out.Assignee = &adminapi.FindingAssignee{Id: f.Assignee.ID, Username: f.Assignee.Username, DisplayName: f.Assignee.DisplayName}
	}
	return out
}

func (h *handlers) ListFindings(ctx context.Context, req adminapi.ListFindingsRequestObject) (adminapi.ListFindingsResponseObject, error) {
	params, err := listing.Parse(findingRecordList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	statuses, err := listing.Enum("status", req.Params.Status)
	if err != nil {
		return nil, err
	}
	query := app.FindingQuery{
		Page: params.ListPage(), Statuses: statuses, DeviceID: req.Params.DeviceId, AssigneeID: req.Params.AssigneeId,
		Cleared: req.Params.Cleared != nil && *req.Params.Cleared,
	}
	if k := req.Params.Kind; k != nil {
		if !k.Valid() {
			return nil, problem.InvalidRequest.WithDetail(fmt.Sprintf("unknown kind %q", string(*k)))
		}
		kind := string(*k)
		query.Kind = &kind
	}
	res, err := h.findings.List(ctx, query)
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.Finding, len(res.Items))
	for i, f := range res.Items {
		items[i] = toFindingRecord(f)
	}
	return adminapi.ListFindings200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func (h *handlers) GetFinding(ctx context.Context, req adminapi.GetFindingRequestObject) (adminapi.GetFindingResponseObject, error) {
	f, err := h.findings.Get(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.GetFinding200JSONResponse(toFindingRecord(f)), nil
}

func (h *handlers) AcknowledgeFinding(ctx context.Context, req adminapi.AcknowledgeFindingRequestObject) (adminapi.AcknowledgeFindingResponseObject, error) {
	f, err := h.findings.Acknowledge(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.AcknowledgeFinding200JSONResponse(toFindingRecord(f)), nil
}

func (h *handlers) AssignFinding(ctx context.Context, req adminapi.AssignFindingRequestObject) (adminapi.AssignFindingResponseObject, error) {
	f, err := h.findings.Assign(ctx, req.Id, req.Body.AssigneeId)
	if err != nil {
		return nil, err
	}
	return adminapi.AssignFinding200JSONResponse(toFindingRecord(f)), nil
}

func (h *handlers) CloseFinding(ctx context.Context, req adminapi.CloseFindingRequestObject) (adminapi.CloseFindingResponseObject, error) {
	externalRef := ""
	if req.Body.ExternalRef != nil {
		externalRef = *req.Body.ExternalRef
	}
	f, err := h.findings.Close(ctx, req.Id, finding.Status(req.Body.Resolution), req.Body.Reason, externalRef)
	if err != nil {
		return nil, err
	}
	return adminapi.CloseFinding200JSONResponse(toFindingRecord(f)), nil
}

func (h *handlers) ReopenFinding(ctx context.Context, req adminapi.ReopenFindingRequestObject) (adminapi.ReopenFindingResponseObject, error) {
	f, err := h.findings.Reopen(ctx, req.Id, req.Body.Reason)
	if err != nil {
		return nil, err
	}
	return adminapi.ReopenFinding200JSONResponse(toFindingRecord(f)), nil
}
