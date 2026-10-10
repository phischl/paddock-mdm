package admin

import (
	"context"
	"encoding/json"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/listing"
)

// attentionList is the list definition of GET /api/v1/attention (plan M5b decision 11).
var attentionList = listing.Spec{Sort: []string{"since", "kind", "hostname"}, DefaultSort: "-since"}

// attentionDeviceList is the list definition of GET /api/v1/attention/devices (plan M7c decision 27).
var attentionDeviceList = listing.Spec{Sort: []string{"severity", "hostname", "since"}, DefaultSort: "-severity"}

// attentionSeverities maps the rank of the grouped query to the API's severity.
var attentionSeverities = map[int32]adminapi.AttentionDeviceSeverity{0: adminapi.AttentionDeviceSeverityInfo, 1: adminapi.AttentionDeviceSeverityWarn, 2: adminapi.AttentionDeviceSeverityCritical}

func (h *handlers) ListAttention(ctx context.Context, req adminapi.ListAttentionRequestObject) (adminapi.ListAttentionResponseObject, error) {
	params, err := listing.Parse(attentionList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	kinds, err := listing.Enum("kind", req.Params.Kind)
	if err != nil {
		return nil, err
	}
	res, err := h.attention.List(ctx, app.AttentionQuery{Page: params.ListPage(), Kinds: kinds})
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.Attention, len(res.Items))
	for i, c := range res.Items {
		items[i] = adminapi.Attention{Id: c.ID, Kind: adminapi.AttentionKind(c.Kind), DeviceId: c.DeviceID, Hostname: c.Hostname,
			Since: c.Since.UTC(), Detail: c.Detail}
	}
	return adminapi.ListAttention200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func (h *handlers) ListAttentionDevices(ctx context.Context, req adminapi.ListAttentionDevicesRequestObject) (adminapi.ListAttentionDevicesResponseObject, error) {
	params, err := listing.Parse(attentionDeviceList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	kinds, err := listing.Enum("kind", req.Params.Kind)
	if err != nil {
		return nil, err
	}
	res, err := h.attention.ListDevices(ctx, app.AttentionDeviceQuery{Page: params.ListPage(), Kinds: kinds, DeviceID: req.Params.DeviceId})
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.AttentionDevice, len(res.Items))
	for i, d := range res.Items {
		items[i] = adminapi.AttentionDevice{
			DeviceId: d.DeviceID, Hostname: d.Hostname, State: adminapi.DeviceState(d.State), OsRelease: map[string]string{},
			LastContactAt: utcPtr(d.LastContactAt), Severity: attentionSeverities[d.Severity], Since: d.Since.UTC(),
			Conditions: []adminapi.AttentionCondition{},
		}
		_ = json.Unmarshal(d.OsRelease, &items[i].OsRelease) // written by the worker from a map[string]string
		if err := json.Unmarshal(d.Conditions, &items[i].Conditions); err != nil {
			return nil, err
		}
		for j := range items[i].Conditions {
			items[i].Conditions[j].Since = items[i].Conditions[j].Since.UTC()
		}
	}
	return adminapi.ListAttentionDevices200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}
