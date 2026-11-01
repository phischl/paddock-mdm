package admin

import (
	"context"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/outbound"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/listing"
)

// notificationDestinationList is the list definition of both destination collections (plan M9 §6.5).
var notificationDestinationList = listing.Spec{Sort: []string{"name", "type", "created_at"}, DefaultSort: "name"}

func toNotificationDestination(d app.NotificationDestination) adminapi.NotificationDestination {
	s := d.State
	out := adminapi.NotificationDestination{
		Id: d.ID, Type: adminapi.NotificationDestinationType(d.Type), Name: d.Name, Enabled: d.Enabled,
		FilterMode: adminapi.NotificationFilterMode(d.FilterMode), Codes: d.Codes, PseudonymizeUsers: d.PseudonymizeUsers,
		IncludeParams: d.IncludeParams, UrlDisplay: d.URLDisplay, HeartbeatIntervalS: d.HeartbeatIntervalS,
		Recipients: d.Recipients, EmailMinIntervalS: d.EmailMinIntervalS, CreatedBy: d.CreatedBy,
		CreatedAt: d.CreatedAt.UTC(), UpdatedAt: d.UpdatedAt.UTC(),
		State: adminapi.NotificationDestinationState{
			Status: adminapi.NotificationDestinationStateStatus(s.Status), CursorCommitSeq: s.CursorCommitSeq,
			ForwardSeq: s.ForwardSeq, LastSuccessAt: utcPtr(s.LastSuccessAt), LastAttemptAt: utcPtr(s.LastAttemptAt),
			NextAttemptAt: utcPtr(s.NextAttemptAt), StalledSince: utcPtr(s.StalledSince), LastError: s.LastError,
			LagSeconds: s.LagSeconds,
		},
	}
	if t := s.LastTest; t != nil {
		out.State.LastTest = &struct {
			At    time.Time `json:"at"`
			Error *string   `json:"error"`
			Ok    bool      `json:"ok"`
		}{At: t.At.UTC(), Error: t.Error, Ok: t.OK}
	}
	return out
}

func toNotificationCreated(d app.NotificationDestination, secret string) adminapi.NotificationDestinationCreated {
	v := toNotificationDestination(d)
	out := adminapi.NotificationDestinationCreated{
		Id: v.Id, Type: v.Type, Name: v.Name, Enabled: v.Enabled, FilterMode: v.FilterMode, Codes: v.Codes,
		PseudonymizeUsers: v.PseudonymizeUsers, IncludeParams: v.IncludeParams, UrlDisplay: v.UrlDisplay,
		HeartbeatIntervalS: v.HeartbeatIntervalS, Recipients: v.Recipients, EmailMinIntervalS: v.EmailMinIntervalS,
		CreatedBy: v.CreatedBy, CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt, State: v.State,
	}
	if secret != "" {
		out.Secret = &secret
	}
	return out
}

func notificationCreateInput(b *adminapi.NotificationDestinationCreate) app.NotificationDestinationInput {
	return app.NotificationDestinationInput{
		Type: outbound.Type(b.Type), Name: b.Name, Enabled: b.Enabled, FilterMode: outbound.FilterMode(b.FilterMode),
		Codes: deref(b.Codes, nil), PseudonymizeUsers: deref(b.PseudonymizeUsers, false), IncludeParams: deref(b.IncludeParams, false),
		URL: b.Url, HeartbeatIntervalS: deref(b.HeartbeatIntervalS, 0), Recipients: deref(b.Recipients, nil),
		EmailMinIntervalS: deref(b.EmailMinIntervalS, 0),
	}
}

func notificationUpdateInput(b *adminapi.NotificationDestinationUpdate) app.NotificationDestinationInput {
	in := app.NotificationDestinationInput{
		Name: b.Name, Enabled: b.Enabled, FilterMode: outbound.FilterMode(b.FilterMode), Codes: deref(b.Codes, nil),
		PseudonymizeUsers: deref(b.PseudonymizeUsers, false), IncludeParams: deref(b.IncludeParams, false), URL: b.Url,
		HeartbeatIntervalS: deref(b.HeartbeatIntervalS, 0), Recipients: deref(b.Recipients, nil),
		EmailMinIntervalS: deref(b.EmailMinIntervalS, 0),
	}
	if b.Type != nil {
		in.Type = outbound.Type(*b.Type)
	}
	if b.Cursor != nil {
		in.Cursor = string(*b.Cursor)
	}
	return in
}

func (h *handlers) listNotificationDestinations(ctx context.Context, scope app.Scope, q listing.Query,
	types *[]adminapi.NotificationDestinationType, enabled *bool) (adminapi.NotificationDestinationPage, error) {
	params, err := listing.Parse(notificationDestinationList, q)
	if err != nil {
		return adminapi.NotificationDestinationPage{}, err
	}
	typeFilter, err := listing.Enum("type", types)
	if err != nil {
		return adminapi.NotificationDestinationPage{}, err
	}
	res, err := h.notifications.List(ctx, scope, app.NotificationQuery{Page: params.ListPage(), Types: typeFilter, Enabled: enabled})
	if err != nil {
		return adminapi.NotificationDestinationPage{}, err
	}
	items := make([]adminapi.NotificationDestination, len(res.Items))
	for i, d := range res.Items {
		items[i] = toNotificationDestination(d)
	}
	return adminapi.NotificationDestinationPage(listing.NewPage(items, params, res.Count)), nil
}

func (h *handlers) createNotificationDestination(ctx context.Context, scope app.Scope, base string,
	b *adminapi.NotificationDestinationCreate) (adminapi.NotificationDestinationCreated, string, error) {
	d, secret, err := h.notifications.Create(ctx, scope, notificationCreateInput(b))
	if err != nil {
		return adminapi.NotificationDestinationCreated{}, "", err
	}
	return toNotificationCreated(d, secret), base + "/" + d.ID.String(), nil
}

// Organization scope.

func (h *handlers) ListNotificationDestinations(ctx context.Context, req adminapi.ListNotificationDestinationsRequestObject) (adminapi.ListNotificationDestinationsResponseObject, error) {
	page, err := h.listNotificationDestinations(ctx, app.ScopeOrg, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	}, req.Params.Type, req.Params.Enabled)
	if err != nil {
		return nil, err
	}
	return adminapi.ListNotificationDestinations200JSONResponse(page), nil
}

func (h *handlers) CreateNotificationDestination(ctx context.Context, req adminapi.CreateNotificationDestinationRequestObject) (adminapi.CreateNotificationDestinationResponseObject, error) {
	body, loc, err := h.createNotificationDestination(ctx, app.ScopeOrg, "/api/v1/notification-destinations", req.Body)
	if err != nil {
		return nil, err
	}
	return adminapi.CreateNotificationDestination201JSONResponse{
		Body: body, Headers: adminapi.CreateNotificationDestination201ResponseHeaders{Location: &loc},
	}, nil
}

func (h *handlers) GetNotificationDestination(ctx context.Context, req adminapi.GetNotificationDestinationRequestObject) (adminapi.GetNotificationDestinationResponseObject, error) {
	d, err := h.notifications.Get(ctx, app.ScopeOrg, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.GetNotificationDestination200JSONResponse(toNotificationDestination(d)), nil
}

func (h *handlers) UpdateNotificationDestination(ctx context.Context, req adminapi.UpdateNotificationDestinationRequestObject) (adminapi.UpdateNotificationDestinationResponseObject, error) {
	d, err := h.notifications.Update(ctx, app.ScopeOrg, req.Id, notificationUpdateInput(req.Body))
	if err != nil {
		return nil, err
	}
	return adminapi.UpdateNotificationDestination200JSONResponse(toNotificationDestination(d)), nil
}

func (h *handlers) DeleteNotificationDestination(ctx context.Context, req adminapi.DeleteNotificationDestinationRequestObject) (adminapi.DeleteNotificationDestinationResponseObject, error) {
	if err := h.notifications.Delete(ctx, app.ScopeOrg, req.Id); err != nil {
		return nil, err
	}
	return adminapi.DeleteNotificationDestination204Response{}, nil
}

func (h *handlers) RotateNotificationDestinationSecret(ctx context.Context, req adminapi.RotateNotificationDestinationSecretRequestObject) (adminapi.RotateNotificationDestinationSecretResponseObject, error) {
	secret, err := h.notifications.RotateSecret(ctx, app.ScopeOrg, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.RotateNotificationDestinationSecret200JSONResponse{Secret: secret}, nil
}

func (h *handlers) TestNotificationDestination(ctx context.Context, req adminapi.TestNotificationDestinationRequestObject) (adminapi.TestNotificationDestinationResponseObject, error) {
	id, err := h.notifications.Test(ctx, app.ScopeOrg, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.TestNotificationDestination202JSONResponse{DeliveryId: id}, nil
}

func (h *handlers) ResolveNotificationPseudonym(ctx context.Context, req adminapi.ResolveNotificationPseudonymRequestObject) (adminapi.ResolveNotificationPseudonymResponseObject, error) {
	id, err := h.notifications.ResolvePseudonym(ctx, req.Id, req.Body.Pseudonym)
	if err != nil {
		return nil, err
	}
	return adminapi.ResolveNotificationPseudonym202JSONResponse{LookupId: id}, nil
}

func (h *handlers) GetNotificationPseudonymLookup(ctx context.Context, req adminapi.GetNotificationPseudonymLookupRequestObject) (adminapi.GetNotificationPseudonymLookupResponseObject, error) {
	l, err := h.notifications.PseudonymLookup(ctx, req.Id, req.LookupId)
	if err != nil {
		return nil, err
	}
	return adminapi.GetNotificationPseudonymLookup200JSONResponse{Pseudonym: l.Pseudonym, Username: l.Username, Resolved: l.Resolved}, nil
}

func (h *handlers) GetNotificationCapabilities(ctx context.Context, _ adminapi.GetNotificationCapabilitiesRequestObject) (adminapi.GetNotificationCapabilitiesResponseObject, error) {
	email, err := h.notifications.Capabilities(ctx)
	if err != nil {
		return nil, err
	}
	return adminapi.GetNotificationCapabilities200JSONResponse{Email: email}, nil
}

// Platform scope (nil organization).

func (h *handlers) ListPlatformNotificationDestinations(ctx context.Context, req adminapi.ListPlatformNotificationDestinationsRequestObject) (adminapi.ListPlatformNotificationDestinationsResponseObject, error) {
	page, err := h.listNotificationDestinations(ctx, app.ScopePlatform, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	}, req.Params.Type, req.Params.Enabled)
	if err != nil {
		return nil, err
	}
	return adminapi.ListPlatformNotificationDestinations200JSONResponse(page), nil
}

func (h *handlers) CreatePlatformNotificationDestination(ctx context.Context, req adminapi.CreatePlatformNotificationDestinationRequestObject) (adminapi.CreatePlatformNotificationDestinationResponseObject, error) {
	body, loc, err := h.createNotificationDestination(ctx, app.ScopePlatform, "/api/platform/v1/notification-destinations", req.Body)
	if err != nil {
		return nil, err
	}
	return adminapi.CreatePlatformNotificationDestination201JSONResponse{
		Body: body, Headers: adminapi.CreatePlatformNotificationDestination201ResponseHeaders{Location: &loc},
	}, nil
}

func (h *handlers) GetPlatformNotificationDestination(ctx context.Context, req adminapi.GetPlatformNotificationDestinationRequestObject) (adminapi.GetPlatformNotificationDestinationResponseObject, error) {
	d, err := h.notifications.Get(ctx, app.ScopePlatform, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.GetPlatformNotificationDestination200JSONResponse(toNotificationDestination(d)), nil
}

func (h *handlers) UpdatePlatformNotificationDestination(ctx context.Context, req adminapi.UpdatePlatformNotificationDestinationRequestObject) (adminapi.UpdatePlatformNotificationDestinationResponseObject, error) {
	d, err := h.notifications.Update(ctx, app.ScopePlatform, req.Id, notificationUpdateInput(req.Body))
	if err != nil {
		return nil, err
	}
	return adminapi.UpdatePlatformNotificationDestination200JSONResponse(toNotificationDestination(d)), nil
}

func (h *handlers) DeletePlatformNotificationDestination(ctx context.Context, req adminapi.DeletePlatformNotificationDestinationRequestObject) (adminapi.DeletePlatformNotificationDestinationResponseObject, error) {
	if err := h.notifications.Delete(ctx, app.ScopePlatform, req.Id); err != nil {
		return nil, err
	}
	return adminapi.DeletePlatformNotificationDestination204Response{}, nil
}

func (h *handlers) RotatePlatformNotificationDestinationSecret(ctx context.Context, req adminapi.RotatePlatformNotificationDestinationSecretRequestObject) (adminapi.RotatePlatformNotificationDestinationSecretResponseObject, error) {
	secret, err := h.notifications.RotateSecret(ctx, app.ScopePlatform, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.RotatePlatformNotificationDestinationSecret200JSONResponse{Secret: secret}, nil
}

func (h *handlers) TestPlatformNotificationDestination(ctx context.Context, req adminapi.TestPlatformNotificationDestinationRequestObject) (adminapi.TestPlatformNotificationDestinationResponseObject, error) {
	id, err := h.notifications.Test(ctx, app.ScopePlatform, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.TestPlatformNotificationDestination202JSONResponse{DeliveryId: id}, nil
}
