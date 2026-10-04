package admin

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/server/internal/adapters/postgres/pgstore"
	"github.com/paddock-mdm/paddock/server/internal/app"
	"github.com/paddock-mdm/paddock/server/internal/domain/enrollment"
	"github.com/paddock-mdm/paddock/server/internal/transport/http/admin/adminapi"
	"github.com/paddock-mdm/paddock/server/internal/transport/http/admin/listing"
)

// List definitions of the M2a collection endpoints; TestListSpecsMatchContract keeps them equal to x-paddock-list.
var (
	enrollmentTokenList = listing.Spec{Sort: []string{"name", "created_at", "expires_at"}, DefaultSort: "-created_at"}
	deviceList          = listing.Spec{Sort: []string{"hostname", "last_contact_at", "enrolled_at", "state"}, DefaultSort: "hostname"}
	managedFileList     = listing.Spec{Sort: []string{"path", "created_at", "updated_at"}, DefaultSort: "path"}
	managedUnitList     = listing.Spec{Sort: []string{"unit", "created_at", "updated_at"}, DefaultSort: "unit"}
)

func (h *handlers) ListEnrollmentTokens(ctx context.Context, req adminapi.ListEnrollmentTokensRequestObject) (adminapi.ListEnrollmentTokensResponseObject, error) {
	params, err := listing.Parse(enrollmentTokenList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	res, err := h.tokens.List(ctx, params.ListPage())
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.EnrollmentToken, len(res.Items))
	for i, t := range res.Items {
		items[i] = toEnrollmentToken(t, h.now())
	}
	return adminapi.ListEnrollmentTokens200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func (h *handlers) CreateEnrollmentToken(ctx context.Context, req adminapi.CreateEnrollmentTokenRequestObject) (adminapi.CreateEnrollmentTokenResponseObject, error) {
	created, err := h.tokens.Create(ctx, app.TokenInput{
		Name: req.Body.Name, ExpiresAt: req.Body.ExpiresAt, MaxUses: req.Body.MaxUses,
		DeviceGroupID: req.Body.DeviceGroupId, AutoApprove: req.Body.AutoApprove,
	})
	if err != nil {
		return nil, err
	}
	keys := make([]adminapi.BundleKey, len(created.Config.BundleKeys))
	for i, k := range created.Config.BundleKeys {
		keys[i] = adminapi.BundleKey{KeyId: k.KeyID, PublicKey: k.PublicKey}
	}
	loc := "/api/v1/enrollment-tokens/" + created.Token.ID.String()
	return adminapi.CreateEnrollmentToken201JSONResponse{
		Body: adminapi.EnrollmentTokenCreated{
			Token:  toEnrollmentToken(created.Token, h.now()),
			Secret: created.Secret,
			EnrollmentConfig: adminapi.EnrollmentConfig{
				ServerUrl: created.Config.ServerURL, OrganizationId: created.Token.OrganizationID,
				Token: created.Config.Token, BundleKeys: keys,
			},
		},
		Headers: adminapi.CreateEnrollmentToken201ResponseHeaders{Location: &loc},
	}, nil
}

func (h *handlers) GetEnrollmentToken(ctx context.Context, req adminapi.GetEnrollmentTokenRequestObject) (adminapi.GetEnrollmentTokenResponseObject, error) {
	t, err := h.tokens.Get(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.GetEnrollmentToken200JSONResponse(toEnrollmentToken(t, h.now())), nil
}

func (h *handlers) RevokeEnrollmentToken(ctx context.Context, req adminapi.RevokeEnrollmentTokenRequestObject) (adminapi.RevokeEnrollmentTokenResponseObject, error) {
	t, err := h.tokens.Revoke(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.RevokeEnrollmentToken200JSONResponse(toEnrollmentToken(t, h.now())), nil
}

func toEnrollmentToken(t pgstore.EnrollmentToken, now time.Time) adminapi.EnrollmentToken {
	return adminapi.EnrollmentToken{
		Id: t.ID, Name: t.Name, DeviceGroupId: idPtr(t.DeviceGroupID), AutoApprove: t.AutoApprove,
		MaxUses: int(t.MaxUses), Uses: int(t.Uses), ExpiresAt: t.ExpiresAt.UTC(), RevokedAt: utcPtr(t.RevokedAt),
		CreatedAt: t.CreatedAt.UTC(),
		Status:    adminapi.EnrollmentTokenStatus(enrollment.Status(t.RevokedAt, t.ExpiresAt, int(t.Uses), int(t.MaxUses), now)),
	}
}

func (h *handlers) ListDevices(ctx context.Context, req adminapi.ListDevicesRequestObject) (adminapi.ListDevicesResponseObject, error) {
	params, err := listing.Parse(deviceList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	states, err := listing.Enum("state", req.Params.State)
	if err != nil {
		return nil, err
	}
	res, err := h.devices.List(ctx, app.DeviceQuery{Page: params.ListPage(), States: states, GroupID: req.Params.DeviceGroupId})
	if err != nil {
		return nil, err
	}
	return adminapi.ListDevices200JSONResponse(listing.NewPage(toDeviceRows(res.Items), params, res.Count)), nil
}

func (h *handlers) ListDeviceGroupDevices(ctx context.Context, req adminapi.ListDeviceGroupDevicesRequestObject) (adminapi.ListDeviceGroupDevicesResponseObject, error) {
	params, err := listing.Parse(deviceList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	states, err := listing.Enum("state", req.Params.State)
	if err != nil {
		return nil, err
	}
	res, err := h.devices.ListGroupMembers(ctx, req.Id, app.DeviceQuery{Page: params.ListPage(), States: states})
	if err != nil {
		return nil, err
	}
	return adminapi.ListDeviceGroupDevices200JSONResponse(listing.NewPage(toDeviceRows(res.Items), params, res.Count)), nil
}

func toDeviceRows(rows []pgstore.ListDevicesRow) []adminapi.Device {
	items := make([]adminapi.Device, len(rows))
	for i, r := range rows {
		items[i] = toDevice(r.Device, &pgstore.DeviceStatus{
			LastContactAt: r.LastContactAt, AppliedBundleVersion: r.AppliedBundleVersion, AgentVersion: r.AgentVersion,
		})
	}
	return items
}

func toDevice(d pgstore.Device, status *pgstore.DeviceStatus) adminapi.Device {
	out := adminapi.Device{
		Id: d.ID, Hostname: d.Hostname, State: adminapi.DeviceState(d.State), HardwareUuid: d.HardwareUuid,
		MachineId: d.MachineID, OsRelease: map[string]string{}, EnrollmentTokenId: idPtr(d.EnrollmentTokenID),
		EnrolledAt: d.EnrolledAt.UTC(), StateChangedAt: d.StateChangedAt.UTC(), BundleVersion: d.BundleSeq,
	}
	_ = json.Unmarshal(d.OsRelease, &out.OsRelease) // written by the worker from a map[string]string
	if status != nil {
		out.LastContactAt, out.AppliedBundleVersion, out.AgentVersion = utcPtr(status.LastContactAt), status.AppliedBundleVersion, status.AgentVersion
	}
	return out
}

func toDeviceDetail(d app.DeviceDetail) adminapi.DeviceDetail {
	base := toDevice(d.Device, d.Status)
	out := adminapi.DeviceDetail{
		Id: base.Id, Hostname: base.Hostname, State: base.State, HardwareUuid: base.HardwareUuid, MachineId: base.MachineId,
		OsRelease: base.OsRelease, EnrollmentTokenId: base.EnrollmentTokenId, EnrolledAt: base.EnrolledAt,
		StateChangedAt: base.StateChangedAt, BundleVersion: base.BundleVersion, LastContactAt: base.LastContactAt,
		AppliedBundleVersion: base.AppliedBundleVersion, AgentVersion: base.AgentVersion,
		Groups: make([]adminapi.DeviceGroupRef, len(d.Groups)), IdentityKeys: make([]adminapi.DeviceIdentityKey, len(d.IdentityKeys)),
		LoginsSuspended: d.Device.LoginsSuspended, LoginManagement: d.LoginManagement(), SchemaVersions: []int{},
		LoginAssignment: adminapi.DeviceLoginAssignment{
			Users: make([]adminapi.UserRef, len(d.Login.Users)), Groups: make([]adminapi.UserGroupRef, len(d.Login.Groups)),
		},
	}
	if d.Status != nil {
		for _, v := range d.Status.SchemaVersions {
			out.SchemaVersions = append(out.SchemaVersions, int(v))
		}
		out.LoginStatus = toDeviceLoginStatus(d.Status.LoginState)
	}
	for i, u := range d.Login.Users {
		out.LoginAssignment.Users[i] = toUserRef(u)
	}
	for i, g := range d.Login.Groups {
		out.LoginAssignment.Groups[i] = toUserGroupRef(g)
	}
	for i, g := range d.Groups {
		out.Groups[i] = adminapi.DeviceGroupRef{Id: g.ID, Name: g.Name}
	}
	for i, k := range d.IdentityKeys {
		out.IdentityKeys[i] = adminapi.DeviceIdentityKey{
			KeyId: k.KeyID, KeyProtection: adminapi.DeviceIdentityKeyKeyProtection(k.KeyProtection),
			Status: adminapi.DeviceIdentityKeyStatus(k.Status), CreatedAt: k.CreatedAt.UTC(),
		}
	}
	return out
}

// toDeviceLoginStatus decodes device_status.login_state; an unreadable area counts as not reported.
func toDeviceLoginStatus(raw json.RawMessage) adminapi.DeviceLoginStatus {
	var state map[string]*adminapi.DeviceReport
	if json.Unmarshal(raw, &state) != nil {
		return adminapi.DeviceLoginStatus{}
	}
	return adminapi.DeviceLoginStatus{Login: state["login"], Sudo: state["sudo"]}
}

func (h *handlers) GetDevice(ctx context.Context, req adminapi.GetDeviceRequestObject) (adminapi.GetDeviceResponseObject, error) {
	d, err := h.devices.Get(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.GetDevice200JSONResponse(toDeviceDetail(d)), nil
}

func (h *handlers) ApproveDevice(ctx context.Context, req adminapi.ApproveDeviceRequestObject) (adminapi.ApproveDeviceResponseObject, error) {
	d, err := h.transition(ctx, req.Id, h.devices.Approve)
	if err != nil {
		return nil, err
	}
	return adminapi.ApproveDevice200JSONResponse{DeviceJSONResponse: adminapi.DeviceJSONResponse(d)}, nil
}

func (h *handlers) RejectDevice(ctx context.Context, req adminapi.RejectDeviceRequestObject) (adminapi.RejectDeviceResponseObject, error) {
	d, err := h.transition(ctx, req.Id, h.devices.Reject)
	if err != nil {
		return nil, err
	}
	return adminapi.RejectDevice200JSONResponse{DeviceJSONResponse: adminapi.DeviceJSONResponse(d)}, nil
}

func (h *handlers) ReleaseDeviceQuarantine(ctx context.Context, req adminapi.ReleaseDeviceQuarantineRequestObject) (adminapi.ReleaseDeviceQuarantineResponseObject, error) {
	d, err := h.transition(ctx, req.Id, h.devices.ReleaseQuarantine)
	if err != nil {
		return nil, err
	}
	return adminapi.ReleaseDeviceQuarantine200JSONResponse{DeviceJSONResponse: adminapi.DeviceJSONResponse(d)}, nil
}

func (h *handlers) RetireDevice(ctx context.Context, req adminapi.RetireDeviceRequestObject) (adminapi.RetireDeviceResponseObject, error) {
	d, err := h.transition(ctx, req.Id, h.devices.Retire)
	if err != nil {
		return nil, err
	}
	return adminapi.RetireDevice200JSONResponse{DeviceJSONResponse: adminapi.DeviceJSONResponse(d)}, nil
}

// transition runs a lifecycle use case and returns the device as it is afterwards.
func (h *handlers) transition(ctx context.Context, id uuid.UUID, fn func(context.Context, uuid.UUID) (pgstore.Device, error)) (adminapi.Device, error) {
	if _, err := fn(ctx, id); err != nil {
		return adminapi.Device{}, err
	}
	d, err := h.devices.Get(ctx, id)
	if err != nil {
		return adminapi.Device{}, err
	}
	return toDevice(d.Device, d.Status), nil
}

func (h *handlers) SetDeviceGroups(ctx context.Context, req adminapi.SetDeviceGroupsRequestObject) (adminapi.SetDeviceGroupsResponseObject, error) {
	d, err := h.devices.SetGroups(ctx, req.Id, req.Body.DeviceGroupIds)
	if err != nil {
		return nil, err
	}
	return adminapi.SetDeviceGroups200JSONResponse(toDeviceDetail(d)), nil
}

func (h *handlers) GetDeviceEffectiveConfig(ctx context.Context, req adminapi.GetDeviceEffectiveConfigRequestObject) (adminapi.GetDeviceEffectiveConfigResponseObject, error) {
	cfg, err := h.devices.EffectiveConfig(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	out := adminapi.EffectiveConfig{
		Resources: make([]adminapi.BundleResource, len(cfg.Resources)), Files: []adminapi.ManagedFile{},
		Units: []adminapi.ManagedUnit{}, Conflicts: []adminapi.ConfigConflict{},
	}
	for i, r := range cfg.Resources {
		out.Resources[i] = adminapi.BundleResource{Id: r.ID, Type: adminapi.BundleResourceType(r.Type)}
		if err := json.Unmarshal(r.Spec, &out.Resources[i].Spec); err != nil {
			return nil, err
		}
	}
	for _, f := range cfg.Files {
		out.Files = append(out.Files, toManagedFile(f))
	}
	for _, u := range cfg.Units {
		out.Units = append(out.Units, toManagedUnit(u))
	}
	for _, c := range cfg.Conflicts {
		out.Conflicts = append(out.Conflicts, adminapi.ConfigConflict{Resource: c.Resource, WinnerId: c.Winner, LoserIds: c.Losers})
	}
	return adminapi.GetDeviceEffectiveConfig200JSONResponse(out), nil
}

func idPtr(id uuid.NullUUID) *uuid.UUID {
	if !id.Valid {
		return nil
	}
	return &id.UUID
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}
