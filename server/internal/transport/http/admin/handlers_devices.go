package admin

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/components"
	"github.com/phischl/paddock-mdm/server/internal/domain/enrollment"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/listing"
)

// List definitions of the M2a collection endpoints; TestListSpecsMatchContract keeps them equal to x-paddock-list.
var (
	enrollmentTokenList = listing.Spec{Sort: []string{"name", "created_at", "expires_at"}, DefaultSort: "-created_at"}
	deviceList          = listing.Spec{Sort: []string{"hostname", "last_contact_at", "enrolled_at", "state"}, DefaultSort: "hostname"}
	managedFileList     = listing.Spec{Sort: []string{"path", "created_at", "updated_at"}, DefaultSort: "path"}
	managedUnitList     = listing.Spec{Sort: []string{"unit", "created_at", "updated_at"}, DefaultSort: "unit"}
	deviceLoginList     = listing.Spec{Sort: []string{"at", "username"}, DefaultSort: "-at"}
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
	keys := toAPIKeys(created.Config.BundleKeys)
	revocationKeys := toAPIKeys(created.Config.RevocationKeys)
	loc := "/api/v1/enrollment-tokens/" + created.Token.ID.String()
	return adminapi.CreateEnrollmentToken201JSONResponse{
		Body: adminapi.EnrollmentTokenCreated{
			Token:  toEnrollmentToken(created.Token, h.now()),
			Secret: created.Secret,
			EnrollmentConfig: adminapi.EnrollmentConfig{
				ServerUrl: created.Config.ServerURL, OrganizationId: created.Token.OrganizationID,
				Token: created.Config.Token, BundleKeys: keys, RevocationKeys: &revocationKeys,
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
	diskStates, err := listing.Enum("disk_state", req.Params.DiskState)
	if err != nil {
		return nil, err
	}
	contacts, err := listing.Enum("contact", req.Params.Contact)
	if err != nil {
		return nil, err
	}
	var security []adminapi.ListDevicesParamsSecurityUpdates
	if req.Params.SecurityUpdates != nil {
		security = append(security, *req.Params.SecurityUpdates)
	}
	overdue, err := listing.Enum("security_updates", &security)
	if err != nil {
		return nil, err
	}
	res, err := h.devices.List(ctx, app.DeviceQuery{Page: params.ListPage(), States: states, GroupID: req.Params.DeviceGroupId,
		DiskStates: diskStates, Contacts: contacts, SecurityOverdue: len(overdue) > 0, OwnerID: req.Params.OwnerId,
		ComponentOutdated: req.Params.ComponentOutdated})
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
		if s := adminapi.DiskState(r.DiskState); s.Valid() {
			items[i].DiskState = &s
		}
		items[i].Contact = adminapi.DeviceContact(r.Contact)
		items[i].ComponentsOutdated = r.ComponentsOutdated
		// Built by ListDevices with jsonb_build_object; an unreadable value leaves the column empty.
		_ = json.Unmarshal(r.Owners, &items[i].Owners)
		if r.HardwareVendor != nil {
			items[i].Hardware = &adminapi.DeviceHardware{
				Vendor: *r.HardwareVendor, Model: deref(r.HardwareModel, ""), Serial: deref(r.HardwareSerial, ""),
				CpuBrand: deref(r.CpuBrand, ""), CpuCores: int(deref(r.CpuCores, 0)), MemoryBytes: deref(r.MemoryBytes, 0),
				DiskTotalBytes: deref(r.DiskTotalBytes, 0),
			}
		}
	}
	return items
}

func toDevice(d pgstore.Device, status *pgstore.DeviceStatus) adminapi.Device {
	out := adminapi.Device{
		Id: d.ID, Hostname: d.Hostname, State: adminapi.DeviceState(d.State), HardwareUuid: d.HardwareUuid,
		Name: d.Name, NameState: adminapi.DeviceNameState(app.NameState(d.Name, d.Hostname)),
		MachineId: d.MachineID, OsRelease: map[string]string{}, EnrollmentTokenId: idPtr(d.EnrollmentTokenID),
		EnrolledAt: d.EnrolledAt.UTC(), StateChangedAt: d.StateChangedAt.UTC(), BundleVersion: d.BundleSeq,
		Owners: []adminapi.UserRef{}, Components: []adminapi.DeviceComponent{}, ComponentsOutdated: []string{},
		AgentUpdateRequestedVersion: d.AgentUpdateRequestedVersion,
		AgentUpdateRequestedAt:      utcPtr(d.AgentUpdateRequestedAt), RetiredReason: d.RetiredReason,
	}
	_ = json.Unmarshal(d.OsRelease, &out.OsRelease) // written by the worker from a map[string]string
	if status != nil {
		out.LastContactAt, out.AppliedBundleVersion, out.AgentVersion = utcPtr(status.LastContactAt), status.AppliedBundleVersion, status.AgentVersion
		if status.ComponentsOutdated != nil {
			out.ComponentsOutdated = status.ComponentsOutdated
		}
	}
	return out
}

// toDeviceComponents is the component list of a device from its last health report and the targets (plan M8d
// decision 55).
func toDeviceComponents(status *pgstore.DeviceStatus, targets map[string]string) []adminapi.DeviceComponent {
	var installed map[string]string
	if status != nil {
		installed = app.HealthComponents(status.Health)
	}
	out := make([]adminapi.DeviceComponent, 0, len(components.Names))
	for _, name := range components.Names {
		c := adminapi.DeviceComponent{Name: adminapi.DeviceComponentName(name), Installed: installed[name],
			Status: adminapi.DeviceComponentStatus(components.Status(name, installed, targets))}
		if v, ok := targets[name]; ok {
			c.Expected = &v
		}
		out = append(out, c)
	}
	return out
}

func toDeviceDetail(d app.DeviceDetail) adminapi.DeviceDetail {
	base := toDevice(d.Device, d.Status)
	base.Owners = toUserRefs(d.Owners)
	base.Hardware = toDeviceHardware(d.Hardware)
	out := adminapi.DeviceDetail{
		Id: base.Id, Hostname: base.Hostname, State: base.State, Contact: adminapi.DeviceContact(d.Contact),
		Name: base.Name, NameState: adminapi.DeviceDetailNameState(base.NameState),
		HardwareUuid: base.HardwareUuid, MachineId: base.MachineId,
		OsRelease: base.OsRelease, EnrollmentTokenId: base.EnrollmentTokenId, EnrolledAt: base.EnrolledAt,
		StateChangedAt: base.StateChangedAt, BundleVersion: base.BundleVersion, LastContactAt: base.LastContactAt,
		AppliedBundleVersion: base.AppliedBundleVersion, AgentVersion: base.AgentVersion, Owners: base.Owners,
		Hardware: base.Hardware, AgentUpdateRequestedVersion: base.AgentUpdateRequestedVersion,
		AgentUpdateRequestedAt: base.AgentUpdateRequestedAt, RetiredReason: base.RetiredReason,
		Uninstall: toDeviceUninstall(d.Uninstall, d.UninstallReportOverdue), DiskConversion: toDeviceDiskConversion(d.DiskConversion),
		Components:         toDeviceComponents(d.Status, d.ComponentTargets),
		ComponentsOutdated: base.ComponentsOutdated,
		Groups:             make([]adminapi.DeviceGroupRef, len(d.Groups)), IdentityKeys: make([]adminapi.DeviceIdentityKey, len(d.IdentityKeys)),
		ConfigStatus: adminapi.DeviceConfigStatusCounts{
			Applied: int(d.ConfigStatus.Applied), Failed: int(d.ConfigStatus.Failed), Pending: int(d.ConfigStatus.Pending),
			DriftCorrected: int(d.ConfigStatus.DriftCorrected),
		},
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
		out.SudoFlavor = toSudoFlavor(d.Status.Health)
		out.PresumedSelfLockedAt = d.Status.PresumedSelfLockedAt
		out.PresumedLostAt = d.Status.PresumedLostAt
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

// toSudoFlavor reads sudo_flavor from the health report of the last check-in; an unknown value counts as not reported.
func toSudoFlavor(health json.RawMessage) *adminapi.DeviceDetailSudoFlavor {
	var h struct {
		SudoFlavor adminapi.DeviceDetailSudoFlavor `json:"sudo_flavor"`
	}
	if json.Unmarshal(health, &h) != nil || !h.SudoFlavor.Valid() {
		return nil
	}
	return &h.SudoFlavor
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
	out := toDevice(d.Device, d.Status)
	out.Contact = adminapi.DeviceContact(d.Contact)
	out.Owners = toUserRefs(d.Owners)
	out.Hardware = toDeviceHardware(d.Hardware)
	out.Uninstall = toDeviceUninstall(d.Uninstall, d.UninstallReportOverdue)
	out.DiskConversion = toDeviceDiskConversion(d.DiskConversion)
	out.Components = toDeviceComponents(d.Status, d.ComponentTargets)
	return out, nil
}

func (h *handlers) UpdateDeviceAgent(ctx context.Context, req adminapi.UpdateDeviceAgentRequestObject) (adminapi.UpdateDeviceAgentResponseObject, error) {
	d, err := h.transition(ctx, req.Id, h.agentUpdates.RequestNow)
	if err != nil {
		return nil, err
	}
	return adminapi.UpdateDeviceAgent200JSONResponse{DeviceJSONResponse: adminapi.DeviceJSONResponse(d)}, nil
}

func (h *handlers) UninstallDevice(ctx context.Context, req adminapi.UninstallDeviceRequestObject) (adminapi.UninstallDeviceResponseObject, error) {
	in := app.UninstallInput{Mode: string(req.Body.Mode), ConfirmHostname: req.Body.ConfirmHostname, Reason: req.Body.Reason,
		ClearTPM: deref(req.Body.ClearTpm, false), KeepLocalAdmin: deref(req.Body.KeepLocalAdmin, false)}
	d, err := h.transition(ctx, req.Id, func(ctx context.Context, id uuid.UUID) (pgstore.Device, error) {
		return h.uninstalls.Request(ctx, id, in)
	})
	if err != nil {
		return nil, err
	}
	return adminapi.UninstallDevice200JSONResponse{DeviceJSONResponse: adminapi.DeviceJSONResponse(d)}, nil
}

func (h *handlers) CancelDeviceUninstall(ctx context.Context, req adminapi.CancelDeviceUninstallRequestObject) (adminapi.CancelDeviceUninstallResponseObject, error) {
	d, err := h.transition(ctx, req.Id, h.uninstalls.Cancel)
	if err != nil {
		return nil, err
	}
	return adminapi.CancelDeviceUninstall200JSONResponse{DeviceJSONResponse: adminapi.DeviceJSONResponse(d)}, nil
}

// toDeviceUninstall is the uninstall of a device; nil without one.
func toDeviceUninstall(u *pgstore.GetDeviceUninstallRow, overdue bool) *adminapi.DeviceUninstall {
	if u == nil {
		return nil
	}
	out := &adminapi.DeviceUninstall{Mode: adminapi.DeviceUninstallMode(u.Mode), RequestedAt: u.RequestedAt.UTC(),
		CommandId: u.CommandID, CommandStatus: u.CommandStatus, UninstalledAt: utcPtr(u.UninstalledAt), ReportOverdue: overdue}
	if u.LocalAdmin != "" {
		out.LocalAdmin = &u.LocalAdmin
	}
	if u.Tpm != "" {
		out.Tpm = &u.Tpm
	}
	if u.RefusedReason != "" {
		out.RefusedReason = &u.RefusedReason
	}
	return out
}

func (h *handlers) EncryptDevice(ctx context.Context, req adminapi.EncryptDeviceRequestObject) (adminapi.EncryptDeviceResponseObject, error) {
	in := app.DiskConversionInput{ConfirmHostname: req.Body.ConfirmHostname, Reason: req.Body.Reason, BackupConfirmed: req.Body.BackupConfirmed}
	d, err := h.transition(ctx, req.Id, func(ctx context.Context, id uuid.UUID) (pgstore.Device, error) {
		return h.conversions.Request(ctx, id, in)
	})
	if err != nil {
		return nil, err
	}
	return adminapi.EncryptDevice200JSONResponse{DeviceJSONResponse: adminapi.DeviceJSONResponse(d)}, nil
}

func (h *handlers) CancelDeviceEncryption(ctx context.Context, req adminapi.CancelDeviceEncryptionRequestObject) (adminapi.CancelDeviceEncryptionResponseObject, error) {
	d, err := h.transition(ctx, req.Id, func(ctx context.Context, id uuid.UUID) (pgstore.Device, error) {
		return h.conversions.Cancel(ctx, id, req.Body.ConfirmHostname)
	})
	if err != nil {
		return nil, err
	}
	return adminapi.CancelDeviceEncryption200JSONResponse{DeviceJSONResponse: adminapi.DeviceJSONResponse(d)}, nil
}

// toDeviceDiskConversion is the latest in-place encryption of a device; nil without one.
func toDeviceDiskConversion(c *app.DiskConversion) *adminapi.DeviceDiskConversion {
	if c == nil {
		return nil
	}
	r := c.DeviceDiskConversion
	out := &adminapi.DeviceDiskConversion{
		Id: r.ID, Phase: adminapi.DeviceDiskConversionPhase(r.Phase), RequestedAt: r.RequestedAt.UTC(), Reason: r.Reason,
		CommandId: r.CommandID, CommandStatus: c.CommandStatus, LuksUuid: idPtr(r.LuksUuid), DataBytes: r.DataBytes,
		FailureStage: r.FailureStage, FailureReason: r.FailureReason, FinishedAt: utcPtr(r.FinishedAt),
		AbortCommandId: idPtr(r.AbortCommandID), AbortCommandStatus: c.AbortCommandStatus,
		AbortRefusedReason: r.AbortRefusedReason, Active: c.Active,
	}
	if r.Layout != nil {
		layout := adminapi.DeviceDiskConversionLayout(*r.Layout)
		out.Layout = &layout
	}
	if p := c.Progress; p != nil {
		out.DoneBytes, out.EtaS, out.ProgressAt = &p.DoneBytes, &p.ETASeconds, utcPtr(p.UpdatedAt)
	}
	n := c.Notes
	out.PausedReason, out.PausedSince, out.CleanupError = optString(n.PausedReason), utcPtr(n.PausedSince), optString(n.CleanupError)
	out.InitrdIssue, out.InitrdIssueKernel = optString(n.InitrdIssue), optString(n.InitrdIssueKernel)
	if n.BootSpaceNeeded > 0 || n.BootSpaceFree > 0 {
		out.BootSpaceNeeded, out.BootSpaceFree = &n.BootSpaceNeeded, &n.BootSpaceFree
	}
	return out
}

func (h *handlers) SetDeviceGroups(ctx context.Context, req adminapi.SetDeviceGroupsRequestObject) (adminapi.SetDeviceGroupsResponseObject, error) {
	d, err := h.devices.SetGroups(ctx, req.Id, req.Body.DeviceGroupIds)
	if err != nil {
		return nil, err
	}
	return adminapi.SetDeviceGroups200JSONResponse(toDeviceDetail(d)), nil
}

func (h *handlers) ListDeviceLogins(ctx context.Context, req adminapi.ListDeviceLoginsRequestObject) (adminapi.ListDeviceLoginsResponseObject, error) {
	params, err := listing.Parse(deviceLoginList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	var username *string
	if u := req.Params.Username; u != nil {
		lower := strings.ToLower(strings.TrimSpace(*u))
		username = &lower
	}
	res, err := h.loginHistory.List(ctx, req.Id, app.LoginEventQuery{Page: params.ListPage(), Username: username})
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.DeviceLoginEvent, len(res.Items))
	for i, e := range res.Items {
		items[i] = adminapi.DeviceLoginEvent{Id: e.ID, Username: e.Username, At: e.At.UTC()}
	}
	return adminapi.ListDeviceLogins200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func (h *handlers) SetDeviceOwners(ctx context.Context, req adminapi.SetDeviceOwnersRequestObject) (adminapi.SetDeviceOwnersResponseObject, error) {
	d, err := h.devices.SetOwners(ctx, req.Id, req.Body.UserIds)
	if err != nil {
		return nil, err
	}
	return adminapi.SetDeviceOwners200JSONResponse(toDeviceDetail(d)), nil
}

func toDeviceHardware(h *pgstore.GetDeviceHardwareRow) *adminapi.DeviceHardware {
	if h == nil {
		return nil
	}
	return &adminapi.DeviceHardware{
		Vendor: h.HardwareVendor, Model: h.HardwareModel, Serial: h.HardwareSerial, CpuBrand: h.CpuBrand, CpuCores: int(h.CpuCores),
		MemoryBytes: h.MemoryBytes, DiskTotalBytes: h.DiskTotalBytes,
	}
}

func toUserRefs(users []pgstore.AppUser) []adminapi.UserRef {
	out := make([]adminapi.UserRef, len(users))
	for i, u := range users {
		out[i] = toUserRef(u)
	}
	return out
}

func (h *handlers) SetDeviceName(ctx context.Context, req adminapi.SetDeviceNameRequestObject) (adminapi.SetDeviceNameResponseObject, error) {
	d, err := h.devices.SetName(ctx, req.Id, req.Body.Name)
	if err != nil {
		return nil, err
	}
	return adminapi.SetDeviceName200JSONResponse(toDeviceDetail(d)), nil
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
	roots, err := h.operatorRoots(ctx)
	if err != nil {
		return nil, err
	}
	for _, f := range cfg.Files {
		out.Files = append(out.Files, toManagedFile(f, roots))
	}
	for _, u := range cfg.Units {
		out.Units = append(out.Units, toManagedUnit(u))
	}
	for _, c := range cfg.Conflicts {
		out.Conflicts = append(out.Conflicts, adminapi.ConfigConflict{Resource: c.Resource, WinnerId: c.Winner, LoserIds: c.Losers})
	}
	if cfg.Rollout != nil {
		out.Rollout = &struct {
			Id     uuid.UUID `json:"id"`
			InWave bool      `json:"in_wave"`
		}{Id: cfg.Rollout.ID, InWave: cfg.Rollout.InWave}
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

func toAPIKeys(in []protocol.BundleKey) []adminapi.BundleKey {
	out := make([]adminapi.BundleKey, len(in))
	for i, k := range in {
		out[i] = adminapi.BundleKey{KeyId: k.KeyID, PublicKey: k.PublicKey}
	}
	return out
}
