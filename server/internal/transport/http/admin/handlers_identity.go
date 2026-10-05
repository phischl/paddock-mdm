package admin

import (
	"context"

	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/server/internal/adapters/postgres/pgstore"
	"github.com/paddock-mdm/paddock/server/internal/app"
	"github.com/paddock-mdm/paddock/server/internal/domain/loginsettings"
	"github.com/paddock-mdm/paddock/server/internal/domain/privilege"
	"github.com/paddock-mdm/paddock/server/internal/transport/http/admin/adminapi"
	"github.com/paddock-mdm/paddock/server/internal/transport/http/admin/listing"
)

// List definitions of the M3a collection endpoints; TestListSpecsMatchContract keeps them equal to x-paddock-list.
var (
	userList              = listing.Spec{Sort: []string{"username", "display_name", "created_at"}, DefaultSort: "username"}
	userGroupList         = listing.Spec{Sort: []string{"name", "slug", "created_at"}, DefaultSort: "name"}
	upstreamGroupList     = listing.Spec{Sort: []string{"name"}, DefaultSort: "name"}
	permissionProfileList = listing.Spec{Sort: []string{"name", "class", "created_at", "updated_at"}, DefaultSort: "name"}
	profileAssignmentList = listing.Spec{Sort: []string{"created_at", "subject_type"}, DefaultSort: "created_at"}
)

func (h *handlers) ListUsers(ctx context.Context, req adminapi.ListUsersRequestObject) (adminapi.ListUsersResponseObject, error) {
	page, err := h.users2page(ctx, nil, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	}, req.Params.Source, req.Params.Locked)
	if err != nil {
		return nil, err
	}
	return adminapi.ListUsers200JSONResponse(page), nil
}

func (h *handlers) ListUserGroupMembers(ctx context.Context, req adminapi.ListUserGroupMembersRequestObject) (adminapi.ListUserGroupMembersResponseObject, error) {
	page, err := h.users2page(ctx, &req.Id, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	}, req.Params.Source, req.Params.Locked)
	if err != nil {
		return nil, err
	}
	return adminapi.ListUserGroupMembers200JSONResponse(page), nil
}

func (h *handlers) users2page(ctx context.Context, group *uuid.UUID, q listing.Query, source *adminapi.UserSourceFilter,
	locked *bool) (listing.Page[adminapi.User], error) {
	params, err := listing.Parse(userList, q)
	if err != nil {
		return listing.Page[adminapi.User]{}, err
	}
	sources, err := listing.Enum("source", source)
	if err != nil {
		return listing.Page[adminapi.User]{}, err
	}
	res, err := h.users.List(ctx, app.UserQuery{Page: params.ListPage(), Sources: sources, Locked: locked, GroupID: group})
	if err != nil {
		return listing.Page[adminapi.User]{}, err
	}
	items := make([]adminapi.User, len(res.Items))
	for i, u := range res.Items {
		items[i] = toUser(u)
	}
	return listing.NewPage(items, params, res.Count), nil
}

func toUser(u pgstore.AppUser) adminapi.User {
	return adminapi.User{
		Id: u.ID, Username: u.Username, DisplayName: u.DisplayName, Email: u.Email, Source: adminapi.IdentitySource(u.Source),
		Locked: u.Locked, LockIncomplete: u.LockIncomplete, LockedAt: utcPtr(u.LockedAt), CreatedAt: u.CreatedAt.UTC(), UpdatedAt: u.UpdatedAt.UTC(),
	}
}

func toUserRef(u pgstore.AppUser) adminapi.UserRef {
	return adminapi.UserRef{Id: u.ID, Username: u.Username, DisplayName: u.DisplayName}
}

func toUserGroupRef(g pgstore.UserGroup) adminapi.UserGroupRef {
	return adminapi.UserGroupRef{Id: g.ID, Slug: g.Slug, Name: g.Name, Source: adminapi.IdentitySource(g.Source)}
}

func (h *handlers) CreateUser(ctx context.Context, req adminapi.CreateUserRequestObject) (adminapi.CreateUserResponseObject, error) {
	email := ""
	if req.Body.Email != nil {
		email = *req.Body.Email
	}
	created, err := h.users.Create(ctx, app.NewUser{Username: req.Body.Username, DisplayName: req.Body.DisplayName, Email: email})
	if err != nil {
		return nil, err
	}
	loc := "/api/v1/users/" + created.User.ID.String()
	return adminapi.CreateUser201JSONResponse{
		Body:    adminapi.UserCreated{User: toUser(created.User), RecoveryLink: created.RecoveryLink},
		Headers: adminapi.CreateUser201ResponseHeaders{Location: &loc},
	}, nil
}

func (h *handlers) GetUser(ctx context.Context, req adminapi.GetUserRequestObject) (adminapi.GetUserResponseObject, error) {
	d, err := h.users.Get(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	u := toUser(d.User)
	out := adminapi.UserDetail{
		Id: u.Id, Username: u.Username, DisplayName: u.DisplayName, Email: u.Email, Source: u.Source, Locked: u.Locked,
		LockIncomplete: u.LockIncomplete, LockedAt: u.LockedAt, CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt,
		Groups: make([]adminapi.UserGroupRef, len(d.Groups)),
	}
	for i, g := range d.Groups {
		out.Groups[i] = toUserGroupRef(g)
	}
	return adminapi.GetUser200JSONResponse(out), nil
}

func (h *handlers) UpdateUser(ctx context.Context, req adminapi.UpdateUserRequestObject) (adminapi.UpdateUserResponseObject, error) {
	u, err := h.users.Update(ctx, req.Id, req.Body.DisplayName, req.Body.Email)
	if err != nil {
		return nil, err
	}
	return adminapi.UpdateUser200JSONResponse(toUser(u)), nil
}

func (h *handlers) DeleteUser(ctx context.Context, req adminapi.DeleteUserRequestObject) (adminapi.DeleteUserResponseObject, error) {
	if err := h.users.Delete(ctx, req.Id); err != nil {
		return nil, err
	}
	return adminapi.DeleteUser204Response{}, nil
}

func (h *handlers) LockUser(ctx context.Context, req adminapi.LockUserRequestObject) (adminapi.LockUserResponseObject, error) {
	u, err := h.users.Lock(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.LockUser200JSONResponse(toUser(u)), nil
}

func (h *handlers) UnlockUser(ctx context.Context, req adminapi.UnlockUserRequestObject) (adminapi.UnlockUserResponseObject, error) {
	u, err := h.users.Unlock(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.UnlockUser200JSONResponse(toUser(u)), nil
}

func (h *handlers) ListUserGroups(ctx context.Context, req adminapi.ListUserGroupsRequestObject) (adminapi.ListUserGroupsResponseObject, error) {
	params, err := listing.Parse(userGroupList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	sources, err := listing.Enum("source", req.Params.Source)
	if err != nil {
		return nil, err
	}
	res, err := h.userGroups.List(ctx, params.ListPage(), sources)
	if err != nil {
		return nil, err
	}
	slug, err := h.orgSlug(ctx)
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.UserGroup, len(res.Items))
	for i, g := range res.Items {
		items[i] = toUserGroup(slug, g)
	}
	return adminapi.ListUserGroups200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

// orgSlug is the slug of the principal's organization (for Authentik group names).
func (h *handlers) orgSlug(ctx context.Context) (string, error) {
	me, err := h.accounts.GetMe(ctx)
	if err != nil {
		return "", err
	}
	if me.Organization == nil {
		return "", nil
	}
	return me.Organization.Slug, nil
}

func toUserGroup(slug string, g pgstore.UserGroup) adminapi.UserGroup {
	return adminapi.UserGroup{
		Id: g.ID, Slug: g.Slug, Name: g.Name, Source: adminapi.IdentitySource(g.Source), UpstreamGroupId: g.UpstreamAuthentikPk,
		AuthentikName: app.AuthentikGroupName(slug, g), CreatedAt: g.CreatedAt.UTC(), UpdatedAt: g.UpdatedAt.UTC(),
	}
}

func (h *handlers) CreateUserGroup(ctx context.Context, req adminapi.CreateUserGroupRequestObject) (adminapi.CreateUserGroupResponseObject, error) {
	g, err := h.userGroups.Create(ctx, app.NewUserGroup{Slug: req.Body.Slug, Name: req.Body.Name, UpstreamPK: req.Body.UpstreamGroupId})
	if err != nil {
		return nil, err
	}
	slug, err := h.orgSlug(ctx)
	if err != nil {
		return nil, err
	}
	loc := "/api/v1/user-groups/" + g.ID.String()
	return adminapi.CreateUserGroup201JSONResponse{
		Body: toUserGroup(slug, g), Headers: adminapi.CreateUserGroup201ResponseHeaders{Location: &loc},
	}, nil
}

func (h *handlers) GetUserGroup(ctx context.Context, req adminapi.GetUserGroupRequestObject) (adminapi.GetUserGroupResponseObject, error) {
	g, err := h.userGroups.Get(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	slug, err := h.orgSlug(ctx)
	if err != nil {
		return nil, err
	}
	return adminapi.GetUserGroup200JSONResponse(toUserGroup(slug, g)), nil
}

func (h *handlers) UpdateUserGroup(ctx context.Context, req adminapi.UpdateUserGroupRequestObject) (adminapi.UpdateUserGroupResponseObject, error) {
	g, err := h.userGroups.Rename(ctx, req.Id, req.Body.Name)
	if err != nil {
		return nil, err
	}
	slug, err := h.orgSlug(ctx)
	if err != nil {
		return nil, err
	}
	return adminapi.UpdateUserGroup200JSONResponse(toUserGroup(slug, g)), nil
}

func (h *handlers) DeleteUserGroup(ctx context.Context, req adminapi.DeleteUserGroupRequestObject) (adminapi.DeleteUserGroupResponseObject, error) {
	if err := h.userGroups.Delete(ctx, req.Id); err != nil {
		return nil, err
	}
	return adminapi.DeleteUserGroup204Response{}, nil
}

func (h *handlers) AddUserGroupMember(ctx context.Context, req adminapi.AddUserGroupMemberRequestObject) (adminapi.AddUserGroupMemberResponseObject, error) {
	if err := h.userGroups.AddMember(ctx, req.Id, req.Body.UserId); err != nil {
		return nil, err
	}
	return adminapi.AddUserGroupMember204Response{}, nil
}

func (h *handlers) RemoveUserGroupMember(ctx context.Context, req adminapi.RemoveUserGroupMemberRequestObject) (adminapi.RemoveUserGroupMemberResponseObject, error) {
	if err := h.userGroups.RemoveMember(ctx, req.Id, req.UserId); err != nil {
		return nil, err
	}
	return adminapi.RemoveUserGroupMember204Response{}, nil
}

func (h *handlers) ListUpstreamGroups(ctx context.Context, req adminapi.ListUpstreamGroupsRequestObject) (adminapi.ListUpstreamGroupsResponseObject, error) {
	params, err := listing.Parse(upstreamGroupList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	res, err := h.userGroups.UpstreamGroups(ctx, params.ListPage(), params.Q)
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.UpstreamGroup, len(res.Items))
	for i, g := range res.Items {
		items[i] = adminapi.UpstreamGroup{Id: g.PK, Name: g.Name}
	}
	return adminapi.ListUpstreamGroups200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func (h *handlers) GetLoginSettings(ctx context.Context, _ adminapi.GetLoginSettingsRequestObject) (adminapi.GetLoginSettingsResponseObject, error) {
	s, err := h.loginSettings.Get(ctx)
	if err != nil {
		return nil, err
	}
	return adminapi.GetLoginSettings200JSONResponse(toLoginSettings(s)), nil
}

func (h *handlers) UpdateLoginSettings(ctx context.Context, req adminapi.UpdateLoginSettingsRequestObject) (adminapi.UpdateLoginSettingsResponseObject, error) {
	b := req.Body
	s, err := h.loginSettings.Update(ctx, loginsettings.Settings{
		HelloEnabled: b.HelloEnabled, HelloPinMinLength: b.HelloPinMinLength, UserLockSessionAction: string(b.UserLockSessionAction),
		BreakGlassAccounts: b.BreakGlassAccounts, SudoersDAllowlist: b.SudoersDAllowlist, SudoLectureText: b.SudoLectureText,
		LocalAdminUsername: b.LocalAdminUsername, LocalAdminRotationDays: b.LocalAdminRotationDays,
		RotateAfterRevealHours: b.RotateAfterRevealHours, NoticeText: b.NoticeText,
	})
	if err != nil {
		return nil, err
	}
	return adminapi.UpdateLoginSettings200JSONResponse(toLoginSettings(s)), nil
}

func toLoginSettings(s pgstore.OrganizationLoginSetting) adminapi.LoginSettings {
	return adminapi.LoginSettings{
		HelloEnabled: s.HelloEnabled, HelloPinMinLength: int(s.HelloPinMinLength),
		UserLockSessionAction: adminapi.SessionAction(s.UserLockSessionAction), BreakGlassAccounts: s.BreakGlassAccounts,
		SudoersDAllowlist: s.SudoersDAllowlist, SudoLectureText: s.SudoLectureText, UpdatedAt: s.UpdatedAt.UTC(),
		LocalAdminUsername: s.LocalAdminUsername, LocalAdminRotationDays: int(s.LocalAdminRotationDays),
		RotateAfterRevealHours: intPtr(s.RotateAfterRevealHours), NoticeText: s.NoticeText,
	}
}

func (h *handlers) SetDeviceLoginAssignment(ctx context.Context, req adminapi.SetDeviceLoginAssignmentRequestObject) (adminapi.SetDeviceLoginAssignmentResponseObject, error) {
	if err := h.logins.SetAssignment(ctx, req.Id, req.Body.Users, req.Body.Groups); err != nil {
		return nil, err
	}
	d, err := h.devices.Get(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.SetDeviceLoginAssignment200JSONResponse(toDeviceDetail(d)), nil
}

func (h *handlers) SuspendDeviceLogins(ctx context.Context, req adminapi.SuspendDeviceLoginsRequestObject) (adminapi.SuspendDeviceLoginsResponseObject, error) {
	if _, err := h.logins.Suspend(ctx, req.Id); err != nil {
		return nil, err
	}
	d, err := h.devices.Get(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.SuspendDeviceLogins200JSONResponse(toDeviceDetail(d)), nil
}

func (h *handlers) ResumeDeviceLogins(ctx context.Context, req adminapi.ResumeDeviceLoginsRequestObject) (adminapi.ResumeDeviceLoginsResponseObject, error) {
	if _, err := h.logins.Resume(ctx, req.Id); err != nil {
		return nil, err
	}
	d, err := h.devices.Get(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.ResumeDeviceLogins200JSONResponse(toDeviceDetail(d)), nil
}

func (h *handlers) ListPermissionProfiles(ctx context.Context, req adminapi.ListPermissionProfilesRequestObject) (adminapi.ListPermissionProfilesResponseObject, error) {
	params, err := listing.Parse(permissionProfileList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	classes, err := listing.Enum("class", req.Params.Class)
	if err != nil {
		return nil, err
	}
	res, err := h.privileges.ListProfiles(ctx, params.ListPage(), classes)
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.PermissionProfile, len(res.Items))
	for i, p := range res.Items {
		items[i] = toPermissionProfile(p)
	}
	return adminapi.ListPermissionProfiles200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func toPermissionProfile(p pgstore.PermissionProfile) adminapi.PermissionProfile {
	root := privilege.RootEquivalentCommands(p.Commands)
	if root == nil {
		root = []string{}
	}
	invalid := privilege.InvalidCommands(p.Commands)
	if invalid == nil {
		invalid = []string{}
	}
	return adminapi.PermissionProfile{
		Id: p.ID, Name: p.Name, Class: adminapi.PrivilegeClass(p.Class), Commands: p.Commands, RequirePassword: p.RequirePassword,
		TimestampTimeoutMin: int(p.TimestampTimeoutMin), Lecture: adminapi.Lecture(p.Lecture), RootEquivalent: len(root) > 0,
		RootEquivalentCommands: root, InvalidCommands: invalid, CreatedAt: p.CreatedAt.UTC(), UpdatedAt: p.UpdatedAt.UTC(),
	}
}

func (h *handlers) CreatePermissionProfile(ctx context.Context, req adminapi.CreatePermissionProfileRequestObject) (adminapi.CreatePermissionProfileResponseObject, error) {
	b := req.Body
	in := privilege.Profile{
		Name: b.Name, Class: privilege.Class(b.Class), Commands: deref(b.Commands, nil), RequirePassword: deref(b.RequirePassword, true),
		TimestampTimeoutMin: deref(b.TimestampTimeoutMin, 5), Lecture: privilege.Lecture(deref(b.Lecture, adminapi.Once)),
	}
	p, err := h.privileges.CreateProfile(ctx, in)
	if err != nil {
		return nil, err
	}
	loc := "/api/v1/permission-profiles/" + p.ID.String()
	return adminapi.CreatePermissionProfile201JSONResponse{
		Body: toPermissionProfile(p), Headers: adminapi.CreatePermissionProfile201ResponseHeaders{Location: &loc},
	}, nil
}

func deref[T any](v *T, def T) T {
	if v == nil {
		return def
	}
	return *v
}

func (h *handlers) GetPermissionProfile(ctx context.Context, req adminapi.GetPermissionProfileRequestObject) (adminapi.GetPermissionProfileResponseObject, error) {
	p, err := h.privileges.GetProfile(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.GetPermissionProfile200JSONResponse(toPermissionProfile(p)), nil
}

func (h *handlers) UpdatePermissionProfile(ctx context.Context, req adminapi.UpdatePermissionProfileRequestObject) (adminapi.UpdatePermissionProfileResponseObject, error) {
	b := req.Body
	patch := app.ProfilePatch{Name: b.Name, Commands: b.Commands, RequirePassword: b.RequirePassword, TimestampTimeoutMin: b.TimestampTimeoutMin}
	if b.Class != nil {
		c := privilege.Class(*b.Class)
		patch.Class = &c
	}
	if b.Lecture != nil {
		l := privilege.Lecture(*b.Lecture)
		patch.Lecture = &l
	}
	p, err := h.privileges.UpdateProfile(ctx, req.Id, patch)
	if err != nil {
		return nil, err
	}
	return adminapi.UpdatePermissionProfile200JSONResponse(toPermissionProfile(p)), nil
}

func (h *handlers) DeletePermissionProfile(ctx context.Context, req adminapi.DeletePermissionProfileRequestObject) (adminapi.DeletePermissionProfileResponseObject, error) {
	if err := h.privileges.DeleteProfile(ctx, req.Id); err != nil {
		return nil, err
	}
	return adminapi.DeletePermissionProfile204Response{}, nil
}

func (h *handlers) ListProfileAssignments(ctx context.Context, req adminapi.ListProfileAssignmentsRequestObject) (adminapi.ListProfileAssignmentsResponseObject, error) {
	params, err := listing.Parse(profileAssignmentList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	types, err := listing.Enum("subject_type", req.Params.SubjectType)
	if err != nil {
		return nil, err
	}
	res, err := h.privileges.ListAssignments(ctx, app.AssignmentQuery{
		Page: params.ListPage(), ProfileID: req.Params.ProfileId, SubjectTypes: types, SubjectID: req.Params.SubjectId,
		DeviceGroupID: req.Params.DeviceGroupId,
	})
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.ProfileAssignment, len(res.Items))
	for i, a := range res.Items {
		items[i] = toProfileAssignment(a)
	}
	return adminapi.ListProfileAssignments200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func toProfileAssignment(a pgstore.ProfileAssignment) adminapi.ProfileAssignment {
	return adminapi.ProfileAssignment{
		Id: a.ID, ProfileId: a.ProfileID, SubjectType: adminapi.SubjectType(a.SubjectType), SubjectId: idPtr(a.SubjectID),
		DeviceGroupId: idPtr(a.DeviceGroupID), CreatedAt: a.CreatedAt.UTC(),
	}
}

func (h *handlers) CreateProfileAssignment(ctx context.Context, req adminapi.CreateProfileAssignmentRequestObject) (adminapi.CreateProfileAssignmentResponseObject, error) {
	b := req.Body
	a, err := h.privileges.CreateAssignment(ctx, app.NewAssignment{
		ProfileID: b.ProfileId, SubjectType: privilege.SubjectType(b.SubjectType), SubjectID: b.SubjectId, DeviceGroupID: b.DeviceGroupId,
	})
	if err != nil {
		return nil, err
	}
	loc := "/api/v1/profile-assignments/" + a.ID.String()
	return adminapi.CreateProfileAssignment201JSONResponse{
		Body: toProfileAssignment(a), Headers: adminapi.CreateProfileAssignment201ResponseHeaders{Location: &loc},
	}, nil
}

func (h *handlers) GetProfileAssignment(ctx context.Context, req adminapi.GetProfileAssignmentRequestObject) (adminapi.GetProfileAssignmentResponseObject, error) {
	a, err := h.privileges.GetAssignment(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.GetProfileAssignment200JSONResponse(toProfileAssignment(a)), nil
}

func (h *handlers) UpdateProfileAssignment(ctx context.Context, req adminapi.UpdateProfileAssignmentRequestObject) (adminapi.UpdateProfileAssignmentResponseObject, error) {
	a, err := h.privileges.UpdateAssignmentScope(ctx, req.Id, req.Body.DeviceGroupId)
	if err != nil {
		return nil, err
	}
	return adminapi.UpdateProfileAssignment200JSONResponse(toProfileAssignment(a)), nil
}

func (h *handlers) DeleteProfileAssignment(ctx context.Context, req adminapi.DeleteProfileAssignmentRequestObject) (adminapi.DeleteProfileAssignmentResponseObject, error) {
	if err := h.privileges.DeleteAssignment(ctx, req.Id); err != nil {
		return nil, err
	}
	return adminapi.DeleteProfileAssignment204Response{}, nil
}

func (h *handlers) GetUserEffectiveProfile(ctx context.Context, req adminapi.GetUserEffectiveProfileRequestObject) (adminapi.GetUserEffectiveProfileResponseObject, error) {
	u, e, names, err := h.privileges.EffectiveProfile(ctx, req.Id, req.Params.DeviceId)
	if err != nil {
		return nil, err
	}
	core := toEffectiveProfile(e)
	out := adminapi.UserEffectiveProfile{
		User: toUserRef(u), DeviceId: req.Params.DeviceId, Class: core.Class, ReportedClass: core.ReportedClass,
		RootEquivalent: core.RootEquivalent, RootEquivalentCommands: core.RootEquivalentCommands, CatalogVersion: core.CatalogVersion,
		Commands: core.Commands, RequirePassword: core.RequirePassword, TimestampTimeoutMin: core.TimestampTimeoutMin,
		Lecture: core.Lecture, Derivation: make([]adminapi.Derivation, len(e.Derivation)),
	}
	for i, d := range e.Derivation {
		out.Derivation[i] = adminapi.Derivation{
			Kind: adminapi.DerivationKind(d.Kind), Item: d.Item, Value: d.Value, AssignmentId: d.AssignmentID,
			ProfileId: d.ProfileID, ProfileName: names[d.ProfileID],
			Subject: adminapi.DerivationSubject{Type: adminapi.SubjectType(d.Subject.Type), Id: d.Subject.ID},
		}
	}
	return adminapi.GetUserEffectiveProfile200JSONResponse(out), nil
}

func toEffectiveProfile(e privilege.EffectiveProfile) adminapi.EffectiveProfile {
	return adminapi.EffectiveProfile{
		Class: adminapi.PrivilegeClass(e.Class), ReportedClass: adminapi.PrivilegeClass(e.ReportedClass),
		RootEquivalent: e.RootEquivalent, RootEquivalentCommands: e.RootEquivalentCommands, CatalogVersion: e.CatalogVersion,
		Commands: e.Commands, RequirePassword: e.RequirePassword, TimestampTimeoutMin: e.TimestampTimeoutMin,
		Lecture: adminapi.Lecture(e.Lecture),
	}
}

func (h *handlers) GetDeviceEffectiveSudo(ctx context.Context, req adminapi.GetDeviceEffectiveSudoRequestObject) (adminapi.GetDeviceEffectiveSudoResponseObject, error) {
	users, err := h.privileges.EffectiveSudo(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	out := adminapi.EffectiveSudo{DeviceId: req.Id, Entries: make([]adminapi.EffectiveSudoEntry, len(users))}
	for i, u := range users {
		c := toEffectiveProfile(u.Effective)
		out.Entries[i] = adminapi.EffectiveSudoEntry{
			User: toUserRef(u.User), Class: c.Class, ReportedClass: c.ReportedClass, RootEquivalent: c.RootEquivalent,
			RootEquivalentCommands: c.RootEquivalentCommands, CatalogVersion: c.CatalogVersion, Commands: c.Commands,
			RequirePassword: c.RequirePassword, TimestampTimeoutMin: c.TimestampTimeoutMin, Lecture: c.Lecture,
		}
	}
	return adminapi.GetDeviceEffectiveSudo200JSONResponse(out), nil
}

func (h *handlers) UpdateOrganization(ctx context.Context, req adminapi.UpdateOrganizationRequestObject) (adminapi.UpdateOrganizationResponseObject, error) {
	o, err := h.orgs.SetDomains(ctx, req.Id, req.Body.Domains)
	if err != nil {
		return nil, err
	}
	return adminapi.UpdateOrganization200JSONResponse(toOrganization(o)), nil
}

func intPtr(v *int32) *int {
	if v == nil {
		return nil
	}
	n := int(*v)
	return &n
}
