package admin

import (
	"context"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/listing"
)

// List definitions of the backup targets and runs (plan M15 decision 13).
var (
	backupTargetList = listing.Spec{Sort: []string{"name", "type", "created_at"}, DefaultSort: "name"}
	backupRunList    = listing.Spec{Sort: []string{"started_at", "kind", "outcome"}, DefaultSort: "-started_at"}
	// The restore plans (plan M15 decision 26).
	backupRestorePlanList = listing.Spec{Sort: []string{"created_at", "state"}, DefaultSort: "-created_at"}
)

func (h *handlers) GetBackupOverview(ctx context.Context, _ adminapi.GetBackupOverviewRequestObject) (adminapi.GetBackupOverviewResponseObject, error) {
	o, err := h.backupRuns.Overview(ctx)
	if err != nil {
		return nil, err
	}
	targets := make([]adminapi.BackupTarget, len(o.Targets))
	for i, t := range o.Targets {
		targets[i] = toBackupTarget(t)
	}
	stanzas := make([]adminapi.BackupStanza, len(o.Repo.Stanzas))
	for i, s := range o.Repo.Stanzas {
		stanzas[i] = adminapi.BackupStanza{Name: s.Name, LastFullAt: utcPtr(s.LastFullAt), WalArchivedAt: utcPtr(s.WALArchivedAt)}
	}
	return adminapi.GetBackupOverview200JSONResponse{
		Key:      toBackupKeyStatus(o.Key),
		Schedule: toBackupSchedule(o.Schedule),
		Targets:  targets,
		Repo:     adminapi.BackupRepo{Path: o.Repo.Path, BytesUsed: o.Repo.BytesUsed, BytesFree: o.Repo.BytesFree, Stanzas: stanzas},
		LastRuns: toBackupRuns(o.LastRuns),
	}, nil
}

func (h *handlers) GetBackupSchedule(ctx context.Context, _ adminapi.GetBackupScheduleRequestObject) (adminapi.GetBackupScheduleResponseObject, error) {
	s, err := h.backupSchedule.Get(ctx)
	if err != nil {
		return nil, err
	}
	return adminapi.GetBackupSchedule200JSONResponse(toBackupSchedule(s)), nil
}

func (h *handlers) PutBackupSchedule(ctx context.Context, req adminapi.PutBackupScheduleRequestObject) (adminapi.PutBackupScheduleResponseObject, error) {
	b := req.Body
	s, err := h.backupSchedule.Put(ctx, backupset.Schedule{
		FullIntervalHours: b.FullIntervalHours, OpenBaoIntervalHours: b.OpenbaoIntervalHours,
		FleetIntervalHours: b.FleetIntervalHours, EscrowIntervalHours: b.EscrowIntervalHours,
		RetentionFull: b.RetentionFull, OpenBaoKeepDays: b.OpenbaoKeepDays, FleetKeepDays: b.FleetKeepDays,
	})
	if err != nil {
		return nil, err
	}
	return adminapi.PutBackupSchedule200JSONResponse(toBackupSchedule(s)), nil
}

func (h *handlers) ListBackupTargets(ctx context.Context, req adminapi.ListBackupTargetsRequestObject) (adminapi.ListBackupTargetsResponseObject, error) {
	params, err := listing.Parse(backupTargetList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	types, err := listing.Enum("type", req.Params.Type)
	if err != nil {
		return nil, err
	}
	states, err := listing.Enum("host_state", req.Params.HostState)
	if err != nil {
		return nil, err
	}
	res, err := h.backupTargets.List(ctx, app.TargetQuery{Page: params.ListPage(), Types: types,
		Enabled: req.Params.Enabled, HostStates: states})
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.BackupTarget, len(res.Items))
	for i, t := range res.Items {
		items[i] = toBackupTarget(t)
	}
	return adminapi.ListBackupTargets200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func (h *handlers) CreateBackupTarget(ctx context.Context, req adminapi.CreateBackupTargetRequestObject) (adminapi.CreateBackupTargetResponseObject, error) {
	t, err := h.backupTargets.Create(ctx, toTargetInput(req.Body))
	if err != nil {
		return nil, err
	}
	loc := "/api/platform/v1/backup/targets/" + t.ID.String()
	return adminapi.CreateBackupTarget201JSONResponse{
		Body: toBackupTarget(t), Headers: adminapi.CreateBackupTarget201ResponseHeaders{Location: &loc},
	}, nil
}

func (h *handlers) GetBackupTarget(ctx context.Context, req adminapi.GetBackupTargetRequestObject) (adminapi.GetBackupTargetResponseObject, error) {
	t, err := h.backupTargets.Get(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.GetBackupTarget200JSONResponse(toBackupTarget(t)), nil
}

func (h *handlers) UpdateBackupTarget(ctx context.Context, req adminapi.UpdateBackupTargetRequestObject) (adminapi.UpdateBackupTargetResponseObject, error) {
	t, err := h.backupTargets.Update(ctx, req.Id, toTargetInput(req.Body))
	if err != nil {
		return nil, err
	}
	return adminapi.UpdateBackupTarget200JSONResponse(toBackupTarget(t)), nil
}

func (h *handlers) DeleteBackupTarget(ctx context.Context, req adminapi.DeleteBackupTargetRequestObject) (adminapi.DeleteBackupTargetResponseObject, error) {
	if err := h.backupTargets.Delete(ctx, req.Id); err != nil {
		return nil, err
	}
	return adminapi.DeleteBackupTarget204Response{}, nil
}

func (h *handlers) TestBackupTarget(ctx context.Context, req adminapi.TestBackupTargetRequestObject) (adminapi.TestBackupTargetResponseObject, error) {
	t, err := h.backupTargets.Test(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.TestBackupTarget202JSONResponse(toBackupTarget(t)), nil
}

func (h *handlers) EnableBackupTarget(ctx context.Context, req adminapi.EnableBackupTargetRequestObject) (adminapi.EnableBackupTargetResponseObject, error) {
	t, err := h.backupTargets.Enable(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.EnableBackupTarget200JSONResponse(toBackupTarget(t)), nil
}

func (h *handlers) DisableBackupTarget(ctx context.Context, req adminapi.DisableBackupTargetRequestObject) (adminapi.DisableBackupTargetResponseObject, error) {
	t, err := h.backupTargets.Disable(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.DisableBackupTarget200JSONResponse(toBackupTarget(t)), nil
}

func (h *handlers) RequestBackupRun(ctx context.Context, req adminapi.RequestBackupRunRequestObject) (adminapi.RequestBackupRunResponseObject, error) {
	var kinds []string
	if req.Body.Kinds != nil {
		for _, k := range *req.Body.Kinds {
			kinds = append(kinds, string(k))
		}
	}
	runs, err := h.backupRuns.Request(ctx, kinds, deref(req.Body.Label, ""))
	if err != nil {
		return nil, err
	}
	return adminapi.RequestBackupRun202JSONResponse(toBackupRuns(runs)), nil
}

func (h *handlers) ListBackupRuns(ctx context.Context, req adminapi.ListBackupRunsRequestObject) (adminapi.ListBackupRunsResponseObject, error) {
	params, err := listing.Parse(backupRunList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	kinds, err := listing.Enum("kind", req.Params.Kind)
	if err != nil {
		return nil, err
	}
	outcomes, err := listing.Enum("outcome", req.Params.Outcome)
	if err != nil {
		return nil, err
	}
	res, err := h.backupRuns.List(ctx, app.BackupRunQuery{Page: params.ListPage(), Kinds: kinds, Outcomes: outcomes,
		TargetID: req.Params.TargetId})
	if err != nil {
		return nil, err
	}
	return adminapi.ListBackupRuns200JSONResponse(listing.NewPage(toBackupRuns(res.Items), params, res.Count)), nil
}

func (h *handlers) ListBackupRestorePlans(ctx context.Context, req adminapi.ListBackupRestorePlansRequestObject) (adminapi.ListBackupRestorePlansResponseObject, error) {
	params, err := listing.Parse(backupRestorePlanList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	states, err := listing.Enum("state", req.Params.State)
	if err != nil {
		return nil, err
	}
	res, err := h.backupRestorePlans.List(ctx, app.RestorePlanQuery{Page: params.ListPage(), States: states})
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.BackupRestorePlan, len(res.Items))
	for i, p := range res.Items {
		items[i] = toBackupRestorePlan(p)
	}
	return adminapi.ListBackupRestorePlans200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func (h *handlers) CreateBackupRestorePlan(ctx context.Context, req adminapi.CreateBackupRestorePlanRequestObject) (adminapi.CreateBackupRestorePlanResponseObject, error) {
	b := req.Body
	in := app.PlanInput{Kind: string(b.Kind), SourceTargetID: b.SourceTargetId, At: b.At, Confirmation: b.Confirmation}
	for _, c := range b.Components {
		in.Components = append(in.Components, string(c))
	}
	p, err := h.backupRestorePlans.Create(ctx, in)
	if err != nil {
		return nil, err
	}
	loc := "/api/platform/v1/backup/restore-plans/" + p.ID.String()
	return adminapi.CreateBackupRestorePlan201JSONResponse{
		Body: toBackupRestorePlan(p), Headers: adminapi.CreateBackupRestorePlan201ResponseHeaders{Location: &loc},
	}, nil
}

func (h *handlers) GetBackupRestorePlan(ctx context.Context, req adminapi.GetBackupRestorePlanRequestObject) (adminapi.GetBackupRestorePlanResponseObject, error) {
	p, err := h.backupRestorePlans.Get(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.GetBackupRestorePlan200JSONResponse(toBackupRestorePlan(p)), nil
}

func (h *handlers) CancelBackupRestorePlan(ctx context.Context, req adminapi.CancelBackupRestorePlanRequestObject) (adminapi.CancelBackupRestorePlanResponseObject, error) {
	p, err := h.backupRestorePlans.Cancel(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.CancelBackupRestorePlan200JSONResponse(toBackupRestorePlan(p)), nil
}

func toBackupRestorePlan(p app.Plan) adminapi.BackupRestorePlan {
	components := make([]adminapi.BackupRestorePlanComponents, len(p.Components))
	for i, c := range p.Components {
		components[i] = adminapi.BackupRestorePlanComponents(c)
	}
	return adminapi.BackupRestorePlan{
		Id: p.ID, Kind: adminapi.BackupRestorePlanKind(p.Kind), Source: adminapi.BackupRestorePlanSource(p.Source),
		SourceTargetId: p.SourceTargetID, SourceTargetName: p.SourceTargetName, At: utcPtr(p.At), Components: components,
		State: adminapi.BackupRestorePlanState(p.State), CreatedBy: p.CreatedBy, CreatedAt: p.CreatedAt.UTC(),
		ExpiresAt: utcPtr(p.ExpiresAt), StartedAt: utcPtr(p.StartedAt), FinishedAt: utcPtr(p.FinishedAt),
		OutcomeDetail: p.OutcomeDetail, HostCommand: p.HostCommand,
	}
}

// toTargetInput maps the body; only the group of the type is read by the use case, an absent group is empty and
// refused by its validation.
func toTargetInput(b *adminapi.BackupTargetInput) app.TargetInput {
	in := app.TargetInput{Name: b.Name, Type: backupset.TargetType(b.Type), Enabled: b.Enabled}
	if l := b.Local; l != nil {
		in.Local = backupset.Local{Path: l.Path}
	}
	if s := b.Smb; s != nil {
		in.SMB = backupset.SMB{Host: s.Host, Share: s.Share, Path: deref(s.Path, ""), Username: s.Username,
			Password: deref(s.Password, ""), Domain: deref(s.Domain, ""), Options: deref(s.Options, "")}
	}
	if n := b.Nfs; n != nil {
		in.NFS = backupset.NFS{Host: n.Host, Export: n.Export, Path: deref(n.Path, ""), Options: deref(n.Options, "")}
	}
	if s := b.S3; s != nil {
		in.S3 = backupset.S3{Endpoint: s.Endpoint, Bucket: s.Bucket, Region: deref(s.Region, ""),
			Prefix: deref(s.Prefix, ""), AccessKey: deref(s.AccessKey, ""), SecretKey: deref(s.SecretKey, ""),
			CAPEM: deref(s.CaPem, "")}
	}
	return in
}

func toBackupTarget(t app.Target) adminapi.BackupTarget {
	s := t.Settings
	var settings adminapi.BackupTargetSettings
	switch backupset.TargetType(t.Type) {
	case backupset.TypeLocal:
		settings.Local = &adminapi.BackupTargetLocalSettings{Path: s.Path}
	case backupset.TypeSMB:
		settings.Smb = &adminapi.BackupTargetSmbSettings{Host: s.Host, Share: s.Share, Path: s.Path, Username: s.Username,
			Domain: s.Domain, Options: s.Options}
	case backupset.TypeNFS:
		settings.Nfs = &adminapi.BackupTargetNfsSettings{Host: s.Host, Export: s.Export, Path: s.Path, Options: s.Options}
	case backupset.TypeS3:
		settings.S3 = &adminapi.BackupTargetS3Settings{Endpoint: s.Endpoint, Bucket: s.Bucket, Region: s.Region,
			Prefix: s.Prefix, CaPem: s.CAPEM}
	}
	status := make([]adminapi.BackupTargetKindStatus, len(t.Status))
	for i, st := range t.Status {
		status[i] = adminapi.BackupTargetKindStatus{Kind: adminapi.BackupKind(st.Kind), LastSuccessAt: utcPtr(st.LastSuccessAt),
			LastError: st.LastError, Bytes: st.Bytes}
	}
	return adminapi.BackupTarget{
		Id: t.ID, Name: t.Name, Type: adminapi.BackupTargetType(t.Type), Enabled: t.Enabled,
		HostState: adminapi.BackupTargetHostState(t.HostState), HostRevision: t.HostRevision, Settings: settings,
		HasCredentials: t.HasCredentials, TestRequestedAt: utcPtr(t.TestRequestedAt), LastTestAt: utcPtr(t.LastTestAt),
		LastTestOk: t.LastTestOK, LastTestError: t.LastTestError, Status: status, CreatedBy: t.CreatedBy,
		CreatedAt: t.CreatedAt.UTC(), UpdatedAt: t.UpdatedAt.UTC(),
	}
}

func toBackupSchedule(s app.ScheduleView) adminapi.BackupSchedule {
	return adminapi.BackupSchedule{
		FullIntervalHours: s.FullIntervalHours, OpenbaoIntervalHours: s.OpenBaoIntervalHours,
		FleetIntervalHours: s.FleetIntervalHours, EscrowIntervalHours: s.EscrowIntervalHours,
		RetentionFull: s.RetentionFull, OpenbaoKeepDays: s.OpenBaoKeepDays, FleetKeepDays: s.FleetKeepDays,
		UpdatedBy: s.UpdatedBy, UpdatedAt: utcPtr(s.UpdatedAt),
	}
}

func toBackupRuns(runs []app.Run) []adminapi.BackupRun {
	out := make([]adminapi.BackupRun, len(runs))
	for i, r := range runs {
		targets := make([]adminapi.BackupRunTarget, 0, len(r.Targets))
		for _, t := range r.Targets {
			// A malformed ID written by the backup role is left out instead of failing the whole list.
			id, err := uuid.Parse(t.TargetID)
			if err != nil {
				continue
			}
			var class *string
			if t.ErrorClass != "" {
				class = &t.ErrorClass
			}
			targets = append(targets, adminapi.BackupRunTarget{TargetId: id, Ok: t.OK, ErrorClass: class})
		}
		var outcome *adminapi.BackupRunOutcome
		if r.Outcome != nil {
			o := adminapi.BackupRunOutcome(*r.Outcome)
			outcome = &o
		}
		out[i] = adminapi.BackupRun{
			Id: r.ID, Kind: adminapi.BackupKind(r.Kind), Label: r.Label, State: adminapi.BackupRunState(r.State),
			Outcome: outcome, StartedAt: utcPtr(r.StartedAt), FinishedAt: utcPtr(r.FinishedAt), Bytes: r.Bytes,
			ErrorClass: r.ErrorClass, Targets: targets, RequestedBy: r.RequestedBy, CreatedAt: r.CreatedAt.UTC(),
		}
	}
	return out
}

func toBackupKey(k app.Key) adminapi.BackupKey {
	return adminapi.BackupKey{
		KeyId: k.KeyID, Fingerprint: k.Fingerprint, State: adminapi.BackupKeyState(k.State), CreatedAt: k.CreatedAt.UTC(),
		CreatedBy: k.CreatedBy, ConfirmedAt: utcPtr(k.ConfirmedAt), ConfirmedBy: k.ConfirmedBy,
		RetiredAt: utcPtr(k.RetiredAt), Attempts: k.Attempts, Legacy: k.Legacy, Positions: positionsPtr(k.Positions),
	}
}

func positionsPtr(p []int) *[]int {
	if p == nil {
		return nil
	}
	return &p
}

func toBackupKeyStatus(s app.KeyStatus) adminapi.BackupKeyStatus {
	out := adminapi.BackupKeyStatus{Retired: make([]adminapi.BackupKey, len(s.Retired))}
	if s.Active != nil {
		k := toBackupKey(*s.Active)
		out.Active = &k
	}
	if s.Pending != nil {
		k := toBackupKey(*s.Pending)
		out.Pending = &k
	}
	for i, k := range s.Retired {
		out.Retired[i] = toBackupKey(k)
	}
	return out
}
