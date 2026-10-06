package admin

import (
	"context"
	"io"
	"net/url"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/agentrelease"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/listing"
)

// agentReleaseList is the list definition of GET /api/platform/v1/agent-releases (plan M2b decision 20).
var agentReleaseList = listing.Spec{Sort: []string{"version", "created_at", "status"}, DefaultSort: "-created_at"}

func (h *handlers) ListAgentReleases(ctx context.Context, req adminapi.ListAgentReleasesRequestObject) (adminapi.ListAgentReleasesResponseObject, error) {
	params, err := listing.Parse(agentReleaseList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	statuses, err := listing.Enum("status", req.Params.Status)
	if err != nil {
		return nil, err
	}
	res, err := h.releases.List(ctx, params.ListPage(), statuses)
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.AgentRelease, len(res.Items))
	for i, r := range res.Items {
		var rollout *string
		if r.RolloutStatus != "" {
			rollout = &r.RolloutStatus
		}
		items[i] = toAgentRelease(pgstore.AgentRelease{Version: r.Version, Status: r.Status, CreatedBy: r.CreatedBy,
			CreatedAt: r.CreatedAt, PublishedAt: r.PublishedAt}, int(r.ArtifactCount), rollout)
	}
	return adminapi.ListAgentReleases200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func (h *handlers) CreateAgentRelease(ctx context.Context, req adminapi.CreateAgentReleaseRequestObject) (adminapi.CreateAgentReleaseResponseObject, error) {
	r, err := h.releases.Create(ctx, req.Body.Version)
	if err != nil {
		return nil, err
	}
	loc := "/api/platform/v1/agent-releases/" + url.PathEscape(r.Version)
	return adminapi.CreateAgentRelease201JSONResponse{
		Body: toAgentRelease(r, 0, nil), Headers: adminapi.CreateAgentRelease201ResponseHeaders{Location: &loc},
	}, nil
}

func (h *handlers) GetAgentRelease(ctx context.Context, req adminapi.GetAgentReleaseRequestObject) (adminapi.GetAgentReleaseResponseObject, error) {
	d, err := h.releases.Get(ctx, req.Version)
	if err != nil {
		return nil, err
	}
	return adminapi.GetAgentRelease200JSONResponse(toAgentReleaseDetail(d)), nil
}

func (h *handlers) UploadAgentArtifact(ctx context.Context, req adminapi.UploadAgentArtifactRequestObject) (adminapi.UploadAgentArtifactResponseObject, error) {
	body, err := io.ReadAll(io.LimitReader(req.Body, agentrelease.MaxArtifactBytes+1))
	if err != nil {
		return nil, problem.InvalidRequest.WithDetail("unreadable body")
	}
	a, err := h.releases.UploadArtifact(ctx, req.Version, req.Arch, body, req.Params.XPaddockMinisig)
	if err != nil {
		return nil, err
	}
	return adminapi.UploadAgentArtifact200JSONResponse(toAgentArtifact(a)), nil
}

func (h *handlers) PublishAgentRelease(ctx context.Context, req adminapi.PublishAgentReleaseRequestObject) (adminapi.PublishAgentReleaseResponseObject, error) {
	if _, err := h.releases.Publish(ctx, req.Version); err != nil {
		return nil, err
	}
	d, err := h.releases.Get(ctx, req.Version)
	if err != nil {
		return nil, err
	}
	return adminapi.PublishAgentRelease200JSONResponse(toAgentReleaseDetail(d).Release), nil
}

func (h *handlers) StartAgentRollout(ctx context.Context, req adminapi.StartAgentRolloutRequestObject) (adminapi.StartAgentRolloutResponseObject, error) {
	var o app.RolloutOptions
	if b := req.Body; b != nil {
		if b.Waves != nil {
			o.Waves = *b.Waves
		}
		o.MinWaveMinutes, o.FailureThresholdPercent, o.FailureThresholdMin = b.MinWaveMinutes, b.FailureThresholdPercent, b.FailureThresholdMin
	}
	r, err := h.releases.StartRollout(ctx, req.Version, o)
	if err != nil {
		return nil, err
	}
	return adminapi.StartAgentRollout201JSONResponse(toAgentRollout(r)), nil
}

func (h *handlers) HaltAgentRollout(ctx context.Context, req adminapi.HaltAgentRolloutRequestObject) (adminapi.HaltAgentRolloutResponseObject, error) {
	r, err := h.releases.Halt(ctx, req.Version)
	if err != nil {
		return nil, err
	}
	return adminapi.HaltAgentRollout200JSONResponse(toAgentRollout(r)), nil
}

func (h *handlers) ResumeAgentRollout(ctx context.Context, req adminapi.ResumeAgentRolloutRequestObject) (adminapi.ResumeAgentRolloutResponseObject, error) {
	r, err := h.releases.Resume(ctx, req.Version)
	if err != nil {
		return nil, err
	}
	return adminapi.ResumeAgentRollout200JSONResponse(toAgentRollout(r)), nil
}

func toAgentRelease(r pgstore.AgentRelease, artifacts int, rollout *string) adminapi.AgentRelease {
	out := adminapi.AgentRelease{
		Version: r.Version, Status: adminapi.AgentReleaseStatus(r.Status), CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt.UTC(),
		PublishedAt: utcPtr(r.PublishedAt), ArtifactCount: artifacts,
	}
	if rollout != nil {
		s := adminapi.AgentRolloutStatus(*rollout)
		out.RolloutStatus = &s
	}
	return out
}

func toAgentArtifact(a pgstore.AgentArtifact) adminapi.AgentArtifact {
	return adminapi.AgentArtifact{Arch: adminapi.AgentArtifactArch(a.Arch), Sha256: a.Sha256, Size: a.Size, CreatedAt: a.CreatedAt.UTC()}
}

func toAgentRollout(r pgstore.AgentRollout) adminapi.AgentRollout {
	waves := make([]int, len(r.Waves))
	for i, w := range r.Waves {
		waves[i] = int(w)
	}
	return adminapi.AgentRollout{
		Version: r.Version, Waves: waves, CurrentWaveIndex: int(r.CurrentWaveIndex), WaveStartedAt: r.WaveStartedAt.UTC(),
		MinWaveMinutes: int(r.MinWaveMinutes), FailureThresholdPercent: int(r.FailureThresholdPercent),
		FailureThresholdMin: int(r.FailureThresholdMin), Status: adminapi.AgentRolloutStatus(r.Status),
		HaltedReason: r.HaltedReason, StartedBy: r.StartedBy, StartedAt: r.StartedAt.UTC(),
	}
}

func toAgentReleaseDetail(d app.ReleaseDetail) adminapi.AgentReleaseDetail {
	var rolloutStatus *string
	if d.Rollout != nil {
		rolloutStatus = &d.Rollout.Status
	}
	out := adminapi.AgentReleaseDetail{
		Release: toAgentRelease(d.Release, len(d.Artifacts), rolloutStatus), Artifacts: make([]adminapi.AgentArtifact, len(d.Artifacts)),
	}
	for i, a := range d.Artifacts {
		out.Artifacts[i] = toAgentArtifact(a)
	}
	if d.Rollout != nil {
		r := toAgentRollout(*d.Rollout)
		out.Rollout = &r
		out.Counts = &adminapi.AgentRolloutCounts{Eligible: d.Stats.Eligible, Updated: d.Stats.Updated, Failed: d.Stats.Failed}
	}
	return out
}
