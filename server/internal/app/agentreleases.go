package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/agentrelease"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// ArtifactStore stores agent binaries in the bucket paddock-agent-artifacts (objectstore.Store).
type ArtifactStore interface {
	Put(ctx context.Context, key, contentType, cacheControl string, body []byte) error
}

// VerifyRelease checks a minisign signature file over a binary with the configured release public key.
type VerifyRelease func(binary, minisig []byte) bool

// AgentReleases are the platform use cases of agent releases and staged rollouts (plan M2b decisions 19–22).
type AgentReleases struct {
	runner   *ActionRunner
	platform *db.PlatformPool
	store    ArtifactStore
	verify   VerifyRelease
	// development allows waves shorter than agentrelease.MinWaveMinutesProduction (PADDOCK_ENV=development).
	development bool
}

// NewAgentReleases creates the use cases. store and verify may be nil in roles that do not upload (worker).
func NewAgentReleases(runner *ActionRunner, platform *db.PlatformPool, store ArtifactStore, verify VerifyRelease, development bool) *AgentReleases {
	return &AgentReleases{runner: runner, platform: platform, store: store, verify: verify, development: development}
}

// Privileged actions of agent releases.
var (
	SpecAgentReleaseCreate  = ActionSpec{Code: audit.CodeAgentReleaseCreated, AllowedRoles: RolesPlatform}
	SpecAgentReleaseUpload  = ActionSpec{Code: audit.CodeAgentReleaseArtifactUploaded, AllowedRoles: RolesPlatform}
	SpecAgentReleasePublish = ActionSpec{Code: audit.CodeAgentReleasePublished, AllowedRoles: RolesPlatform}
	SpecAgentRolloutStart   = ActionSpec{Code: audit.CodeAgentRolloutStarted, AllowedRoles: RolesPlatform}
	SpecAgentRolloutHalt    = ActionSpec{Code: audit.CodeAgentRolloutHalted, AllowedRoles: RolesPlatform}
	SpecAgentRolloutResume  = ActionSpec{Code: audit.CodeAgentRolloutResumed, AllowedRoles: RolesPlatform}
)

func releaseTarget(version string) audit.Target {
	return audit.Target{Type: "agent_release", ID: version, Display: version}
}

// List returns one page of releases with their rollout status.
func (a *AgentReleases) List(ctx context.Context, page ListPage, statuses []string) (Listed[pgstore.ListAgentReleasesRow], error) {
	var out Listed[pgstore.ListAgentReleasesRow]
	if _, err := RequirePlatform(ctx); err != nil {
		return out, err
	}
	err := a.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		n, err := q.CountAgentReleases(ctx, pgstore.CountAgentReleasesParams{QPattern: page.QPattern, Statuses: statuses, CountLimit: countLimit})
		if err != nil {
			return fmt.Errorf("count agent releases: %w", err)
		}
		out.Count = int(n)
		out.Items, err = q.ListAgentReleases(ctx, pgstore.ListAgentReleasesParams{
			QPattern: page.QPattern, Statuses: statuses, Sort: page.Sort, SkipRows: page.Offset, MaxRows: page.Limit,
		})
		if err != nil {
			return fmt.Errorf("list agent releases: %w", err)
		}
		return nil
	})
	return out, err
}

// ReleaseDetail is a release with its artifacts and rollout.
type ReleaseDetail struct {
	Release   pgstore.AgentRelease
	Artifacts []pgstore.AgentArtifact
	Rollout   *pgstore.AgentRollout
	Stats     pgstore.AgentRolloutStatsRow // devices in the current wave; failed and updated devices
}

// Get returns a release with artifacts, rollout and its counts.
func (a *AgentReleases) Get(ctx context.Context, version string) (ReleaseDetail, error) {
	var d ReleaseDetail
	if _, err := RequirePlatform(ctx); err != nil {
		return d, err
	}
	err := a.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		if d.Release, err = q.GetAgentRelease(ctx, version); err != nil {
			return notFound(err)
		}
		if d.Artifacts, err = q.ListAgentArtifacts(ctx, version); err != nil {
			return err
		}
		r, err := q.GetAgentRollout(ctx, version)
		if db.IsNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		d.Rollout = &r
		d.Stats, err = q.AgentRolloutStats(ctx, pgstore.AgentRolloutStatsParams{Version: version, Percent: r.Waves[r.CurrentWaveIndex]})
		return err
	})
	return d, err
}

// Create creates a draft release.
func (a *AgentReleases) Create(ctx context.Context, version string) (pgstore.AgentRelease, error) {
	spec := SpecAgentReleaseCreate
	spec.Params = map[string]any{"version": version}
	t := releaseTarget(version)
	spec.Target = &t
	var out pgstore.AgentRelease
	err := a.runner.RunTx(ctx, ScopePlatform, spec, func(ctx context.Context, q *pgstore.Queries, _ Recorder) error {
		if err := agentrelease.ValidateVersion(version); err != nil {
			return problem.InvalidRequest.WithDetail(err.Error())
		}
		var err error
		out, err = q.InsertAgentRelease(ctx, pgstore.InsertAgentReleaseParams{Version: version, CreatedBy: actorName(ctx)})
		if db.IsUniqueViolation(err, "") {
			return problem.AlreadyExists.WithDetail("a release with this version exists")
		}
		return err
	})
	return out, err
}

// UploadArtifact verifies the binary's minisign signature with the release public key and stores it as the
// artifact of arch. Published releases are immutable.
func (a *AgentReleases) UploadArtifact(ctx context.Context, version, arch string, binary []byte, minisigB64 string) (pgstore.AgentArtifact, error) {
	sum := sha256.Sum256(binary)
	art := pgstore.UpsertAgentArtifactParams{
		Version: version, Arch: arch, Sha256: hex.EncodeToString(sum[:]), Size: int64(len(binary)), Minisig: minisigB64,
		ObjectKey: agentrelease.ObjectKey(version, arch),
	}
	spec := SpecAgentReleaseUpload
	spec.Params = map[string]any{"version": version, "arch": arch, "sha256": art.Sha256, "size": art.Size}
	t := releaseTarget(version)
	spec.Target = &t
	var out pgstore.AgentArtifact
	err := a.runner.RunExternal(ctx, ScopePlatform, spec,
		func(ctx context.Context, q *pgstore.Queries, _ Recorder) error {
			if err := agentrelease.ValidateArch(arch); err != nil {
				return problem.InvalidRequest.WithDetail(err.Error())
			}
			if len(binary) == 0 || len(binary) > agentrelease.MaxArtifactBytes {
				return problem.InvalidRequest.WithDetail("the binary must have 1 byte to 128 MiB")
			}
			sig, err := base64.StdEncoding.DecodeString(minisigB64)
			if err != nil || a.verify == nil || !a.verify(binary, sig) {
				return problem.InvalidRequest.WithDetail("X-Paddock-Minisig does not verify with the release public key")
			}
			r, err := q.GetAgentRelease(ctx, version)
			if err != nil {
				return notFound(err)
			}
			if r.Status != agentrelease.StatusDraft {
				return problem.InvalidState.WithDetail("artifacts of a published release cannot change")
			}
			return nil
		},
		func(ctx context.Context) error {
			return a.store.Put(ctx, art.ObjectKey, "application/octet-stream", "no-store", binary)
		},
		func(ctx context.Context, q *pgstore.Queries, _ Recorder, externalErr error) error {
			if externalErr != nil {
				return nil
			}
			var err error
			out, err = q.UpsertAgentArtifact(ctx, art)
			return err
		})
	if err != nil && problem.From(err) == problem.Internal {
		slog.ErrorContext(ctx, "storing an agent artifact failed", "version", version, "arch", arch, "error", err)
		return out, problem.UpstreamUnavailable.WithDetail("the artifact store is unavailable")
	}
	return out, err
}

// Publish makes a draft release with at least one artifact available for rollouts.
func (a *AgentReleases) Publish(ctx context.Context, version string) (pgstore.AgentRelease, error) {
	spec := SpecAgentReleasePublish
	spec.Params = map[string]any{"version": version}
	t := releaseTarget(version)
	spec.Target = &t
	var out pgstore.AgentRelease
	err := a.runner.RunTx(ctx, ScopePlatform, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		r, err := q.GetAgentRelease(ctx, version)
		if err != nil {
			return notFound(err)
		}
		if r.Status != agentrelease.StatusDraft {
			return problem.InvalidState.WithDetail("the release is already published")
		}
		arts, err := q.ListAgentArtifacts(ctx, version)
		if err != nil {
			return err
		}
		if len(arts) == 0 {
			return problem.InvalidState.WithDetail("upload at least one artifact before publishing")
		}
		arches := make([]string, len(arts))
		for i, art := range arts {
			arches[i] = art.Arch
		}
		rec.SetParam("arches", arches)
		out, err = q.PublishAgentRelease(ctx, version)
		return err
	})
	return out, err
}

// RolloutOptions override the rollout defaults; nil keeps the default.
type RolloutOptions struct {
	Waves                   []int
	MinWaveMinutes          *int
	FailureThresholdPercent *int
	FailureThresholdMin     *int
}

// StartRollout starts the staged rollout of a published release. Only one rollout runs at a time.
func (a *AgentReleases) StartRollout(ctx context.Context, version string, o RolloutOptions) (pgstore.AgentRollout, error) {
	p := pgstore.InsertAgentRolloutParams{
		Version: version, MinWaveMinutes: agentrelease.DefaultMinWaveMinutes,
		FailureThresholdPercent: agentrelease.DefaultFailureThresholdPercent,
		FailureThresholdMin:     agentrelease.DefaultFailureThresholdMin, StartedBy: actorName(ctx),
	}
	waves := agentrelease.DefaultWaves
	if o.Waves != nil {
		waves = o.Waves
	}
	for _, w := range waves {
		p.Waves = append(p.Waves, int32(w)) //nolint:gosec // validated 1..100
	}
	setInt := func(dst *int32, src *int) {
		if src != nil {
			*dst = int32(min(max(*src, -1), 1<<30)) //nolint:gosec // clamped
		}
	}
	setInt(&p.MinWaveMinutes, o.MinWaveMinutes)
	setInt(&p.FailureThresholdPercent, o.FailureThresholdPercent)
	setInt(&p.FailureThresholdMin, o.FailureThresholdMin)
	spec := SpecAgentRolloutStart
	spec.Params = map[string]any{
		"version": version, "waves": waves, "min_wave_minutes": p.MinWaveMinutes,
		"failure_threshold_percent": p.FailureThresholdPercent, "failure_threshold_min": p.FailureThresholdMin,
	}
	t := releaseTarget(version)
	spec.Target = &t
	var out pgstore.AgentRollout
	err := a.runner.RunTx(ctx, ScopePlatform, spec, func(ctx context.Context, q *pgstore.Queries, _ Recorder) error {
		if err := a.validateRollout(waves, p); err != nil {
			return err
		}
		r, err := q.GetAgentRelease(ctx, version)
		if err != nil {
			return notFound(err)
		}
		if r.Status != agentrelease.StatusPublished {
			return problem.InvalidState.WithDetail("only published releases can be rolled out")
		}
		if _, err := q.GetAgentRollout(ctx, version); err == nil {
			return problem.AlreadyExists.WithDetail("this release already has a rollout; resume it instead")
		}
		out, err = q.InsertAgentRollout(ctx, p)
		if db.IsUniqueViolation(err, "agent_rollout_one_running_idx") {
			return problem.InvalidState.WithDetail("another rollout is running; halt it first")
		}
		return err
	})
	return out, err
}

func (a *AgentReleases) validateRollout(waves []int, p pgstore.InsertAgentRolloutParams) error {
	if err := agentrelease.ValidateWaves(waves); err != nil {
		return problem.InvalidRequest.WithDetail(err.Error())
	}
	minWave := int32(agentrelease.MinWaveMinutesProduction)
	if a.development {
		minWave = 1
	}
	switch {
	case p.MinWaveMinutes < minWave:
		return problem.InvalidRequest.WithDetail(fmt.Sprintf("min_wave_minutes must be at least %d", minWave))
	case p.FailureThresholdPercent < 0 || p.FailureThresholdPercent > 100:
		return problem.InvalidRequest.WithDetail("failure_threshold_percent must be between 0 and 100")
	case p.FailureThresholdMin < 0:
		return problem.InvalidRequest.WithDetail("failure_threshold_min must not be negative")
	}
	return nil
}

// Halt stops a running rollout; devices are no longer offered the release.
func (a *AgentReleases) Halt(ctx context.Context, version string) (pgstore.AgentRollout, error) {
	reason := "halted by a platform administrator"
	return a.transition(ctx, SpecAgentRolloutHalt, version, agentrelease.RolloutRunning, agentrelease.RolloutHalted, &reason)
}

// Resume continues a halted rollout in the wave where it stopped; a rollout that had completed becomes the current
// release again. Failures reported before the resume no longer count (plan M2.1 decision 1).
func (a *AgentReleases) Resume(ctx context.Context, version string) (pgstore.AgentRollout, error) {
	return a.transition(ctx, SpecAgentRolloutResume, version, agentrelease.RolloutHalted, "", nil)
}

// transition moves a rollout from status from to status to; an empty to resumes (running, or completed when the
// rollout had completed).
func (a *AgentReleases) transition(ctx context.Context, spec ActionSpec, version, from, to string, reason *string) (pgstore.AgentRollout, error) {
	spec.Params = map[string]any{"version": version}
	if reason != nil {
		spec.Params["reason"] = *reason
	}
	t := releaseTarget(version)
	spec.Target = &t
	var out pgstore.AgentRollout
	err := a.runner.RunTx(ctx, ScopePlatform, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		r, err := q.GetAgentRollout(ctx, version)
		if err != nil {
			return notFound(err)
		}
		if r.Status != from {
			return problem.InvalidState.WithDetail("the rollout is " + r.Status)
		}
		rec.SetParam("wave", r.CurrentWaveIndex)
		if to != "" {
			out, err = q.SetAgentRolloutStatus(ctx, pgstore.SetAgentRolloutStatusParams{Version: version, Status: to, HaltedReason: reason})
		} else {
			status := agentrelease.RolloutRunning
			if r.CompletedAt != nil {
				status = agentrelease.RolloutCompleted
			}
			out, err = q.ResumeAgentRollout(ctx, pgstore.ResumeAgentRolloutParams{Version: version, Status: status})
		}
		if db.IsUniqueViolation(err, "agent_rollout_one_running_idx") {
			return problem.InvalidState.WithDetail("another rollout is running; halt it first")
		}
		return err
	})
	return out, err
}

// EvaluateRollouts is the worker's rollout round (plan M2b decision 22, M2.1 decision 1): every running rollout
// halts when its failed devices reach the threshold, otherwise advances or completes; the current release (a
// completed rollout that devices are offered) halts when its failures within agentrelease.CurrentReleaseWindow reach
// the threshold. Each change is audited with the system as actor. It returns what devices are offered now (nil:
// nothing).
func (a *AgentReleases) EvaluateRollouts(ctx context.Context, now time.Time) (*agentrelease.Offer, error) {
	var evaluated []pgstore.AgentRollout
	if err := a.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		if evaluated, err = q.ListRunningAgentRollouts(ctx); err != nil {
			return err
		}
		current, err := q.CurrentAgentRollout(ctx)
		if err == nil && current.Status == agentrelease.RolloutCompleted {
			evaluated = append(evaluated, current)
		}
		if db.IsNoRows(err) {
			return nil
		}
		return err
	}); err != nil {
		return nil, err
	}
	for _, r := range evaluated {
		if err := a.evaluate(ctx, r, now); err != nil {
			return nil, fmt.Errorf("evaluate rollout %s: %w", r.Version, err)
		}
	}
	return a.offer(ctx)
}

func (a *AgentReleases) evaluate(ctx context.Context, r pgstore.AgentRollout, now time.Time) error {
	stats, err := a.evaluationStats(ctx, r, now)
	if err != nil {
		return err
	}
	waves := make([]int, len(r.Waves))
	for i, w := range r.Waves {
		waves[i] = int(w)
	}
	in := agentrelease.Rollout{
		Waves: waves, CurrentWave: int(r.CurrentWaveIndex), WaveStartedAt: r.WaveStartedAt, MinWaveMinutes: int(r.MinWaveMinutes),
		FailurePercent: int(r.FailureThresholdPercent), FailureMin: int(r.FailureThresholdMin), Status: r.Status,
		Eligible: stats.Eligible, Failed: stats.Failed,
	}
	t := releaseTarget(r.Version)
	params := map[string]any{"version": r.Version, "eligible": stats.Eligible, "failed": stats.Failed}
	var spec ActionSpec
	var fn func(ctx context.Context, q *pgstore.Queries) error
	switch agentrelease.Decide(in, now) {
	case agentrelease.Halt:
		threshold := agentrelease.Threshold(stats.Eligible, in.FailurePercent, in.FailureMin)
		reason := fmt.Sprintf("%d failed devices reached the threshold of %d", stats.Failed, threshold)
		if r.Status == agentrelease.RolloutCompleted {
			reason = fmt.Sprintf("%d failed devices since %s reached the threshold of %d for the current release",
				stats.Failed, agentrelease.CurrentReleaseSince(r.EvaluationSince, now).UTC().Format(time.RFC3339), threshold)
		}
		params["reason"], params["wave"], params["threshold"] = reason, r.CurrentWaveIndex, threshold
		spec = ActionSpec{Code: audit.CodeAgentRolloutHalted}
		fn = func(ctx context.Context, q *pgstore.Queries) error {
			_, err := q.SetAgentRolloutStatus(ctx, pgstore.SetAgentRolloutStatusParams{Version: r.Version, Status: agentrelease.RolloutHalted, HaltedReason: &reason})
			return err
		}
	case agentrelease.Advance:
		params["wave"], params["percent"] = r.CurrentWaveIndex+1, r.Waves[r.CurrentWaveIndex+1]
		spec = ActionSpec{Code: audit.CodeAgentRolloutAdvanced}
		fn = func(ctx context.Context, q *pgstore.Queries) error {
			_, err := q.AdvanceAgentRollout(ctx, r.Version)
			return err
		}
	case agentrelease.Complete:
		spec = ActionSpec{Code: audit.CodeAgentRolloutCompleted}
		fn = func(ctx context.Context, q *pgstore.Queries) error {
			_, err := q.CompleteAgentRollout(ctx, r.Version)
			return err
		}
	default:
		return nil
	}
	spec.Target, spec.Params = &t, params
	slog.InfoContext(ctx, "agent rollout changed", "version", r.Version, "code", spec.Code, "eligible", stats.Eligible, "failed", stats.Failed)
	return a.runner.RunTx(ctx, ScopePlatform, spec, func(ctx context.Context, q *pgstore.Queries, _ Recorder) error { return fn(ctx, q) })
}

// evaluationStats counts the eligible and failed devices of a rollout: in the waves up to the current one with the
// failures since its start or last resume while it runs, and from agentrelease.CurrentReleaseSince once it is the
// current release.
func (a *AgentReleases) evaluationStats(ctx context.Context, r pgstore.AgentRollout, now time.Time) (pgstore.AgentRolloutStatsRow, error) {
	var stats pgstore.AgentRolloutStatsRow
	err := a.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		if r.Status == agentrelease.RolloutCompleted {
			c, err := q.CurrentReleaseStats(ctx, pgstore.CurrentReleaseStatsParams{Version: r.Version, Since: agentrelease.CurrentReleaseSince(r.EvaluationSince, now)})
			stats.Eligible, stats.Failed = c.Offered, c.Failed
			return err
		}
		e, err := q.RolloutEvaluationStats(ctx, pgstore.RolloutEvaluationStatsParams{
			Version: r.Version, Percent: r.Waves[r.CurrentWaveIndex], Since: r.EvaluationSince,
		})
		stats.Eligible, stats.Failed = e.Eligible, e.Failed
		return err
	})
	return stats, err
}

// offer reads the rollout devices are offered and its artifacts.
func (a *AgentReleases) offer(ctx context.Context) (*agentrelease.Offer, error) {
	var out *agentrelease.Offer
	err := a.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		r, err := q.CurrentAgentRollout(ctx)
		if db.IsNoRows(err) || (err == nil && r.Status == agentrelease.RolloutHalted) {
			return nil
		}
		if err != nil {
			return err
		}
		arts, err := q.ListAgentArtifacts(ctx, r.Version)
		if err != nil {
			return err
		}
		o := agentrelease.Offer{Version: r.Version, Status: r.Status, CurrentWave: int(r.CurrentWaveIndex), Artifacts: map[string]agentrelease.Artifact{}}
		for _, w := range r.Waves {
			o.Waves = append(o.Waves, int(w))
		}
		for _, art := range arts {
			o.Artifacts[art.Arch] = agentrelease.Artifact{SHA256: art.Sha256, Size: art.Size, Minisig: art.Minisig, ObjectKey: art.ObjectKey}
		}
		out = &o
		return nil
	})
	return out, err
}

// actorName is the recorded creator of releases and rollouts.
func actorName(ctx context.Context) string {
	p, _ := principal.From(ctx)
	if p.Display != "" {
		return p.Display
	}
	return p.ID.String()
}
