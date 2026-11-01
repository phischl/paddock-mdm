package app

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/configrollout"
	"github.com/phischl/paddock-mdm/server/internal/domain/declarative"
	"github.com/phischl/paddock-mdm/server/internal/domain/statechange"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// The actions on a staged configuration rollout (plan M11 decision 32). The worker records halted, advanced and
// completed with the system as actor.
var (
	SpecConfigRolloutHalt     = ActionSpec{Code: audit.CodeConfigRolloutHalted, AllowedRoles: RolesWrite}
	SpecConfigRolloutResume   = ActionSpec{Code: audit.CodeConfigRolloutResumed, AllowedRoles: RolesWrite}
	SpecConfigRolloutAdvance  = ActionSpec{Code: audit.CodeConfigRolloutAdvanced, AllowedRoles: RolesWrite}
	SpecConfigRolloutComplete = ActionSpec{Code: audit.CodeConfigRolloutCompleted, AllowedRoles: RolesWrite}
)

// Report outcomes of a device in a rollout's device list: report_only is the report of a report-only device, whose
// plan errors are never a failed apply (plan M11 amendment R6.6); none is a bundle without a report.
const (
	RolloutReportApplied    = "applied"
	RolloutReportRejected   = "rejected"
	RolloutReportReportOnly = "report_only"
	RolloutReportNone       = "none"
)

// rolloutHaltReasonMax is the longest reason of a manual halt.
const rolloutHaltReasonMax = 500

// ConfigRollouts are the use cases of staged configuration rollouts: reading them, the administrator's wave actions
// and the worker's evaluation.
type ConfigRollouts struct {
	runner *ActionRunner
	org    *db.OrgPool
}

// NewConfigRollouts creates the use cases.
func NewConfigRollouts(runner *ActionRunner, org *db.OrgPool) *ConfigRollouts {
	return &ConfigRollouts{runner: runner, org: org}
}

// RolloutCounts are the devices of a rollout: eligible are the active devices inside the wave it reached, failed those
// whose newest report on a bundle of the rollout since its start or last resume is a rejection or names a failed
// staged resource (what the worker counts), applied those whose newest such report applied every staged resource, and
// pending the rest.
type RolloutCounts struct {
	Eligible, Applied, Failed, Pending int
}

// ConfigRolloutRecord is a rollout with its counts.
type ConfigRolloutRecord struct {
	pgstore.ConfigRollout
	Counts RolloutCounts
}

// ConfigRolloutDetail is a rollout with its change set and the resource IDs it stages.
type ConfigRolloutDetail struct {
	ConfigRolloutRecord
	ChangeSet         ChangeSetRecord
	StagedResourceIDs []string
}

// ConfigRolloutDevice is an active device as a rollout sees it: whether it is inside the wave, its newest bundle,
// whether that bundle carries the rollout, its report and the staged resources that failed in it.
type ConfigRolloutDevice struct {
	DeviceID          uuid.UUID
	Hostname          string
	InWave            bool
	BundleVersion     *int64
	CarriesRollout    bool
	ReportOutcome     string
	FailedResourceIDs []string
}

// ConfigRolloutDeviceQuery selects a page of a rollout's devices; nil and empty filters select every device.
type ConfigRolloutDeviceQuery struct {
	Page           ListPage
	InWave         *bool
	ReportOutcomes []string
}

// rolloutTarget is the audit target of a rollout.
func rolloutTarget(id uuid.UUID) audit.Target {
	return audit.Target{Type: "config_rollout", ID: id.String()}
}

// reachedPercent is the share of devices the rollout reached: the current wave while it is open, and the wave it had
// reached when it was reverted; every device once it completed.
func reachedPercent(r pgstore.ConfigRollout) int {
	waves := make([]int, len(r.Waves))
	for i, w := range r.Waves {
		waves[i] = int(w)
	}
	status := r.Status
	if status == configrollout.StatusReverted {
		// configrollout.Percent is what devices receive (nothing once reverted); the counts show how far it got.
		status = configrollout.StatusRunning
	}
	return configrollout.Percent(status, waves, int(r.CurrentWaveIndex))
}

// inWave reports whether device is inside the wave r reached.
func inWave(r pgstore.ConfigRollout, device uuid.UUID, canary map[uuid.UUID]bool) bool {
	return configrollout.Eligible(configrollout.Bucket(device, r.ID), reachedPercent(r), canary[device])
}

// stagedFailure reports whether failed names a staged resource.
func stagedFailure(failed, staged []string) bool {
	return slices.ContainsFunc(failed, func(id string) bool { return slices.Contains(staged, id) })
}

// deviceState is how the counts of a rollout see one device of its wave.
type deviceState int

const (
	statePending deviceState = iota
	stateApplied
	stateFailed
)

// countsAgainst reports whether rep counts toward the failure rate of r: received by the server since the rollout's
// start or last resume (plan M11 amendment R6.14). The server's time, not the device's: a device clock running behind
// would otherwise date a failure right after the start before it. The time is checked after the newest report was
// picked, so an older version reported late does not hide a newer one.
func countsAgainst(r pgstore.ConfigRollout, rep pgstore.ListConfigRolloutReportsRow) bool {
	return !rep.RecordedAt.Before(r.EvaluationSince)
}

// classify is the one rule of the worker's evaluation and of the API's counts (plan M11 decision 27, amendments R6.6
// and R6.14) for a device's newest report on a bundle of r (nil: none): failed is a rejection, or an enforced apply
// with a failed staged resource, reported since evaluation_since; the failed resources of a report-only device are
// plan errors and never count, its rejection does. Applied is an enforced apply without a failed staged resource;
// everything else is pending.
func classify(r pgstore.ConfigRollout, rep *pgstore.ListConfigRolloutReportsRow, staged []string) deviceState {
	switch {
	case rep == nil:
		return statePending
	case rep.Outcome == RolloutReportRejected:
		if countsAgainst(r, *rep) {
			return stateFailed
		}
		return statePending
	case rep.Mode == protocol.BundleModeReportOnly:
		return statePending
	case stagedFailure(rep.FailedResourceIds, staged):
		if countsAgainst(r, *rep) {
			return stateFailed
		}
		return statePending
	case rep.Outcome == RolloutReportApplied:
		return stateApplied
	}
	return statePending
}

// countRollout counts the active devices of r (RolloutCounts).
func countRollout(r pgstore.ConfigRollout, staged []string, devices []uuid.UUID, canary map[uuid.UUID]bool,
	reports map[uuid.UUID]pgstore.ListConfigRolloutReportsRow) RolloutCounts {
	var c RolloutCounts
	for _, d := range devices {
		if !inWave(r, d, canary) {
			continue
		}
		c.Eligible++
		var rep *pgstore.ListConfigRolloutReportsRow
		if row, ok := reports[d]; ok {
			rep = &row
		}
		switch classify(r, rep, staged) {
		case stateApplied:
			c.Applied++
		case stateFailed:
			c.Failed++
		default:
			c.Pending++
		}
	}
	return c
}

// stagedResourceIDs returns the resource IDs the plan of a change set stages.
func stagedResourceIDs(plan json.RawMessage) ([]string, error) {
	var p declarative.Plan
	if err := json.Unmarshal(plan, &p); err != nil {
		return nil, fmt.Errorf("decode the plan of the rollout's change set: %w", err)
	}
	return configrollout.StagedResourceIDs(p), nil
}

// rolloutWorld is what the counts of rollouts read: the active devices, the members of their canary groups and the
// devices' newest reports on bundles of the rollouts.
type rolloutWorld struct {
	devices []pgstore.ListConfigRolloutDevicesRow
	canary  map[uuid.UUID]map[uuid.UUID]bool
	reports map[uuid.UUID]map[uuid.UUID]pgstore.ListConfigRolloutReportsRow
}

// loadRolloutWorld reads the rolloutWorld of rollouts; q filters the devices by hostname.
func loadRolloutWorld(ctx context.Context, q *pgstore.Queries, rollouts []pgstore.ConfigRollout, hostname *string) (rolloutWorld, error) {
	w := rolloutWorld{canary: map[uuid.UUID]map[uuid.UUID]bool{}, reports: map[uuid.UUID]map[uuid.UUID]pgstore.ListConfigRolloutReportsRow{}}
	var err error
	if w.devices, err = q.ListConfigRolloutDevices(ctx, hostname); err != nil {
		return w, fmt.Errorf("list the active devices: %w", err)
	}
	ids := make([]uuid.UUID, len(rollouts))
	for i, r := range rollouts {
		ids[i] = r.ID
		if !r.CanaryDeviceGroupID.Valid || w.canary[r.CanaryDeviceGroupID.UUID] != nil {
			continue
		}
		members, err := q.ListActiveGroupMemberIDs(ctx, r.CanaryDeviceGroupID.UUID)
		if err != nil {
			return w, fmt.Errorf("list the canary devices: %w", err)
		}
		set := map[uuid.UUID]bool{}
		for _, m := range members {
			set[m] = true
		}
		w.canary[r.CanaryDeviceGroupID.UUID] = set
	}
	reports, err := q.ListConfigRolloutReports(ctx, ids)
	if err != nil {
		return w, fmt.Errorf("list the rollout reports: %w", err)
	}
	for _, rep := range reports {
		if w.reports[rep.RolloutID] == nil {
			w.reports[rep.RolloutID] = map[uuid.UUID]pgstore.ListConfigRolloutReportsRow{}
		}
		w.reports[rep.RolloutID][rep.DeviceID] = rep
	}
	return w, nil
}

// canaryOf returns the canary members of r (nil: none).
func (w rolloutWorld) canaryOf(r pgstore.ConfigRollout) map[uuid.UUID]bool {
	if !r.CanaryDeviceGroupID.Valid {
		return nil
	}
	return w.canary[r.CanaryDeviceGroupID.UUID]
}

// counts returns the RolloutCounts of r.
func (w rolloutWorld) counts(r pgstore.ConfigRollout, staged []string) RolloutCounts {
	ids := make([]uuid.UUID, len(w.devices))
	for i, d := range w.devices {
		ids[i] = d.ID
	}
	return countRollout(r, staged, ids, w.canaryOf(r), w.reports[r.ID])
}

// List returns one page of the organization's rollouts with their counts.
func (c *ConfigRollouts) List(ctx context.Context, page ListPage, statuses []string) (Listed[ConfigRolloutRecord], error) {
	var out Listed[ConfigRolloutRecord]
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := c.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		n, err := q.CountConfigRollouts(ctx, pgstore.CountConfigRolloutsParams{QPattern: page.QPattern, Statuses: statuses, CountLimit: countLimit})
		if err != nil {
			return fmt.Errorf("count rollouts: %w", err)
		}
		out.Count = int(n)
		rows, err := q.ListConfigRollouts(ctx, pgstore.ListConfigRolloutsParams{
			QPattern: page.QPattern, Statuses: statuses, Sort: page.Sort, SkipRows: page.Offset, MaxRows: page.Limit,
		})
		if err != nil {
			return fmt.Errorf("list rollouts: %w", err)
		}
		if len(rows) == 0 {
			return nil
		}
		rollouts := make([]pgstore.ConfigRollout, len(rows))
		for i, r := range rows {
			rollouts[i] = r.ConfigRollout
		}
		w, err := loadRolloutWorld(ctx, q, rollouts, nil)
		if err != nil {
			return err
		}
		out.Items = make([]ConfigRolloutRecord, len(rows))
		for i, r := range rows {
			staged, err := stagedResourceIDs(r.Plan)
			if err != nil {
				return err
			}
			out.Items[i] = ConfigRolloutRecord{ConfigRollout: r.ConfigRollout, Counts: w.counts(r.ConfigRollout, staged)}
		}
		return nil
	})
	return out, err
}

// Get returns a rollout with its counts, its change set and the resource IDs it stages; unknown and foreign rollouts
// are both not_found.
func (c *ConfigRollouts) Get(ctx context.Context, id uuid.UUID) (ConfigRolloutDetail, error) {
	var out ConfigRolloutDetail
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := c.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		r, err := q.GetConfigRollout(ctx, id)
		if err != nil {
			return notFound(err)
		}
		cs, err := q.GetChangeSet(ctx, r.ChangeSetID)
		if err != nil {
			return fmt.Errorf("read the change set of rollout %s: %w", id, err)
		}
		staged, err := stagedResourceIDs(cs.Plan)
		if err != nil {
			return err
		}
		w, err := loadRolloutWorld(ctx, q, []pgstore.ConfigRollout{r}, nil)
		if err != nil {
			return err
		}
		out = ConfigRolloutDetail{
			ConfigRolloutRecord: ConfigRolloutRecord{ConfigRollout: r, Counts: w.counts(r, staged)},
			ChangeSet:           changeSetRecord(cs), StagedResourceIDs: staged,
		}
		return nil
	})
	return out, err
}

// ListDevices returns one page of the active devices of the organization as rollout id sees them (plan M11 decision
// 34). Sorted by hostname, in_wave or report_outcome, each with the hostname order of the database as tie-breaker.
func (c *ConfigRollouts) ListDevices(ctx context.Context, id uuid.UUID, query ConfigRolloutDeviceQuery) (Listed[ConfigRolloutDevice], error) {
	var out Listed[ConfigRolloutDevice]
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	var all []ConfigRolloutDevice
	err := c.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		r, err := q.GetConfigRollout(ctx, id)
		if err != nil {
			return notFound(err)
		}
		plan, err := q.GetConfigRolloutPlan(ctx, id)
		if err != nil {
			return fmt.Errorf("read the plan of rollout %s: %w", id, err)
		}
		staged, err := stagedResourceIDs(plan)
		if err != nil {
			return err
		}
		w, err := loadRolloutWorld(ctx, q, []pgstore.ConfigRollout{r}, query.Page.QPattern)
		if err != nil {
			return err
		}
		canary, reports := w.canaryOf(r), w.reports[r.ID]
		for _, d := range w.devices {
			var rep *pgstore.ListConfigRolloutReportsRow
			if row, ok := reports[d.ID]; ok {
				rep = &row
			}
			dev := rolloutDevice(r, d, rep, staged, canary)
			if (query.InWave == nil || *query.InWave == dev.InWave) &&
				(len(query.ReportOutcomes) == 0 || slices.Contains(query.ReportOutcomes, dev.ReportOutcome)) {
				all = append(all, dev)
			}
		}
		return nil
	})
	if err != nil {
		return out, err
	}
	sortRolloutDevices(all, query.Page.Sort)
	out.Count = min(len(all), countLimit)
	from := min(int(query.Page.Offset), len(all))
	out.Items = all[from:min(from+int(query.Page.Limit), len(all))]
	return out, nil
}

// rolloutDevice is device d as rollout r sees it. The report is the device's newest report on a bundle of r, the one
// its counts read (classify); a failure that no longer counts is shown as none. The failed resources it lists are those
// that count, and the plan errors of a report-only device, which are shown but never count.
func rolloutDevice(r pgstore.ConfigRollout, d pgstore.ListConfigRolloutDevicesRow, rep *pgstore.ListConfigRolloutReportsRow,
	staged []string, canary map[uuid.UUID]bool) ConfigRolloutDevice {
	out := ConfigRolloutDevice{
		DeviceID: d.ID, Hostname: d.Hostname, InWave: inWave(r, d.ID, canary), ReportOutcome: RolloutReportNone,
		CarriesRollout: d.BundleRolloutID == r.ID, FailedResourceIDs: []string{},
	}
	if d.BundleVersion > 0 {
		out.BundleVersion = &d.BundleVersion
	}
	if rep == nil {
		return out
	}
	reportOnly := rep.Mode == protocol.BundleModeReportOnly && rep.Outcome == RolloutReportApplied
	failure := !reportOnly && (rep.Outcome == RolloutReportRejected || stagedFailure(rep.FailedResourceIds, staged))
	switch {
	case failure && !countsAgainst(r, *rep):
		// A failure the counts discarded at the last resume is not listed (amendment R6.14 c): the device is pending.
		return out
	case reportOnly:
		out.ReportOutcome = RolloutReportReportOnly
	default:
		out.ReportOutcome = rep.Outcome
	}
	for _, id := range rep.FailedResourceIds {
		if slices.Contains(staged, id) {
			out.FailedResourceIDs = append(out.FailedResourceIDs, id)
		}
	}
	return out
}

// sortRolloutDevices orders devices, which arrive in the database's hostname order, by sort; equal keys keep that
// order, so the hostname is the tie-breaker as the collation of the other lists orders it.
func sortRolloutDevices(devices []ConfigRolloutDevice, sort string) {
	field, desc := strings.TrimPrefix(sort, "-"), strings.HasPrefix(sort, "-")
	if field == "hostname" {
		if desc {
			slices.Reverse(devices)
		}
		return
	}
	key := func(d ConfigRolloutDevice) string {
		if field == "in_wave" {
			return strconv.FormatBool(d.InWave)
		}
		return d.ReportOutcome
	}
	slices.SortStableFunc(devices, func(a, b ConfigRolloutDevice) int {
		if desc {
			return strings.Compare(key(b), key(a))
		}
		return strings.Compare(key(a), key(b))
	})
}

// Halt stops a running rollout with reason (2 to 500 characters): devices keep the state of the wave it reached.
func (c *ConfigRollouts) Halt(ctx context.Context, id uuid.UUID, reason string) (pgstore.ConfigRollout, error) {
	reason = strings.TrimSpace(reason)
	return c.transition(ctx, SpecConfigRolloutHalt, id, nil,
		// Validated before the rollout is read, as every request is, and before it becomes an audit param: a NUL cannot
		// be stored in the event either (jsonb).
		func(rec Recorder) error {
			if n := utf8.RuneCountInString(reason); n < 2 || n > rolloutHaltReasonMax || !reasonText(reason) {
				return problem.InvalidRequest.WithDetail("reason must have 2 to 500 characters without control characters")
			}
			rec.SetParam("reason", reason)
			return nil
		},
		func(ctx context.Context, q *pgstore.Queries, _ Recorder, r pgstore.ConfigRollout) (pgstore.ConfigRollout, error) {
			if r.Status != configrollout.StatusRunning {
				return r, problem.InvalidState.WithDetail("the rollout is " + r.Status)
			}
			return q.HaltConfigRollout(ctx, pgstore.HaltConfigRolloutParams{ID: r.ID, HaltedReason: &reason})
		})
}

// Resume continues a halted rollout in the wave where it stopped; failures reported before the resume no longer count.
// The devices inside the wave do not change, so nothing is recompiled.
func (c *ConfigRollouts) Resume(ctx context.Context, id uuid.UUID) (pgstore.ConfigRollout, error) {
	return c.transition(ctx, SpecConfigRolloutResume, id, nil, nil,
		func(ctx context.Context, q *pgstore.Queries, _ Recorder, r pgstore.ConfigRollout) (pgstore.ConfigRollout, error) {
			if r.Status != configrollout.StatusHalted {
				return r, problem.InvalidState.WithDetail("the rollout is " + r.Status)
			}
			return q.ResumeConfigRollout(ctx, r.ID)
		})
}

// Advance moves a running rollout to its next wave at once; refused in the last wave and while halted.
func (c *ConfigRollouts) Advance(ctx context.Context, id uuid.UUID) (pgstore.ConfigRollout, error) {
	return c.transition(ctx, SpecConfigRolloutAdvance, id, map[string]any{"manual": true}, nil, advance)
}

// Complete ends a running or halted rollout: every device receives the staged change at its next check-in.
func (c *ConfigRollouts) Complete(ctx context.Context, id uuid.UUID) (pgstore.ConfigRollout, error) {
	reason := "completed by " + actorName(ctx)
	return c.transition(ctx, SpecConfigRolloutComplete, id, map[string]any{"manual": true}, nil, complete(reason))
}

// advance is the change of SpecConfigRolloutAdvance.
func advance(ctx context.Context, q *pgstore.Queries, rec Recorder, r pgstore.ConfigRollout) (pgstore.ConfigRollout, error) {
	if r.Status != configrollout.StatusRunning {
		return r, problem.InvalidState.WithDetail("the rollout is " + r.Status)
	}
	next := int(r.CurrentWaveIndex) + 1
	if next >= len(r.Waves) {
		return r, problem.InvalidState.WithDetail("the rollout is in its last wave; complete it instead")
	}
	rec.SetParam("wave", next)
	rec.SetParam("percent", int(r.Waves[next]))
	out, err := q.AdvanceConfigRollout(ctx, r.ID)
	if err == nil {
		rec.StateChanged(statechange.ScopeOrg, r.OrganizationID)
	}
	return out, err
}

// complete is the change of SpecConfigRolloutComplete with the ended reason.
func complete(reason string) func(ctx context.Context, q *pgstore.Queries, rec Recorder, r pgstore.ConfigRollout) (pgstore.ConfigRollout, error) {
	return func(ctx context.Context, q *pgstore.Queries, rec Recorder, r pgstore.ConfigRollout) (pgstore.ConfigRollout, error) {
		if !configrollout.Open(r.Status) {
			return r, problem.InvalidState.WithDetail("the rollout is " + r.Status)
		}
		out, err := q.CompleteConfigRollout(ctx, pgstore.CompleteConfigRolloutParams{ID: r.ID, EndedReason: &reason})
		if err == nil {
			rec.StateChanged(statechange.ScopeOrg, r.OrganizationID)
		}
		return out, err
	}
}

// transition runs change on rollout id under its row lock as the audited action spec, with params and the rollout's
// IDs and wave; validate (optional) checks the request inside the action before the rollout is read. The rollout settings are not consulted: an open rollout keeps its rules after rollouts were switched
// off, and these actions are the way out (plan M11 amendment R6.13).
func (c *ConfigRollouts) transition(ctx context.Context, spec ActionSpec, id uuid.UUID, params map[string]any,
	validate func(rec Recorder) error, change func(ctx context.Context, q *pgstore.Queries, rec Recorder, r pgstore.ConfigRollout) (pgstore.ConfigRollout, error)) (pgstore.ConfigRollout, error) {
	t := rolloutTarget(id)
	spec.Target = &t
	spec.Params = map[string]any{"rollout_id": id.String()}
	for k, v := range params {
		spec.Params[k] = v
	}
	var out pgstore.ConfigRollout
	err := c.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		if validate != nil {
			if err := validate(rec); err != nil {
				return err
			}
		}
		r, err := q.LockConfigRollout(ctx, id)
		if err != nil {
			return notFound(err)
		}
		rec.SetParam("change_set_id", r.ChangeSetID.String())
		rec.SetParam("wave", int(r.CurrentWaveIndex))
		out, err = change(ctx, q, rec, r)
		return err
	})
	return out, err
}

// runningRollout is a running rollout as the worker read it, with its counts.
type runningRollout struct {
	pgstore.ConfigRollout
	counts RolloutCounts
}

// Evaluate is the worker's round for the organization of ctx (plan M11 decision 33): every running rollout halts when
// its failed devices reach the threshold, otherwise advances once the wave's minimum duration passed, or completes
// after the last wave. It counts with the API's rule (classify, amendment R6.14) in a fixed number of queries per
// organization. Each change is one audited action of the system; a halted rollout is not evaluated.
func (c *ConfigRollouts) Evaluate(ctx context.Context, now time.Time) error {
	var running []runningRollout
	if err := c.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		rows, err := q.ListRunningConfigRollouts(ctx)
		if err != nil {
			return fmt.Errorf("list running rollouts: %w", err)
		}
		if len(rows) == 0 {
			return nil
		}
		rollouts := make([]pgstore.ConfigRollout, len(rows))
		for i, r := range rows {
			rollouts[i] = r.ConfigRollout
		}
		w, err := loadRolloutWorld(ctx, q, rollouts, nil)
		if err != nil {
			return err
		}
		for _, r := range rows {
			staged, err := stagedResourceIDs(r.Plan)
			if err != nil {
				return err
			}
			running = append(running, runningRollout{ConfigRollout: r.ConfigRollout, counts: w.counts(r.ConfigRollout, staged)})
		}
		return nil
	}); err != nil {
		return err
	}
	for _, r := range running {
		if err := c.evaluate(ctx, r, now); err != nil {
			return fmt.Errorf("evaluate rollout %s: %w", r.ID, err)
		}
	}
	return nil
}

// evaluate decides on one running rollout and records the change, if any.
func (c *ConfigRollouts) evaluate(ctx context.Context, r runningRollout, now time.Time) error {
	waves := make([]int, len(r.Waves))
	for i, w := range r.Waves {
		waves[i] = int(w)
	}
	eligible, failed := int64(r.counts.Eligible), int64(r.counts.Failed)
	in := configrollout.Rollout{
		Status: configrollout.StatusRunning, Waves: waves, CurrentWave: int(r.CurrentWaveIndex), WaveStartedAt: r.WaveStartedAt,
		MinWaveMinutes: int(r.MinWaveMinutes), FailurePercent: int(r.FailureThresholdPercent), FailureMin: int(r.FailureThresholdMin),
		Eligible: eligible, Failed: failed,
	}
	var spec ActionSpec
	var params map[string]any
	var change func(ctx context.Context, q *pgstore.Queries, rec Recorder, r pgstore.ConfigRollout) (pgstore.ConfigRollout, error)
	switch configrollout.Decide(in, now) {
	case configrollout.Halt:
		threshold := configrollout.Threshold(eligible, in.FailurePercent, in.FailureMin)
		reason := fmt.Sprintf("%d failed devices reached the threshold of %d", failed, threshold)
		spec = SpecConfigRolloutHalt
		params = map[string]any{"reason": reason, "eligible": eligible, "failed": failed, "threshold": threshold}
		change = func(ctx context.Context, q *pgstore.Queries, _ Recorder, r pgstore.ConfigRollout) (pgstore.ConfigRollout, error) {
			return q.HaltConfigRollout(ctx, pgstore.HaltConfigRolloutParams{ID: r.ID, HaltedReason: &reason})
		}
	case configrollout.Advance:
		spec, params, change = SpecConfigRolloutAdvance, map[string]any{"manual": false}, advance
	case configrollout.Complete:
		spec, params, change = SpecConfigRolloutComplete, map[string]any{"manual": false}, complete("every wave passed")
	default:
		return nil
	}
	slog.InfoContext(ctx, "config rollout changed", "rollout", r.ID, "code", spec.Code, "eligible", eligible, "failed", failed)
	read := r.ConfigRollout
	return ignoreStale(c.transition(ctx, spec, r.ID, params, nil,
		func(ctx context.Context, q *pgstore.Queries, rec Recorder, cur pgstore.ConfigRollout) (pgstore.ConfigRollout, error) {
			// The decision was read outside this transaction; an administrator may have acted since, also by halting
			// and resuming, which discards the failures the decision counted.
			if cur.Status != configrollout.StatusRunning || cur.CurrentWaveIndex != read.CurrentWaveIndex ||
				!cur.EvaluationSince.Equal(read.EvaluationSince) || !cur.WaveStartedAt.Equal(read.WaveStartedAt) {
				return cur, problem.InvalidState.WithDetail("the rollout changed since it was evaluated")
			}
			return change(ctx, q, rec, cur)
		}))
}

// ignoreStale drops the invalid_state of a rollout an administrator changed between the worker's read and its action:
// the attempt is recorded as a failure, and the next round decides on the new state.
func ignoreStale(_ pgstore.ConfigRollout, err error) error {
	if problem.From(err).Code == problem.InvalidState.Code {
		return nil
	}
	return err
}

// StatusCounts returns the number of the organization's rollouts by status (the worker's gauge).
func (c *ConfigRollouts) StatusCounts(ctx context.Context) (map[string]int64, error) {
	if p, ok := principal.From(ctx); !ok || p.Kind != principal.KindSystem {
		return nil, problem.Forbidden
	}
	out := map[string]int64{}
	err := c.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		rows, err := q.CountConfigRolloutsByStatus(ctx)
		for _, r := range rows {
			out[r.Status] = r.N
		}
		return err
	})
	return out, err
}
