package app_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"aead.dev/minisign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/pkg/releasesig"
	"github.com/phischl/paddock-mdm/pkg/semver"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/agentrelease"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

type fakeArtifactStore struct {
	mu   sync.Mutex
	puts map[string][]byte
	fail error
}

func (f *fakeArtifactStore) Put(_ context.Context, key, _, _ string, body []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	f.puts[key] = body
	return nil
}

type releaseHarness struct {
	releases *app.AgentReleases
	reports  *app.DeviceReports
	runner   *app.ActionRunner
	store    *fakeArtifactStore
	priv     minisign.PrivateKey
	super    *pgx.Conn
}

func newReleaseHarness(t *testing.T, development bool) releaseHarness {
	t.Helper()
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	platform, err := db.NewPlatformPool(ctx, env.Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	worker, err := db.NewOrgPool(ctx, env.Worker, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(worker.Close)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeArtifactStore{puts: map[string][]byte{}}
	runner := app.NewActionRunner(worker, platform, httpx.RequestID)
	verify := app.NewReleaseVerifier(pub)
	return releaseHarness{
		releases: app.NewAgentReleases(runner, platform, store, verify, verify, development),
		reports:  app.NewDeviceReports(runner, worker), runner: runner, store: store, priv: priv, super: super,
	}
}

func platformAdmin() context.Context {
	ctx := principal.With(context.Background(), principal.Principal{Kind: principal.KindPlatformAdmin, Role: principal.RolePlatform, ID: uuid.New(), Display: "pa@test"})
	return httpx.WithRequestID(ctx, uuid.NewString())
}

func systemCtx(org uuid.UUID) context.Context {
	ctx := principal.With(context.Background(), principal.Principal{Kind: principal.KindSystem, Display: "worker", OrganizationID: org})
	return httpx.WithRequestID(ctx, uuid.NewString())
}

// uniqueVersion returns a release version no other test uses.
func uniqueVersion() string { return "1.0.0-t" + uuid.NewString()[:8] }

// published creates, uploads (amd64) and publishes a release.
// signBinary signs an agent binary as make agent-release does: the trusted comment names version and arch.
func (h releaseHarness) signBinary(bin []byte, version, arch string) string {
	return base64.StdEncoding.EncodeToString(minisign.SignWithComments(h.priv, bin, releasesig.Comment(version, arch), ""))
}

func (h releaseHarness) published(t *testing.T) string {
	t.Helper()
	ctx := platformAdmin()
	v := uniqueVersion()
	if _, err := h.releases.Create(ctx, v); err != nil {
		t.Fatal(err)
	}
	bin := []byte("paddockd " + v)
	if _, err := h.releases.UploadArtifact(ctx, v, "amd64", bin, h.signBinary(bin, v, "amd64")); err != nil {
		t.Fatal(err)
	}
	if _, err := h.releases.Publish(ctx, v); err != nil {
		t.Fatal(err)
	}
	return v
}

func expectProblem(t *testing.T, err error, want *problem.Error) {
	t.Helper()
	if !errors.Is(err, want) && problem.From(err).Code != want.Code {
		t.Fatalf("err = %v, want %s", err, want.Code)
	}
}

// haltAll stops every running rollout, so that each test starts its own.
func (h releaseHarness) haltAll(t *testing.T) {
	t.Helper()
	if _, err := h.super.Exec(context.Background(), "UPDATE agent_rollout SET status = 'halted' WHERE status = 'running'"); err != nil {
		t.Fatal(err)
	}
}

func TestAgentReleaseLifecycle(t *testing.T) {
	h := newReleaseHarness(t, false)
	h.haltAll(t)
	ctx := platformAdmin()
	v := uniqueVersion()
	if _, err := h.releases.Create(ctx, v); err != nil {
		t.Fatal(err)
	}
	_, err := h.releases.Create(ctx, v)
	expectProblem(t, err, problem.AlreadyExists)
	_, err = h.releases.Create(ctx, "v1")
	expectProblem(t, err, problem.InvalidRequest)
	_, err = h.releases.Publish(ctx, v)
	expectProblem(t, err, problem.InvalidState) // no artifact yet

	bin := []byte("binary")
	_, err = h.releases.UploadArtifact(ctx, v, "amd64", bin, base64.StdEncoding.EncodeToString(minisign.Sign(h.priv, []byte("other"))))
	expectProblem(t, err, problem.InvalidRequest)
	_, err = h.releases.UploadArtifact(ctx, v, "amd64", bin, "%%%")
	expectProblem(t, err, problem.InvalidRequest)
	// Signed, but the trusted comment binds the binary to another version or architecture, or is missing.
	for _, sig := range []string{h.signBinary(bin, "9.9.9", "amd64"), h.signBinary(bin, v, "arm64"),
		base64.StdEncoding.EncodeToString(minisign.Sign(h.priv, bin))} {
		_, err = h.releases.UploadArtifact(ctx, v, "amd64", bin, sig)
		expectProblem(t, err, problem.ReleaseSignatureMismatch)
	}
	if len(h.store.puts) != 0 {
		t.Fatal("a binary with an invalid signature was stored")
	}
	art, err := h.releases.UploadArtifact(ctx, v, "amd64", bin, h.signBinary(bin, v, "amd64"))
	if err != nil || art.Size != 6 || art.ObjectKey != agentrelease.ObjectKey(v, "amd64") || string(h.store.puts[art.ObjectKey]) != "binary" {
		t.Fatalf("upload: %+v, %v", art, err)
	}
	deb := []byte("debian package")
	debSig := base64.StdEncoding.EncodeToString(minisign.Sign(h.priv, deb))
	_, err = h.releases.UploadPackage(ctx, v, "paddock-agent", "", "amd64", deb, base64.StdEncoding.EncodeToString(minisign.Sign(h.priv, bin)))
	expectProblem(t, err, problem.InvalidRequest)
	_, err = h.releases.UploadPackage(ctx, v, "../paddockd", "", "amd64", deb, debSig)
	expectProblem(t, err, problem.InvalidRequest)
	_, err = h.releases.UploadPackage(ctx, v, "paddock-agent", "", "386", deb, debSig)
	expectProblem(t, err, problem.InvalidRequest)
	pkg, err := h.releases.UploadPackage(ctx, v, "paddock-agent", "", "amd64", deb, debSig)
	if err != nil || pkg.ObjectKey != agentrelease.PackageObjectKey(v, "paddock-agent", "", "amd64") || string(h.store.puts[pkg.ObjectKey]) != "debian package" {
		t.Fatalf("package upload: %+v, %v", pkg, err)
	}
	if r, err := h.releases.Publish(ctx, v); err != nil || r.Status != agentrelease.StatusPublished {
		t.Fatalf("publish: %+v, %v", r, err)
	}
	_, err = h.releases.UploadArtifact(ctx, v, "amd64", bin, h.signBinary(bin, v, "amd64"))
	expectProblem(t, err, problem.InvalidState)
	_, err = h.releases.UploadPackage(ctx, v, "paddock-supervisor", "", "amd64", deb, debSig)
	expectProblem(t, err, problem.InvalidState)

	short := 5
	_, err = h.releases.StartRollout(ctx, v, app.RolloutOptions{MinWaveMinutes: &short})
	expectProblem(t, err, problem.InvalidRequest) // below 60 minutes outside development
	_, err = h.releases.StartRollout(ctx, v, app.RolloutOptions{Waves: []int{10, 5, 100}})
	expectProblem(t, err, problem.InvalidRequest)
	r, err := h.releases.StartRollout(ctx, v, app.RolloutOptions{})
	if err != nil || r.Status != agentrelease.RolloutRunning || len(r.Waves) != 4 || r.MinWaveMinutes != 1440 {
		t.Fatalf("start: %+v, %v", r, err)
	}
	other := h.published(t)
	_, err = h.releases.StartRollout(ctx, other, app.RolloutOptions{})
	expectProblem(t, err, problem.InvalidState) // one rollout at a time
	_, err = h.releases.StartRollout(ctx, v, app.RolloutOptions{})
	expectProblem(t, err, problem.AlreadyExists)

	if r, err := h.releases.Halt(ctx, v); err != nil || r.Status != agentrelease.RolloutHalted || r.HaltedReason == nil {
		t.Fatalf("halt: %+v, %v", r, err)
	}
	_, err = h.releases.Halt(ctx, v)
	expectProblem(t, err, problem.InvalidState)
	if r, err := h.releases.Resume(ctx, v); err != nil || r.Status != agentrelease.RolloutRunning {
		t.Fatalf("resume: %+v, %v", r, err)
	}
	d, err := h.releases.Get(ctx, v)
	if err != nil || d.Rollout == nil || len(d.Artifacts) != 1 || len(d.Packages) != 1 {
		t.Fatalf("detail %+v, %v", d, err)
	}
	h.haltAll(t)

	// Organization administrators cannot touch releases.
	orgAdmin := principal.With(context.Background(), principal.Principal{Kind: principal.KindAdmin, Role: principal.RoleOrgAdmin, OrganizationID: uuid.New()})
	_, err = h.releases.Create(httpx.WithRequestID(orgAdmin, uuid.NewString()), uniqueVersion())
	expectProblem(t, err, problem.Forbidden)
}

// device inserts an organization with one active device whose rollout bucket is inside the first wave of 100 %.
func (h releaseHarness) device(t *testing.T) (org, dev uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	org, dev = uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	if _, err := h.super.Exec(ctx, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'R', 'active')", org, "r"+org.String()[24:]); err != nil {
		t.Fatal(err)
	}
	if _, err := h.super.Exec(ctx, "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'h', 'active')", dev, org); err != nil {
		t.Fatal(err)
	}
	return org, dev
}

func TestRolloutRoundHaltsOnFailures(t *testing.T) {
	h := newReleaseHarness(t, true)
	h.haltAll(t)
	v := h.published(t)
	one, wave := 1, 1
	if _, err := h.releases.StartRollout(platformAdmin(), v, app.RolloutOptions{Waves: []int{100}, FailureThresholdMin: &one, MinWaveMinutes: &wave}); err != nil {
		t.Fatal(err)
	}
	sys := systemCtx(uuid.Nil)
	offer, err := h.releases.EvaluateRollouts(sys, time.Now())
	if err != nil || offer == nil || offer.Version != v || offer.Artifacts["amd64"].Size == 0 {
		t.Fatalf("offer %+v, %v", offer, err)
	}

	// A device reports a rollback: the event is recorded once and counted.
	org, dev := h.device(t)
	data, _ := json.Marshal(map[string]string{"version": v, "from_version": "0.9.0", "outcome": "rolled_back"})
	ev := protocol.Event{EventSeq: 1, Type: protocol.EventAgentRolledBack, OccurredAt: time.Now(), Data: data}
	for range 2 {
		if _, err := h.reports.RecordEvent(systemCtx(org), dev, ev); err != nil {
			t.Fatal(err)
		}
	}
	offer, err = h.releases.EvaluateRollouts(sys, time.Now())
	if err != nil || offer != nil {
		t.Fatalf("after the first failure: offer %+v, %v; want halted (nothing offered)", offer, err)
	}
	d, _ := h.releases.Get(platformAdmin(), v)
	if d.Rollout.Status != agentrelease.RolloutHalted || d.Stats.Failed != 1 {
		t.Fatalf("rollout %+v stats %+v", d.Rollout, d.Stats)
	}
	var actor string
	if err := h.super.QueryRow(context.Background(),
		"SELECT actor->>'type' FROM action WHERE code = 'agent_rollout.halted' AND target->>'id' = $1 AND outcome = 'success'", v).Scan(&actor); err != nil || actor != "system" {
		t.Fatalf("agent_rollout.halted audit: %q, %v", actor, err)
	}
}

// TestRolloutIgnoresRefusedDowngrades (PDK-025): a device on a newer agent refuses the release as a downgrade; the
// failure is audited but never counts toward the rollout's failure rate, so even a threshold of one device keeps the
// rollout running.
func TestRolloutIgnoresRefusedDowngrades(t *testing.T) {
	h := newReleaseHarness(t, true)
	h.haltAll(t)
	v := h.published(t)
	one, wave := 1, 1
	if _, err := h.releases.StartRollout(platformAdmin(), v, app.RolloutOptions{Waves: []int{100}, FailureThresholdMin: &one, MinWaveMinutes: &wave}); err != nil {
		t.Fatal(err)
	}
	org, dev := h.device(t)
	data, _ := json.Marshal(map[string]string{"version": v, "from_version": "999.0.0", "outcome": "downgrade_refused"})
	ev := protocol.Event{EventSeq: 1, Type: protocol.EventAgentUpdateFailed, OccurredAt: time.Now(), Data: data}
	if _, err := h.reports.RecordEvent(systemCtx(org), dev, ev); err != nil {
		t.Fatal(err)
	}
	offer, err := h.releases.EvaluateRollouts(systemCtx(uuid.Nil), time.Now())
	if err != nil || offer == nil || offer.Version != v || offer.Status != agentrelease.RolloutRunning {
		t.Fatalf("offer %+v, %v; want the rollout still running", offer, err)
	}
	ctx := context.Background()
	var reports, audited int
	if err := h.super.QueryRow(ctx, "SELECT count(*) FROM agent_update_report WHERE device_id = $1", dev).Scan(&reports); err != nil || reports != 0 {
		t.Fatalf("%d update reports (%v), want 0", reports, err)
	}
	if err := h.super.QueryRow(ctx, "SELECT count(*) FROM action WHERE code = 'device.agent_update_failed' AND target->>'id' = $1", dev.String()).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("%d audit events (%v), want 1", audited, err)
	}

	// The same device failing for another reason counts and halts the rollout.
	data, _ = json.Marshal(map[string]string{"version": v, "from_version": "0.9.0", "outcome": "self_test_failed"})
	ev = protocol.Event{EventSeq: 2, Type: protocol.EventAgentUpdateFailed, OccurredAt: time.Now(), Data: data}
	if _, err := h.reports.RecordEvent(systemCtx(org), dev, ev); err != nil {
		t.Fatal(err)
	}
	if offer, err := h.releases.EvaluateRollouts(systemCtx(uuid.Nil), time.Now()); err != nil || offer != nil {
		t.Fatalf("after a real failure: offer %+v, %v; want halted", offer, err)
	}
}

// TestRollbackFailedCountsOnceAndRaisesAttention (ADR 0024): a device whose flip back failed reports rollback_failed,
// audited as device.agent_rollback_failed and counted by every failure count of the release; when the retried rollback
// succeeds the same device reports rolled_back and still counts once. While the device runs the release without a
// rolled_back, the attention list shows agent_rollback_pending to its own organization only.
func TestRollbackFailedCountsOnceAndRaisesAttention(t *testing.T) {
	h := newReleaseHarness(t, true)
	h.haltAll(t)
	v := h.published(t)
	ctx := context.Background()
	org, dev := h.device(t)
	other, _ := h.device(t)
	if _, err := h.super.Exec(ctx, "INSERT INTO device_status (device_id, organization_id, agent_version) VALUES ($1, $2, $3)", dev, org, v); err != nil {
		t.Fatal(err)
	}
	report := func(seq int64, eventType, outcome string) {
		t.Helper()
		data, _ := json.Marshal(map[string]string{"version": v, "from_version": "0.9.0", "outcome": outcome})
		if _, err := h.reports.RecordEvent(systemCtx(org), dev, protocol.Event{EventSeq: seq, Type: eventType, OccurredAt: time.Now(), Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	failed := func() [3]int64 {
		t.Helper()
		var n [3]int64
		if err := h.super.QueryRow(ctx, `SELECT (SELECT failed FROM paddock_agent_rollout_stats($1, 100)),
			(SELECT failed FROM paddock_agent_rollout_evaluation_stats($1, 100, '-infinity')),
			(SELECT failed FROM paddock_agent_current_release_stats($1, '-infinity'))`, v).Scan(&n[0], &n[1], &n[2]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// attention lists the pending rollbacks of dev as the API role of the organization asking.
	attention := func(asking uuid.UUID) []string {
		t.Helper()
		tx, err := h.super.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE paddock_api"); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, "SELECT set_config('paddock.org_id', $1, true)", asking.String()); err != nil {
			t.Fatal(err)
		}
		rows, err := tx.Query(ctx, "SELECT detail FROM attention_condition WHERE device_id = $1 AND kind = 'agent_rollback_pending'", dev)
		if err != nil {
			t.Fatal(err)
		}
		details, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		return details
	}

	report(1, protocol.EventAgentUpdateFailed, "rollback_failed")
	report(1, protocol.EventAgentUpdateFailed, "rollback_failed")
	if n := failed(); n != [3]int64{1, 1, 1} {
		t.Fatalf("failed counts %v after rollback_failed, want 1 each", n)
	}
	var audited, outcomes int
	if err := h.super.QueryRow(ctx, "SELECT count(*) FROM action WHERE code = 'device.agent_rollback_failed' AND target->>'id' = $1", dev.String()).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("%d device.agent_rollback_failed events (%v), want 1", audited, err)
	}
	if err := h.super.QueryRow(ctx, "SELECT count(*) FROM action WHERE code = 'device.agent_update_failed' AND target->>'id' = $1", dev.String()).Scan(&audited); err != nil || audited != 0 {
		t.Fatalf("%d device.agent_update_failed events (%v), want 0", audited, err)
	}
	if got := attention(org); len(got) != 1 || got[0] != v {
		t.Fatalf("agent_rollback_pending details %v, want [%s]", got, v)
	}
	if got := attention(other); len(got) != 0 {
		t.Fatalf("another organization sees agent_rollback_pending %v", got)
	}

	report(2, protocol.EventAgentRolledBack, "rolled_back")
	if n := failed(); n != [3]int64{1, 1, 1} {
		t.Fatalf("failed counts %v after a later rolled_back, want 1 each", n)
	}
	if err := h.super.QueryRow(ctx, "SELECT count(*) FROM agent_update_report WHERE device_id = $1 AND outcome IN ('rollback_failed', 'rolled_back')", dev).Scan(&outcomes); err != nil || outcomes != 2 {
		t.Fatalf("%d update reports (%v), want rollback_failed and rolled_back", outcomes, err)
	}
	if got := attention(org); len(got) != 0 {
		t.Fatalf("agent_rollback_pending %v after rolled_back", got)
	}
}

// TestRollbackPendingEndsWhenTheDeviceLeavesTheVersion (ADR 0024): the attention row is gone once the device reports
// another agent version, also without a rolled_back report (an operator flipped current by hand).
func TestRollbackPendingEndsWhenTheDeviceLeavesTheVersion(t *testing.T) {
	h := newReleaseHarness(t, true)
	v := h.published(t)
	ctx := context.Background()
	org, dev := h.device(t)
	if _, err := h.super.Exec(ctx, "INSERT INTO device_status (device_id, organization_id, agent_version) VALUES ($1, $2, $3)", dev, org, v); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(map[string]string{"version": v, "from_version": "0.9.0", "outcome": "rollback_failed"})
	if _, err := h.reports.RecordEvent(systemCtx(org), dev, protocol.Event{EventSeq: 1, Type: protocol.EventAgentUpdateFailed, OccurredAt: time.Now(), Data: data}); err != nil {
		t.Fatal(err)
	}
	pending := func() bool {
		t.Helper()
		var ok bool
		if err := h.super.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM attention_condition WHERE device_id = $1 AND kind = 'agent_rollback_pending')", dev).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !pending() {
		t.Fatal("no agent_rollback_pending while the device runs the release")
	}
	if _, err := h.super.Exec(ctx, "UPDATE device_status SET agent_version = '0.9.0' WHERE device_id = $1", dev); err != nil {
		t.Fatal(err)
	}
	if pending() {
		t.Fatal("agent_rollback_pending after the device left the release")
	}
}

func TestRolloutRoundAdvancesAndCompletes(t *testing.T) {
	h := newReleaseHarness(t, true)
	h.haltAll(t)
	v := h.published(t)
	wave := 1
	if _, err := h.releases.StartRollout(platformAdmin(), v, app.RolloutOptions{Waves: []int{50, 100}, MinWaveMinutes: &wave}); err != nil {
		t.Fatal(err)
	}
	sys := systemCtx(uuid.Nil)
	if o, err := h.releases.EvaluateRollouts(sys, time.Now()); err != nil || o.CurrentWave != 0 {
		t.Fatalf("young wave advanced: %+v, %v", o, err)
	}
	later := time.Now().Add(2 * time.Minute)
	if o, err := h.releases.EvaluateRollouts(sys, later); err != nil || o.CurrentWave != 1 || o.Status != agentrelease.RolloutRunning {
		t.Fatalf("advance: %+v, %v", o, err)
	}
	if o, err := h.releases.EvaluateRollouts(sys, later.Add(2*time.Minute)); err != nil || o.Status != agentrelease.RolloutCompleted {
		t.Fatalf("complete: %+v, %v", o, err)
	}
	// A completed rollout keeps offering its release to every device.
	if o, err := h.releases.EvaluateRollouts(sys, later.Add(time.Hour)); err != nil || o == nil || o.Version != v ||
		agentrelease.Percent(o.Status, o.Waves, o.CurrentWave) != 100 {
		t.Fatalf("completed offer: %+v, %v", o, err)
	}
}

// completedRollout returns a release whose single-wave rollout (failure threshold: one device) has completed.
func (h releaseHarness) completedRollout(t *testing.T, now time.Time) string {
	t.Helper()
	h.haltAll(t)
	v := h.published(t)
	one, zero := 1, 0
	if _, err := h.releases.StartRollout(platformAdmin(), v, app.RolloutOptions{Waves: []int{100}, MinWaveMinutes: &one,
		FailureThresholdMin: &one, FailureThresholdPercent: &zero}); err != nil {
		t.Fatal(err)
	}
	if o, err := h.releases.EvaluateRollouts(systemCtx(uuid.Nil), now); err != nil || o == nil || o.Version != v || o.Status != agentrelease.RolloutCompleted {
		t.Fatalf("complete: %+v, %v", o, err)
	}
	return v
}

func (h releaseHarness) reportFailure(t *testing.T, version string) {
	t.Helper()
	org, dev := h.device(t)
	data, _ := json.Marshal(map[string]string{"version": version, "from_version": "0.9.0", "outcome": "update_failed"})
	ev := protocol.Event{EventSeq: 1, Type: protocol.EventAgentUpdateFailed, OccurredAt: time.Now(), Data: data}
	if _, err := h.reports.RecordEvent(systemCtx(org), dev, ev); err != nil {
		t.Fatal(err)
	}
}

// Plan M2.1 decision 1: the current release halts when its failures within 7 days reach the threshold, and resuming
// it restores the offer.
func TestCurrentReleaseAutoStop(t *testing.T) {
	h := newReleaseHarness(t, true)
	sys := systemCtx(uuid.Nil)
	now := time.Now().Add(2 * time.Minute)
	v := h.completedRollout(t, now)

	// A failure older than the window does not count.
	h.reportFailure(t, v)
	if _, err := h.super.Exec(context.Background(), "UPDATE agent_update_report SET reported_at = now() - interval '8 days' WHERE version = $1", v); err != nil {
		t.Fatal(err)
	}
	if o, err := h.releases.EvaluateRollouts(sys, now); err != nil || o == nil || o.Status != agentrelease.RolloutCompleted {
		t.Fatalf("a failure older than 7 days halted the current release: %+v, %v", o, err)
	}

	// A failure within the window reaches the threshold of one device: nothing is offered any more.
	h.reportFailure(t, v)
	if o, err := h.releases.EvaluateRollouts(sys, now); err != nil || o != nil {
		t.Fatalf("after a failure within 7 days: offer %+v, %v; want halted (nothing offered)", o, err)
	}
	d, _ := h.releases.Get(platformAdmin(), v)
	if d.Rollout.Status != agentrelease.RolloutHalted || d.Rollout.HaltedReason == nil || d.Rollout.CompletedAt == nil {
		t.Fatalf("rollout %+v", d.Rollout)
	}
	var actor, reason string
	if err := h.super.QueryRow(context.Background(),
		"SELECT actor->>'type', params->>'reason' FROM action WHERE code = 'agent_rollout.halted' AND target->>'id' = $1 AND outcome = 'success'", v).Scan(&actor, &reason); err != nil || actor != "system" {
		t.Fatalf("agent_rollout.halted audit: %q, %v", actor, err)
	}
	if !strings.Contains(reason, "current release") {
		t.Fatalf("halt reason %q", reason)
	}

	// Resume restores the current-release offer; the failures before the resume no longer count.
	r, err := h.releases.Resume(platformAdmin(), v)
	if err != nil || r.Status != agentrelease.RolloutCompleted || r.HaltedReason != nil {
		t.Fatalf("resume: %+v, %v", r, err)
	}
	if o, err := h.releases.EvaluateRollouts(sys, now); err != nil || o == nil || o.Version != v ||
		agentrelease.Percent(o.Status, o.Waves, o.CurrentWave) != 100 {
		t.Fatalf("resumed offer: %+v, %v", o, err)
	}
	// A new failure at the threshold halts it again.
	h.reportFailure(t, v)
	if o, err := h.releases.EvaluateRollouts(sys, now); err != nil || o != nil {
		t.Fatalf("after a failure since the resume: offer %+v, %v; want halted", o, err)
	}
}

// Plan M2.1 decision 1: a resumed running rollout runs again, counts only failures since the resume, and cannot
// run next to another running rollout.
func TestResumeRunningRollout(t *testing.T) {
	h := newReleaseHarness(t, true)
	h.haltAll(t)
	sys, admin := systemCtx(uuid.Nil), platformAdmin()
	v := h.published(t)
	one, hour := 1, 60
	if _, err := h.releases.StartRollout(admin, v, app.RolloutOptions{Waves: []int{100}, FailureThresholdMin: &one, MinWaveMinutes: &hour}); err != nil {
		t.Fatal(err)
	}
	h.reportFailure(t, v)
	if o, err := h.releases.EvaluateRollouts(sys, time.Now()); err != nil || o != nil {
		t.Fatalf("after the first failure: offer %+v, %v; want halted", o, err)
	}

	// Another rollout runs: resuming would run two at once.
	other := h.published(t)
	if _, err := h.releases.StartRollout(admin, other, app.RolloutOptions{}); err != nil {
		t.Fatal(err)
	}
	_, err := h.releases.Resume(admin, v)
	expectProblem(t, err, problem.InvalidState)
	if problem.From(err).Status != http.StatusConflict {
		t.Fatalf("resume next to a running rollout: %v, want 409", err)
	}
	if _, err := h.releases.Halt(admin, other); err != nil {
		t.Fatal(err)
	}

	r, err := h.releases.Resume(admin, v)
	if err != nil || r.Status != agentrelease.RolloutRunning || r.CompletedAt != nil {
		t.Fatalf("resume: %+v, %v", r, err)
	}
	if o, err := h.releases.EvaluateRollouts(sys, time.Now()); err != nil || o == nil || o.Version != v || o.Status != agentrelease.RolloutRunning {
		t.Fatalf("the failure before the resume halted the rollout again: %+v, %v", o, err)
	}
	h.reportFailure(t, v)
	if o, err := h.releases.EvaluateRollouts(sys, time.Now()); err != nil || o != nil {
		t.Fatalf("after a failure since the resume: offer %+v, %v; want halted", o, err)
	}
}

// A completed rollout that a newer rollout replaced is not the current release and is not evaluated.
func TestReplacedReleaseIsNotEvaluated(t *testing.T) {
	h := newReleaseHarness(t, true)
	now := time.Now().Add(2 * time.Minute)
	old := h.completedRollout(t, now)
	h.completedRollout(t, now)
	h.reportFailure(t, old)
	if _, err := h.releases.EvaluateRollouts(systemCtx(uuid.Nil), now); err != nil {
		t.Fatal(err)
	}
	if d, _ := h.releases.Get(platformAdmin(), old); d.Rollout.Status != agentrelease.RolloutCompleted {
		t.Fatalf("replaced rollout %+v", d.Rollout)
	}
}

// Offered devices of the current release are the active devices that contacted the server within the window.
func TestCurrentReleaseStatsWindow(t *testing.T) {
	h := newReleaseHarness(t, true)
	ctx := context.Background()
	since := time.Now().Add(-time.Hour)
	offered := func() int64 {
		t.Helper()
		var n, failed int64
		if err := h.super.QueryRow(ctx, "SELECT offered, failed FROM paddock_agent_current_release_stats('0.0.0-none', $1)", since).Scan(&n, &failed); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := offered()
	h.device(t) // never contacted the server
	for _, contact := range []time.Time{time.Now(), since.Add(-time.Minute)} {
		org, dev := h.device(t)
		if _, err := h.super.Exec(ctx, "INSERT INTO device_status (device_id, organization_id, last_contact_at) VALUES ($1, $2, $3)", dev, org, contact); err != nil {
			t.Fatal(err)
		}
	}
	if got := offered() - before; got != 1 {
		t.Fatalf("offered devices grew by %d, want 1 (only the device that contacted the server in the window)", got)
	}
}

func TestRolloutBucketMatchesSQL(t *testing.T) {
	h := newReleaseHarness(t, true)
	ids := []uuid.UUID{uuid.Nil, uuid.MustParse("ffffffff-ffff-ffff-ffff-ffffffffffff")}
	for range 50 {
		ids = append(ids, uuid.New())
	}
	for _, id := range ids {
		var got int
		if err := h.super.QueryRow(context.Background(), "SELECT paddock_rollout_bucket($1)", id).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if want := agentrelease.Bucket(id); got != want {
			t.Fatalf("%s: SQL %d, Go %d", id, got, want)
		}
	}
}

// TestVersionKeyMatchesCompare (PDK-025): the byte order of paddock_version_key is the order of semver.Compare, so
// SQL and Go agree on "newer"; anything that is no semantic version has no key.
func TestVersionKeyMatchesCompare(t *testing.T) {
	h := newReleaseHarness(t, true)
	versions := []string{"0.0.0-dev", "0.1.0-alpha.1", "0.1.0-alpha.2", "0.1.0-alpha.10", "0.1.0-beta.1", "0.1.0-rc.1",
		"0.1.0", "0.1.0+build.7", "0.2.0", "0.9.0", "0.10.0", "1.0.0-alpha", "1.0.0-alpha.beta", "1.0.0-alpha-1", "1.0.0-alpha0",
		"1.0.0-a", "1.0.0-A", "1.0.0-0a", "1.0.0-007", "1.0.0-8", "1.0.0-1.0.0", "1.0.0-18446744073709551615",
		"1.0.0-18446744073709551616", "1.0.0-rc.1", "1.0.0", "1.0.01", "1.2.0", "1.10.0", "18446744073709551615.0.0",
		"18446744073709551616.0.0", "99999999999999999999.0.0", "100000000000000000000.0.0", "0.2.1700000000-good"}
	keys := make([]string, len(versions))
	for i, v := range versions {
		if err := h.super.QueryRow(context.Background(), "SELECT paddock_version_key($1)", v).Scan(&keys[i]); err != nil {
			t.Fatalf("%s: %v", v, err)
		}
	}
	for i, a := range versions {
		for j, b := range versions {
			if got, want := strings.Compare(keys[i], keys[j]), semver.Compare(a, b); got != want {
				t.Errorf("%s vs %s: key order %d, Compare %d (keys %q, %q)", a, b, got, want, keys[i], keys[j])
			}
		}
	}
	for _, invalid := range []string{"", "1.0", "v1.0.0", "1.0.0-", "unknown"} {
		var key *string
		if err := h.super.QueryRow(context.Background(), "SELECT paddock_version_key($1)", invalid).Scan(&key); err != nil || key != nil {
			t.Errorf("%q: key %v, %v; want NULL", invalid, key, err)
		}
	}
}

// TestListReleasesSortsByVersion (PDK-025): sort=version orders by SemVer precedence, not as text (0.2.0 before
// 0.10.0, pre-releases before their release, alpha.2 before alpha.10).
func TestListReleasesSortsByVersion(t *testing.T) {
	h := newReleaseHarness(t, true)
	major := strconv.FormatInt(time.Now().UnixNano()%9000000+1000000, 10)
	want := []string{major + ".2.0", major + ".9.0-alpha.2", major + ".9.0-alpha.10", major + ".9.0-rc.1", major + ".9.0", major + ".10.0"}
	for _, i := range []int{5, 2, 0, 4, 1, 3} {
		if _, err := h.releases.Create(platformAdmin(), want[i]); err != nil {
			t.Fatal(err)
		}
	}
	descending := slices.Clone(want)
	slices.Reverse(descending)
	pattern := "%" + major + ".%"
	for sort, order := range map[string][]string{"version": want, "-version": descending} {
		listed, err := h.releases.List(platformAdmin(), app.ListPage{Sort: sort, QPattern: &pattern, Limit: 10}, nil)
		if err != nil {
			t.Fatal(err)
		}
		got := make([]string, len(listed.Items))
		for i, r := range listed.Items {
			got[i] = r.Version
		}
		if !slices.Equal(got, order) {
			t.Errorf("sort=%s: %v, want %v", sort, got, order)
		}
	}
}
