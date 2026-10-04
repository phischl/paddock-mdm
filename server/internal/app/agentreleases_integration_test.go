package app_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"aead.dev/minisign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paddock-mdm/paddock/pkg/protocol"
	"github.com/paddock-mdm/paddock/server/internal/app"
	"github.com/paddock-mdm/paddock/server/internal/domain/agentrelease"
	"github.com/paddock-mdm/paddock/server/internal/platform/db"
	"github.com/paddock-mdm/paddock/server/internal/platform/httpx"
	"github.com/paddock-mdm/paddock/server/internal/principal"
	"github.com/paddock-mdm/paddock/server/internal/problem"
	"github.com/paddock-mdm/paddock/server/internal/testsupport/pgtest"
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
	verify := func(bin, sig []byte) bool { return minisign.Verify(pub, bin, sig) }
	return releaseHarness{
		releases: app.NewAgentReleases(runner, platform, store, verify, development),
		reports:  app.NewDeviceReports(runner, worker), store: store, priv: priv, super: super,
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
func (h releaseHarness) published(t *testing.T) string {
	t.Helper()
	ctx := platformAdmin()
	v := uniqueVersion()
	if _, err := h.releases.Create(ctx, v); err != nil {
		t.Fatal(err)
	}
	bin := []byte("paddockd " + v)
	if _, err := h.releases.UploadArtifact(ctx, v, "amd64", bin, base64.StdEncoding.EncodeToString(minisign.Sign(h.priv, bin))); err != nil {
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
	if len(h.store.puts) != 0 {
		t.Fatal("a binary with an invalid signature was stored")
	}
	art, err := h.releases.UploadArtifact(ctx, v, "amd64", bin, base64.StdEncoding.EncodeToString(minisign.Sign(h.priv, bin)))
	if err != nil || art.Size != 6 || art.ObjectKey != agentrelease.ObjectKey(v, "amd64") || string(h.store.puts[art.ObjectKey]) != "binary" {
		t.Fatalf("upload: %+v, %v", art, err)
	}
	if r, err := h.releases.Publish(ctx, v); err != nil || r.Status != agentrelease.StatusPublished {
		t.Fatalf("publish: %+v, %v", r, err)
	}
	_, err = h.releases.UploadArtifact(ctx, v, "amd64", bin, base64.StdEncoding.EncodeToString(minisign.Sign(h.priv, bin)))
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
	if err != nil || d.Rollout == nil || len(d.Artifacts) != 1 {
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
