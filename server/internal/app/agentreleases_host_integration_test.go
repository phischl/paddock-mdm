package app_test

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"

	"aead.dev/minisign"
	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/releasesig"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/agentrelease"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// hostFiles are the signed files of a release as the offline signing step produces them (plan M7b §6.4).
func (h releaseHarness) hostFiles(version string) ([]app.HostArtifact, []app.HostPackage) {
	bin := []byte("paddockd " + version)
	deb := []byte("paddock-agent deb " + version)
	return []app.HostArtifact{{Arch: "amd64", Binary: bin,
			Minisig: minisign.SignWithComments(h.priv, bin, releasesig.Comment(version, "amd64"), "")}},
		[]app.HostPackage{{Name: agentrelease.PackageAgent, Arch: "amd64", Deb: deb, Minisig: minisign.Sign(h.priv, deb)}}
}

// TestAgentReleasePublishFromHost: the host command publishes through the API's use cases with their audit events
// and the system actor of the host commands (plan M7b decision 31).
func TestAgentReleasePublishFromHost(t *testing.T) {
	h := newReleaseHarness(t, false)
	corr := "host-" + uuid.NewString()
	ctx := httpx.WithRequestID(context.Background(), corr)
	v := uniqueVersion()
	arts, pkgs := h.hostFiles(v)

	d, err := h.releases.PublishFromHost(ctx, v, arts, pkgs)
	if err != nil {
		t.Fatal(err)
	}
	if d.Release.Status != agentrelease.StatusPublished || len(d.Artifacts) != 1 || len(d.Packages) != 1 {
		t.Fatalf("release %+v, %d artifacts, %d packages", d.Release, len(d.Artifacts), len(d.Packages))
	}
	if _, ok := h.store.puts[agentrelease.ObjectKey(v, "amd64")]; !ok {
		t.Error("the binary was not stored")
	}
	for code, want := range map[string]int{
		"agent_release.created": 1, "agent_release.artifact_uploaded": 2, "agent_release.published": 1,
	} {
		if n := countRows(t, h.super, `SELECT count(*) FROM action WHERE correlation_id = $1 AND code = $2
			AND outcome = 'success' AND actor->>'type' = 'system' AND actor->>'display' = 'paddock-server admin'`,
			corr, code); n != want {
			t.Errorf("%d %s events of the host actor, want %d", n, code, want)
		}
	}

	if _, err := h.releases.PublishFromHost(ctx, v, arts, pkgs); !errors.Is(err, problem.InvalidState) {
		t.Errorf("publishing %s again: %v, want invalid_state (already published)", v, err)
	}
}

// TestAgentReleasePublishFromHostRefusesBadSignatures: a file signed with another key or a binary signed for another
// release creates nothing and stores nothing.
func TestAgentReleasePublishFromHostRefusesBadSignatures(t *testing.T) {
	h := newReleaseHarness(t, false)
	_, otherKey, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx := httpx.WithRequestID(context.Background(), uuid.NewString())
	for name, tamper := range map[string]func(v string, arts []app.HostArtifact, pkgs []app.HostPackage){
		"package signed with another key": func(_ string, _ []app.HostArtifact, pkgs []app.HostPackage) {
			pkgs[0].Minisig = minisign.Sign(otherKey, pkgs[0].Deb)
		},
		"binary signed with another key": func(v string, arts []app.HostArtifact, _ []app.HostPackage) {
			arts[0].Minisig = minisign.SignWithComments(otherKey, arts[0].Binary, releasesig.Comment(v, "amd64"), "")
		},
		"binary signed for another release": func(_ string, arts []app.HostArtifact, _ []app.HostPackage) {
			arts[0].Minisig = minisign.SignWithComments(h.priv, arts[0].Binary, releasesig.Comment("9.9.9", "amd64"), "")
		},
	} {
		v := uniqueVersion()
		arts, pkgs := h.hostFiles(v)
		tamper(v, arts, pkgs)
		before := len(h.store.puts)
		if _, err := h.releases.PublishFromHost(ctx, v, arts, pkgs); err == nil {
			t.Errorf("%s: published", name)
		}
		if n := countRows(t, h.super, "SELECT count(*) FROM agent_release WHERE version = $1", v); n != 0 {
			t.Errorf("%s: the release was created", name)
		}
		if len(h.store.puts) != before {
			t.Errorf("%s: a file was stored", name)
		}
		if n := countRows(t, h.super, `SELECT count(*) FROM action WHERE target->>'id' = $1`, v); n != 1 {
			t.Errorf("%s: %d audit events of %s, want exactly the failed upload", name, n, v)
		}
		if n := countRows(t, h.super, `SELECT count(*) FROM action WHERE target->>'id' = $1
			AND code = 'agent_release.artifact_uploaded' AND outcome = 'failure'
			AND actor->>'type' = 'system' AND actor->>'display' = 'paddock-server admin'`, v); n != 1 {
			t.Errorf("%s: no failed agent_release.artifact_uploaded event of the host actor", name)
		}
	}
}

// TestAgentReleasePublishFromHostAuditsRefusedCreation: an invalid version and a release without a binary are refused
// with exactly one failed agent_release.created event of the host actor, as the API records an invalid version.
func TestAgentReleasePublishFromHostAuditsRefusedCreation(t *testing.T) {
	h := newReleaseHarness(t, false)
	ctx := httpx.WithRequestID(context.Background(), uuid.NewString())
	for name, tc := range map[string]struct {
		version string
		noBin   bool
	}{
		"invalid version": {version: "not a version " + uuid.NewString()},
		"no agent binary": {version: uniqueVersion(), noBin: true},
	} {
		arts, pkgs := h.hostFiles(tc.version)
		if tc.noBin {
			arts = nil
		}
		if _, err := h.releases.PublishFromHost(ctx, tc.version, arts, pkgs); !errors.Is(err, problem.InvalidRequest) {
			t.Errorf("%s: %v, want invalid_request", name, err)
		}
		if n := countRows(t, h.super, `SELECT count(*) FROM action WHERE target->>'id' = $1`, tc.version); n != 1 {
			t.Errorf("%s: %d audit events, want exactly the failed creation", name, n)
		}
		if n := countRows(t, h.super, `SELECT count(*) FROM action WHERE target->>'id' = $1
			AND code = 'agent_release.created' AND outcome = 'failure' AND params->>'version' = $1
			AND actor->>'type' = 'system' AND actor->>'display' = 'paddock-server admin'`, tc.version); n != 1 {
			t.Errorf("%s: no failed agent_release.created event of the host actor", name)
		}
	}
}

// TestAgentRolloutFromHost: the host commands start and halt a rollout with the API's validation and problem codes and
// one audit event per attempt of the host actor (ADR 0034 amendment 2026-10-26).
func TestAgentRolloutFromHost(t *testing.T) {
	h := newReleaseHarness(t, false)
	h.haltAll(t)
	t.Cleanup(func() { h.haltAll(t) })
	corr := "host-" + uuid.NewString()
	ctx := httpx.WithRequestID(context.Background(), corr)
	hostEvents := func(code, outcome string) int {
		t.Helper()
		return countRows(t, h.super, `SELECT count(*) FROM action WHERE correlation_id = $1 AND code = $2 AND outcome = $3
			AND actor->>'type' = 'system' AND actor->>'display' = 'paddock-server admin'`, corr, code, outcome)
	}

	draft := uniqueVersion()
	if _, err := h.releases.Create(platformAdmin(), draft); err != nil {
		t.Fatal(err)
	}
	_, err := h.releases.StartRolloutFromHost(ctx, draft, app.RolloutOptions{})
	expectProblem(t, err, problem.InvalidState)
	v := h.published(t)
	_, err = h.releases.StartRolloutFromHost(ctx, v, app.RolloutOptions{Waves: []int{50, 10}})
	expectProblem(t, err, problem.InvalidRequest)
	if n := hostEvents("agent_rollout.started", "failure"); n != 2 {
		t.Errorf("%d failed agent_rollout.started events of the host actor, want 2", n)
	}

	r, err := h.releases.StartRolloutFromHost(ctx, v, app.RolloutOptions{})
	if err != nil || r.Status != agentrelease.RolloutRunning || len(r.Waves) != len(agentrelease.DefaultWaves) ||
		r.StartedBy != "paddock-server admin" {
		t.Fatalf("start: %+v, %v", r, err)
	}
	if n := hostEvents("agent_rollout.started", "success"); n != 1 {
		t.Errorf("%d agent_rollout.started events of the host actor, want 1", n)
	}
	_, err = h.releases.StartRolloutFromHost(ctx, v, app.RolloutOptions{})
	expectProblem(t, err, problem.AlreadyExists)
	_, err = h.releases.StartRolloutFromHost(ctx, h.published(t), app.RolloutOptions{})
	expectProblem(t, err, problem.InvalidState)

	if r, err := h.releases.HaltFromHost(ctx, v); err != nil || r.Status != agentrelease.RolloutHalted || r.HaltedReason == nil {
		t.Fatalf("halt: %+v, %v", r, err)
	}
	if n := hostEvents("agent_rollout.halted", "success"); n != 1 {
		t.Errorf("%d agent_rollout.halted events of the host actor, want 1", n)
	}
	_, err = h.releases.HaltFromHost(ctx, v)
	expectProblem(t, err, problem.InvalidState)
}
