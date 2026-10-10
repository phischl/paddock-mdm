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
