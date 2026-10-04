package admin_test

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"aead.dev/minisign"
	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/server/internal/principal"
)

func TestAgentReleasesAPI(t *testing.T) {
	e := newEnv(t)
	root := e.platformSession()
	if _, err := e.super.Exec(t.Context(), "UPDATE agent_rollout SET status = 'halted' WHERE status = 'running'"); err != nil {
		t.Fatal(err)
	}
	v := "2.0.0-api" + uuid.NewString()[:6]
	base := "/api/platform/v1/agent-releases/" + v

	created := e.do(call{method: "POST", path: "/api/platform/v1/agent-releases", body: map[string]string{"version": v}, cookie: root})
	if created.status != http.StatusCreated || created.header.Get("Location") != base {
		t.Fatalf("create: %d %s %s", created.status, created.header.Get("Location"), created.body)
	}
	bin := []byte("\x7fELF paddockd")
	sig := base64.StdEncoding.EncodeToString(minisign.Sign(e.release, bin))
	upload := func(sig string) result {
		return e.do(call{method: "PUT", path: base + "/artifacts/amd64", rawBody: string(bin), contentType: "application/octet-stream",
			headers: map[string]string{"X-Paddock-Minisig": sig}, cookie: root})
	}
	if r := upload(base64.StdEncoding.EncodeToString([]byte("forged"))); r.status != http.StatusBadRequest {
		t.Fatalf("forged signature: %d %s", r.status, r.body)
	}
	var art struct {
		Arch   string `json:"arch"`
		Size   int64  `json:"size"`
		Sha256 string `json:"sha256"`
	}
	r := upload(sig)
	r.decode(t, &art)
	if r.status != http.StatusOK || art.Arch != "amd64" || art.Size != int64(len(bin)) || len(art.Sha256) != 64 {
		t.Fatalf("upload: %d %s", r.status, r.body)
	}
	if r := e.do(call{method: "POST", path: base + "/publish", cookie: root}); r.status != http.StatusOK || !strings.Contains(string(r.body), `"published"`) {
		t.Fatalf("publish: %d %s", r.status, r.body)
	}
	start := e.do(call{method: "POST", path: base + "/rollout", cookie: root,
		body: map[string]any{"waves": []int{100}, "min_wave_minutes": 1, "failure_threshold_min": 1}})
	if start.status != http.StatusCreated {
		t.Fatalf("start: %d %s", start.status, start.body)
	}
	var detail struct {
		Release struct {
			RolloutStatus string `json:"rollout_status"`
			ArtifactCount int    `json:"artifact_count"`
		} `json:"release"`
		Counts *struct{ Failed int64 } `json:"counts"`
	}
	d := e.do(call{method: "GET", path: base, cookie: root})
	d.decode(t, &detail)
	if detail.Release.RolloutStatus != "running" || detail.Release.ArtifactCount != 1 || detail.Counts == nil {
		t.Fatalf("detail %s", d.body)
	}
	list := e.do(call{method: "GET", path: "/api/platform/v1/agent-releases?sort=-version&q=" + v, cookie: root})
	if list.status != http.StatusOK || !strings.Contains(string(list.body), v) {
		t.Fatalf("list: %d %s", list.status, list.body)
	}
	if r := e.do(call{method: "POST", path: base + "/rollout/halt", cookie: root}); r.status != http.StatusOK {
		t.Fatalf("halt: %d %s", r.status, r.body)
	}
	if r := e.do(call{method: "POST", path: base + "/rollout/halt", cookie: root}); r.status != http.StatusConflict {
		t.Fatalf("halt twice: %d %s", r.status, r.body)
	}
	if r := e.do(call{method: "POST", path: base + "/rollout/resume", cookie: root}); r.status != http.StatusOK {
		t.Fatalf("resume: %d %s", r.status, r.body)
	}
	_ = e.do(call{method: "POST", path: base + "/rollout/halt", cookie: root})

	// Organization administrators get 403 on every platform endpoint, and each attempt is audited.
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	if r := e.do(call{method: "GET", path: "/api/platform/v1/agent-releases", cookie: alice}); r.status != http.StatusForbidden {
		t.Fatalf("org admin list: %d", r.status)
	}
	denied := e.do(call{method: "POST", path: base + "/rollout/resume", cookie: alice})
	if denied.status != http.StatusForbidden {
		t.Fatalf("org admin resume: %d", denied.status)
	}
	if ev := e.events(denied.header.Get("X-Request-Id")); len(ev) != 1 {
		t.Fatalf("denied resume recorded %v", ev)
	}
}
