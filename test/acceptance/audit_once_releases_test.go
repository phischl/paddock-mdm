package acceptance

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"testing"
	"time"

	"aead.dev/minisign"
	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/releasesig"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// releaseKey is the development release key (make dev-release-key).
func releaseKey(t *testing.T) minisign.PrivateKey {
	t.Helper()
	k, err := stack.ReleaseKey("")
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func gateVersion() string { return "0.0.1-gate" + uuid.NewString()[:8] }

// uploadArtifact sends a signed (or, with sig set, any) binary as the amd64 artifact of version.
func uploadArtifact(t *testing.T, p *env.Portal, version string, bin, sig []byte) env.Response {
	t.Helper()
	return uploadRelease(t, p, version, "/artifacts/amd64", bin, sig)
}

// uploadPackage sends a Debian package as the amd64 package name of version (plan M4b decision 1).
func uploadPackage(t *testing.T, p *env.Portal, version, name string, deb, sig []byte) env.Response {
	t.Helper()
	return uploadRelease(t, p, version, "/packages/"+name+"/amd64", deb, sig)
}

// uploadRelease PUTs a file below a release with its minisign signature.
func uploadRelease(t *testing.T, p *env.Portal, version, path string, body, sig []byte) env.Response {
	t.Helper()
	ctx := testContext(t, time.Minute)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, stack.AdminURL()+"/api/platform/v1/agent-releases/"+version+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Paddock-CSRF", "1")
	req.Header.Set("X-Paddock-Minisig", base64.StdEncoding.EncodeToString(sig))
	res, err := p.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	data, _ := io.ReadAll(res.Body)
	return env.Response{Status: res.StatusCode, Header: res.Header, Body: data, RequestID: res.Header.Get("X-Request-Id")}
}

// gateRelease creates a release as root; with artifact it uploads a signed binary, with publish it publishes.
func gateRelease(t *testing.T, root *env.Portal, artifact, publish bool) string {
	t.Helper()
	v := gateVersion()
	expectStatus(t, call(t, root, http.MethodPost, "/api/platform/v1/agent-releases", map[string]string{"version": v}), http.StatusCreated, "")
	if artifact {
		bin := []byte("gate binary " + v)
		expectStatus(t, uploadArtifact(t, root, v, bin, signBinary(t, bin, v)), http.StatusOK, "")
	}
	if publish {
		expectStatus(t, call(t, root, http.MethodPost, "/api/platform/v1/agent-releases/"+v+"/publish", nil), http.StatusOK, "")
	}
	return v
}

// gateRollout returns a published release with a running rollout (other running rollouts are halted first, and the
// gate's own when the test ends: its binary is not a real agent).
func gateRollout(t *testing.T, root *env.Portal) string {
	t.Helper()
	haltRunningRollouts(t, root)
	t.Cleanup(func() { haltRunningRollouts(t, root) })
	v := gateRelease(t, root, true, true)
	expectStatus(t, call(t, root, http.MethodPost, "/api/platform/v1/agent-releases/"+v+"/rollout", map[string]any{}), http.StatusCreated, "")
	return v
}

func haltRunningRollouts(t *testing.T, root *env.Portal) {
	t.Helper()
	res := call(t, root, http.MethodGet, "/api/platform/v1/agent-releases?page_size=100", nil)
	expectStatus(t, res, http.StatusOK, "")
	var page struct {
		Items []struct {
			Version       string `json:"version"`
			RolloutStatus string `json:"rollout_status"`
		} `json:"items"`
	}
	if err := res.JSON(&page); err != nil {
		t.Fatal(err)
	}
	for _, r := range page.Items {
		if r.RolloutStatus == "running" {
			expectStatus(t, call(t, root, http.MethodPost, "/api/platform/v1/agent-releases/"+r.Version+"/rollout/halt", nil), http.StatusOK, "")
		}
	}
}

// platformCase builds the audit cases of a platform release operation: the request is made by run with the
// session and version it gets; events of platform administrators go to the platform pseudo-organization, denials
// of organization administrators to their own organization.
func platformCase(name, code, outcome string, status int, problemCode string, setup func(t *testing.T, w *auditWorld) string,
	run func(t *testing.T, p *env.Portal, version string) env.Response, asAlice bool) auditCase {
	return auditCase{name, func(t *testing.T, w *auditWorld) {
		v := setup(t, w)
		p := w.root
		if asAlice {
			p = w.alice
		}
		res := run(t, p, v)
		expectStatus(t, res, status, problemCode)
		if asAlice {
			expectOneEvent(t, w.alice, res.RequestID, code, outcome)
			return
		}
		expectOneIndexEvent(t, w.idx, platformOrg, "correlation_id = $1", res.RequestID, code, outcome, auditPollTimeout)
	}}
}

func post(path string) func(t *testing.T, p *env.Portal, v string) env.Response {
	return func(t *testing.T, p *env.Portal, v string) env.Response {
		return call(t, p, http.MethodPost, "/api/platform/v1/agent-releases/"+v+path, nil)
	}
}

var (
	unknownRelease = func(*testing.T, *auditWorld) string { return gateVersion() }
	draftRelease   = func(t *testing.T, w *auditWorld) string { return gateRelease(t, w.root, false, false) }
	draftArtifact  = func(t *testing.T, w *auditWorld) string { return gateRelease(t, w.root, true, false) }
	publishedRel   = func(t *testing.T, w *auditWorld) string { return gateRelease(t, w.root, true, true) }
	runningRollout = func(t *testing.T, w *auditWorld) string { return gateRollout(t, w.root) }
	haltedRollout  = func(t *testing.T, w *auditWorld) string {
		v := gateRollout(t, w.root)
		expectStatus(t, call(t, w.root, http.MethodPost, "/api/platform/v1/agent-releases/"+v+"/rollout/halt", nil), http.StatusOK, "")
		return v
	}
)

// signBinary signs an amd64 agent binary of version v as make agent-release does (plan M4b.1 decision 10).
func signBinary(t *testing.T, bin []byte, v string) []byte {
	return minisign.SignWithComments(releaseKey(t), bin, releasesig.Comment(v, "amd64"), "")
}

func signedUpload(t *testing.T, p *env.Portal, v string) env.Response {
	bin := []byte("gate binary " + v)
	return uploadArtifact(t, p, v, bin, signBinary(t, bin, v))
}

func signedPackage(t *testing.T, p *env.Portal, v string) env.Response {
	deb := []byte("gate package " + v)
	return uploadPackage(t, p, v, "paddock-agent", deb, minisign.Sign(releaseKey(t), deb))
}

// releaseAuditCases are the A3 cases of the agent release operations (plan M2b decision 20).
var releaseAuditCases = map[string][]auditCase{
	"POST /api/platform/v1/agent-releases": {
		platformCase("success", "agent_release.created", "success", http.StatusCreated, "", unknownRelease, func(t *testing.T, p *env.Portal, v string) env.Response {
			return call(t, p, http.MethodPost, "/api/platform/v1/agent-releases", map[string]string{"version": v})
		}, false),
		platformCase("validation failure", "agent_release.created", "failure", http.StatusBadRequest, "invalid_request", unknownRelease, func(t *testing.T, p *env.Portal, _ string) env.Response {
			return call(t, p, http.MethodPost, "/api/platform/v1/agent-releases", map[string]string{"version": "v1"})
		}, false),
		platformCase("wrong role", "agent_release.created", "denied", http.StatusForbidden, "forbidden", unknownRelease, func(t *testing.T, p *env.Portal, v string) env.Response {
			return call(t, p, http.MethodPost, "/api/platform/v1/agent-releases", map[string]string{"version": v})
		}, true),
		platformCase("conflict", "agent_release.created", "failure", http.StatusConflict, "already_exists", draftRelease, func(t *testing.T, p *env.Portal, v string) env.Response {
			return call(t, p, http.MethodPost, "/api/platform/v1/agent-releases", map[string]string{"version": v})
		}, false),
	},
	"PUT /api/platform/v1/agent-releases/{version}/artifacts/{arch}": {
		platformCase("success", "agent_release.artifact_uploaded", "success", http.StatusOK, "", draftRelease, signedUpload, false),
		platformCase("validation failure", "agent_release.artifact_uploaded", "failure", http.StatusBadRequest, "invalid_request", draftRelease,
			func(t *testing.T, p *env.Portal, v string) env.Response {
				return uploadArtifact(t, p, v, []byte("forged"), minisign.Sign(releaseKey(t), []byte("something else")))
			}, false),
		platformCase("signed for another version", "agent_release.artifact_uploaded", "failure", http.StatusUnprocessableEntity,
			"release_signature_mismatch", draftRelease, func(t *testing.T, p *env.Portal, v string) env.Response {
				bin := []byte("gate binary " + v)
				return uploadArtifact(t, p, v, bin, signBinary(t, bin, "0.0.1-other"))
			}, false),
		platformCase("wrong role", "agent_release.artifact_uploaded", "denied", http.StatusForbidden, "forbidden", draftRelease, signedUpload, true),
		platformCase("not found", "agent_release.artifact_uploaded", "failure", http.StatusNotFound, "not_found", unknownRelease, signedUpload, false),
		platformCase("conflict", "agent_release.artifact_uploaded", "failure", http.StatusConflict, "invalid_state", publishedRel, signedUpload, false),
	},
	"PUT /api/platform/v1/agent-releases/{version}/packages/{name}/{arch}": {
		platformCase("success", "agent_release.artifact_uploaded", "success", http.StatusOK, "", draftRelease, signedPackage, false),
		platformCase("validation failure", "agent_release.artifact_uploaded", "failure", http.StatusBadRequest, "invalid_request", draftRelease,
			func(t *testing.T, p *env.Portal, v string) env.Response {
				return uploadPackage(t, p, v, "paddock-agent", []byte("forged"), minisign.Sign(releaseKey(t), []byte("something else")))
			}, false),
		platformCase("wrong role", "agent_release.artifact_uploaded", "denied", http.StatusForbidden, "forbidden", draftRelease, signedPackage, true),
		platformCase("not found", "agent_release.artifact_uploaded", "failure", http.StatusNotFound, "not_found", unknownRelease, signedPackage, false),
		platformCase("conflict", "agent_release.artifact_uploaded", "failure", http.StatusConflict, "invalid_state", publishedRel, signedPackage, false),
	},
	"POST /api/platform/v1/agent-releases/{version}/publish": {
		platformCase("success", "agent_release.published", "success", http.StatusOK, "", draftArtifact, post("/publish"), false),
		platformCase("wrong role", "agent_release.published", "denied", http.StatusForbidden, "forbidden", draftArtifact, post("/publish"), true),
		platformCase("not found", "agent_release.published", "failure", http.StatusNotFound, "not_found", unknownRelease, post("/publish"), false),
		platformCase("conflict", "agent_release.published", "failure", http.StatusConflict, "invalid_state", draftRelease, post("/publish"), false),
	},
	"POST /api/platform/v1/agent-releases/{version}/rollout": {
		platformCase("success", "agent_rollout.started", "success", http.StatusCreated, "",
			func(t *testing.T, w *auditWorld) string {
				haltRunningRollouts(t, w.root)
				t.Cleanup(func() { haltRunningRollouts(t, w.root) })
				return publishedRel(t, w)
			},
			func(t *testing.T, p *env.Portal, v string) env.Response {
				return call(t, p, http.MethodPost, "/api/platform/v1/agent-releases/"+v+"/rollout", map[string]any{})
			}, false),
		platformCase("validation failure", "agent_rollout.started", "failure", http.StatusBadRequest, "invalid_request", publishedRel,
			func(t *testing.T, p *env.Portal, v string) env.Response {
				return call(t, p, http.MethodPost, "/api/platform/v1/agent-releases/"+v+"/rollout", map[string]any{"waves": []int{50}})
			}, false),
		platformCase("wrong role", "agent_rollout.started", "denied", http.StatusForbidden, "forbidden", publishedRel,
			func(t *testing.T, p *env.Portal, v string) env.Response {
				return call(t, p, http.MethodPost, "/api/platform/v1/agent-releases/"+v+"/rollout", map[string]any{})
			}, true),
		platformCase("not found", "agent_rollout.started", "failure", http.StatusNotFound, "not_found", unknownRelease,
			func(t *testing.T, p *env.Portal, v string) env.Response {
				return call(t, p, http.MethodPost, "/api/platform/v1/agent-releases/"+v+"/rollout", map[string]any{})
			}, false),
		platformCase("conflict", "agent_rollout.started", "failure", http.StatusConflict, "already_exists", haltedRollout,
			func(t *testing.T, p *env.Portal, v string) env.Response {
				return call(t, p, http.MethodPost, "/api/platform/v1/agent-releases/"+v+"/rollout", map[string]any{})
			}, false),
	},
	"POST /api/platform/v1/agent-releases/{version}/rollout/halt": {
		platformCase("success", "agent_rollout.halted", "success", http.StatusOK, "", runningRollout, post("/rollout/halt"), false),
		platformCase("wrong role", "agent_rollout.halted", "denied", http.StatusForbidden, "forbidden", runningRollout, post("/rollout/halt"), true),
		platformCase("not found", "agent_rollout.halted", "failure", http.StatusNotFound, "not_found", publishedRel, post("/rollout/halt"), false),
		platformCase("conflict", "agent_rollout.halted", "failure", http.StatusConflict, "invalid_state", haltedRollout, post("/rollout/halt"), false),
	},
	"POST /api/platform/v1/agent-releases/{version}/rollout/resume": {
		platformCase("success", "agent_rollout.resumed", "success", http.StatusOK, "",
			func(t *testing.T, w *auditWorld) string {
				v := haltedRollout(t, w)
				haltRunningRollouts(t, w.root)
				return v
			}, post("/rollout/resume"), false),
		platformCase("wrong role", "agent_rollout.resumed", "denied", http.StatusForbidden, "forbidden", haltedRollout, post("/rollout/resume"), true),
		platformCase("not found", "agent_rollout.resumed", "failure", http.StatusNotFound, "not_found", publishedRel, post("/rollout/resume"), false),
		platformCase("conflict", "agent_rollout.resumed", "failure", http.StatusConflict, "invalid_state", runningRollout, post("/rollout/resume"), false),
	},
}
