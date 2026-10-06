package acceptance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"aead.dev/minisign"
	"github.com/oasdiff/yaml"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// installRelease publishes a gate release with the three Debian packages, so that autoinstalls generated afterwards
// use it (plan M4b decisions 1 and 2, plan M4c decision 4).
func installRelease(t *testing.T, root *env.Portal) string {
	t.Helper()
	v := gateRelease(t, root, true, false)
	for _, name := range []string{"paddock-agent", "paddock-supervisor"} {
		deb := []byte("!<arch>\n" + name + " " + v)
		expectStatus(t, uploadPackage(t, root, v, name, deb, minisign.Sign(releaseKey(t), deb)), http.StatusOK, "")
	}
	// paddock-revoke is installed by the autoinstall, signed with the revocation release key (plan M4c decision 4).
	revokeKey, err := stack.RevokeReleaseKey("")
	if err != nil {
		t.Fatal(err)
	}
	deb := []byte("!<arch>\npaddock-revoke " + v)
	expectStatus(t, uploadPackage(t, root, v, "paddock-revoke", deb, minisign.Sign(revokeKey, deb)), http.StatusOK, "")
	expectStatus(t, call(t, root, http.MethodPost, "/api/platform/v1/agent-releases/"+v+"/publish", nil), http.StatusOK, "")
	return v
}

// generated is the part of a Paddock autoinstall the gate checks.
type generated struct {
	Autoinstall struct {
		Storage struct {
			Layout struct{ Name, Password string }
		}
		LateCommands []any `json:"late-commands"`
	}
}

// TestAutoinstallGenerator is the generator gate of plan M4b (decisions 1–3): an operator's autoinstall for each
// release installs the packages of the newest release from the public bundles host, pinned by SHA-256, with a fresh
// random passphrase; the audit event names release and agent version but carries no secret; auditors are refused and
// another organization's configuration is not found.
func TestAutoinstallGenerator(t *testing.T) {
	root, alice, bob, carol := login(t, env.PlatformAdmin), login(t, env.Alice), login(t, env.Bob), login(t, env.Carol)
	v := installRelease(t, root)
	tok := createToken(t, alice, tokenOptions{maxUses: 1, autoApprove: true})
	client, err := env.NewHTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	passphrases := map[string]bool{}
	for _, release := range []string{"24.04", "26.04"} {
		res := call(t, alice, http.MethodPost, "/api/v1/autoinstall", autoinstallBody(tok.EnrollmentConfig, release))
		expectStatus(t, res, http.StatusOK, "")
		if ct := res.Header.Get("Content-Type"); ct != "text/yaml" || res.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: Content-Type %q, Cache-Control %q", release, ct, res.Header.Get("Cache-Control"))
		}
		ev := expectOneEvent(t, alice, res.RequestID, "autoinstall.generated", "success")
		if ev.Params["release"] != release || ev.Params["agent_version"] != v {
			t.Errorf("%s: audit params %v, want release and agent version %s", release, ev.Params, v)
		}
		raw, _ := json.Marshal(ev.Params)
		var doc generated
		js, err := yaml.YAMLToJSON(res.Body)
		if err == nil {
			err = json.Unmarshal(js, &doc)
		}
		if err != nil {
			t.Fatalf("%s: user-data is not YAML: %v", release, err)
		}
		pass := doc.Autoinstall.Storage.Layout.Password
		if doc.Autoinstall.Storage.Layout.Name != "lvm" || !regexp.MustCompile(`^[A-Za-z0-9]{32,}$`).MatchString(pass) || passphrases[pass] {
			t.Fatalf("%s: storage layout %q with a passphrase of %d characters (reused: %v)", release, doc.Autoinstall.Storage.Layout.Name, len(pass), passphrases[pass])
		}
		passphrases[pass] = true
		if strings.Contains(string(raw), pass) || strings.Contains(string(raw), tok.Secret) {
			t.Fatalf("%s: the audit event contains the passphrase or the token", release)
		}
		// Every package the installer downloads is public and matches its pinned SHA-256.
		downloads := 0
		for _, c := range doc.Autoinstall.LateCommands {
			args, _ := c.([]any)
			for i, a := range args {
				url, _ := a.(string)
				if !strings.HasPrefix(url, stack.BundlesURL()+"/packages/"+v+"/") || i+1 >= len(args) {
					continue
				}
				downloads++
				req, err := http.NewRequestWithContext(testContext(t, time.Minute), http.MethodGet, url, nil)
				if err != nil {
					t.Fatal(err)
				}
				got, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(got.Body)
				_ = got.Body.Close()
				sum := sha256.Sum256(body)
				if got.StatusCode != http.StatusOK || hex.EncodeToString(sum[:]) != args[i+1] {
					t.Errorf("%s: %s: HTTP %d, SHA-256 %x, pinned %v", release, url, got.StatusCode, sum, args[i+1])
				}
			}
		}
		if downloads != 3 {
			t.Errorf("%s: %d package downloads of release %s, want 3 (agent, supervisor, revoke)", release, downloads, v)
		}
	}

	res := call(t, bob, http.MethodPost, "/api/v1/autoinstall", autoinstallBody(tok.EnrollmentConfig, "26.04"))
	expectStatus(t, res, http.StatusForbidden, "forbidden")
	res = call(t, carol, http.MethodPost, "/api/v1/autoinstall", autoinstallBody(tok.EnrollmentConfig, "26.04"))
	expectStatus(t, res, http.StatusNotFound, "not_found")
}

// autoinstallAuditCases are the A3 cases of the generator (plan M4b decision 2).
var autoinstallAuditCases = []auditCase{
	{"success", func(t *testing.T, w *auditWorld) {
		installRelease(t, w.root)
		tok := createToken(t, w.alice, tokenOptions{})
		res := call(t, w.alice, http.MethodPost, "/api/v1/autoinstall", autoinstallBody(tok.EnrollmentConfig, "26.04"))
		expectStatus(t, res, http.StatusOK, "")
		expectOneEvent(t, w.alice, res.RequestID, "autoinstall.generated", "success")
	}},
	{"validation failure", func(t *testing.T, w *auditWorld) {
		body := autoinstallBody(createToken(t, w.alice, tokenOptions{}).EnrollmentConfig, "26.04")
		body["hostname"] = "Not A Hostname"
		res := call(t, w.alice, http.MethodPost, "/api/v1/autoinstall", body)
		expectStatus(t, res, http.StatusBadRequest, "invalid_request")
		expectOneEvent(t, w.alice, res.RequestID, "autoinstall.generated", "failure")
	}},
	{"wrong role", func(t *testing.T, w *auditWorld) {
		res := call(t, w.bob, http.MethodPost, "/api/v1/autoinstall", autoinstallBody(createToken(t, w.alice, tokenOptions{}).EnrollmentConfig, "26.04"))
		expectStatus(t, res, http.StatusForbidden, "forbidden")
		expectOneEvent(t, w.alice, res.RequestID, "autoinstall.generated", "denied")
	}},
	{"not found", func(t *testing.T, w *auditWorld) {
		cfg := createToken(t, w.alice, tokenOptions{}).EnrollmentConfig
		cfg.Token = "unknown-" + uniqueSuffix()
		res := call(t, w.alice, http.MethodPost, "/api/v1/autoinstall", autoinstallBody(cfg, "26.04"))
		expectStatus(t, res, http.StatusNotFound, "not_found")
		expectOneEvent(t, w.alice, res.RequestID, "autoinstall.generated", "failure")
	}},
	{"revoked token", func(t *testing.T, w *auditWorld) {
		tok := createToken(t, w.alice, tokenOptions{})
		expectStatus(t, call(t, w.alice, http.MethodPost, "/api/v1/enrollment-tokens/"+tok.Token.ID+"/revoke", nil), http.StatusOK, "")
		res := call(t, w.alice, http.MethodPost, "/api/v1/autoinstall", autoinstallBody(tok.EnrollmentConfig, "26.04"))
		expectStatus(t, res, http.StatusUnprocessableEntity, "token_revoked")
		expectOneEvent(t, w.alice, res.RequestID, "autoinstall.generated", "failure")
	}},
}

func init() { deviceAuditCases["POST /api/v1/autoinstall"] = autoinstallAuditCases }
