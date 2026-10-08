package acceptance

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// paddockctl runs the binary that `make acceptance` builds (PADDOCK_ACCEPTANCE_PADDOCKCTL) with the stack's URL and
// Caddy CA and the given token file.
type paddockctl struct {
	bin, caFile string
}

func newPaddockctl(t *testing.T) paddockctl {
	t.Helper()
	bin := os.Getenv("PADDOCK_ACCEPTANCE_PADDOCKCTL")
	if bin == "" {
		t.Fatal("PADDOCK_ACCEPTANCE_PADDOCKCTL is not set: run the gate with make acceptance, which builds bin/paddockctl")
	}
	dir, err := stack.SecretsDir()
	if err != nil {
		t.Fatal(err)
	}
	return paddockctl{bin: bin, caFile: filepath.Join(dir, "caddy-root.crt")}
}

type ctlResult struct {
	code           int
	stdout, stderr string
}

func (p paddockctl) run(t *testing.T, tokenFile, stdin string, args ...string) ctlResult {
	t.Helper()
	cmd := exec.CommandContext(testContext(t, 2*time.Minute), p.bin, args...) //nolint:gosec // the gate's own binary
	cmd.Env = []string{"PADDOCK_URL=" + stack.AdminURL(), "PADDOCK_CA_FILE=" + p.caFile, "PADDOCK_TOKEN_FILE=" + tokenFile,
		"HOME=" + t.TempDir()}
	cmd.Stdin = strings.NewReader(stdin)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	var exit *exec.ExitError
	code := 0
	switch {
	case errors.As(err, &exit):
		code = exit.ExitCode()
	case err != nil:
		t.Fatalf("paddockctl %s: %v", strings.Join(args, " "), err)
	}
	return ctlResult{code: code, stdout: out.String(), stderr: errOut.String()}
}

// tokenFile writes a secret to a file of mode mode.
func tokenFile(t *testing.T, secret string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

var changeSetLine = regexp.MustCompile(`Applied change set [0-9a-f-]{36}\n`)

// TestPaddockctl is gate T3 of plan M6c: whoami, get config, apply with dry run, the refusal of deletions without
// --yes and the apply with --yes, devices list and the exit codes of a wrong secret and an open token file. Applies
// run in an organization of their own (gateOrg).
func TestPaddockctl(t *testing.T) {
	ctl := newPaddockctl(t)
	alice := login(t, env.Alice)
	acmeToken := createAPIToken(t, alice, env.Alice, "org_auditor")
	acme := tokenFile(t, acmeToken.Secret, 0o600)

	if r := ctl.run(t, acme, "", "whoami"); r.code != 0 || !strings.Contains(r.stdout, "organization: acme") ||
		!strings.Contains(r.stdout, "token: "+acmeToken.Token.Name) || strings.Contains(r.stdout, acmeToken.Secret) {
		t.Fatalf("whoami: %+v", r)
	}
	r := ctl.run(t, acme, "", "devices", "list", "--page-size", "10", "-o", "json")
	var page struct {
		PageSize int   `json:"page_size"`
		Items    []any `json:"items"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &page); err != nil || r.code != 0 || page.PageSize != 10 || page.Items == nil {
		t.Fatalf("devices list: %+v (%v)", r, err)
	}
	if r := ctl.run(t, tokenFile(t, "pdk_"+strings.Repeat("A", 43), 0o600), "", "whoami"); r.code != 1 || !strings.Contains(r.stderr, "unauthenticated") {
		t.Fatalf("wrong secret: %+v", r)
	}
	if r := ctl.run(t, tokenFile(t, acmeToken.Secret, 0o644), "", "whoami"); r.code != 2 || !strings.Contains(r.stderr, "readable by others") {
		t.Fatalf("0644 token file: %+v", r)
	}

	admin, _ := gateOrg(t, "t3-admin")
	res := call(t, admin.Portal, http.MethodPost, "/api/v1/package-holds", map[string]any{"package": "t3-held"})
	expectStatus(t, res, http.StatusCreated, "")
	admin.stepUp(t)
	created := postAPIToken(t, admin.Portal, apiTokenName("t3"), "org_admin", 2*time.Hour)
	expectStatus(t, created, http.StatusCreated, "")
	removeCreated(t, admin.Portal, "/api/v1/api-tokens", created)
	var tok apiTokenCreated
	if err := created.JSON(&tok); err != nil {
		t.Fatal(err)
	}
	org := tokenFile(t, tok.Secret, 0o600)

	exported := ctl.run(t, org, "", "get", "config")
	if exported.code != 0 || !strings.HasPrefix(exported.stdout, "api_version: \"paddock/v1\"\nkind: \"OrganizationConfig\"\nsettings:\n") {
		t.Fatalf("get config: %+v", exported)
	}
	if r := ctl.run(t, org, exported.stdout, "apply", "--dry-run", "-f", "-"); r.code != 0 ||
		!strings.HasSuffix(r.stdout, "Plan: 0 to create, 0 to update, 0 to delete\n") {
		t.Fatalf("dry run of the export: %+v", r)
	}

	var doc map[string]any
	if r := ctl.run(t, org, "", "get", "config", "-o", "json"); r.code != 0 || json.Unmarshal([]byte(r.stdout), &doc) != nil {
		t.Fatalf("get config -o json: %+v", r)
	}
	doc["managed_files"] = append(doc["managed_files"].([]any), map[string]any{"path": "/etc/paddock-t3.conf", "content": "t3\n"})
	added, _ := json.Marshal(doc)
	if r := ctl.run(t, org, string(added), "apply", "--dry-run", "-f", "-"); r.code != 0 || !strings.Contains(r.stdout, "+ managed_files /etc/paddock-t3.conf\n") {
		t.Fatalf("dry run of a changed file: %+v", r)
	}
	if n := listTotal(t, admin.Portal, "/api/v1/change-sets"); n != 0 {
		t.Fatalf("the dry run recorded %d change sets", n)
	}

	doc["package_holds"] = []any{}
	changed, _ := json.Marshal(doc)
	file := filepath.Join(t.TempDir(), "paddock.json")
	if err := os.WriteFile(file, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	if r := ctl.run(t, org, "", "apply", "-f", file); r.code != 3 || !strings.Contains(r.stderr, "plan deletes 1 resources; re-run with --yes") {
		t.Fatalf("apply with a deletion and no --yes: %+v", r)
	}
	if listTotal(t, admin.Portal, "/api/v1/package-holds?q=t3-held") != 1 || listTotal(t, admin.Portal, "/api/v1/managed-files?q=paddock-t3") != 0 {
		t.Fatal("the refused apply changed something")
	}
	if r := ctl.run(t, org, "", "apply", "--yes", "-f", file); r.code != 0 || !changeSetLine.MatchString(r.stdout) {
		t.Fatalf("apply --yes: %+v", r)
	}
	if listTotal(t, admin.Portal, "/api/v1/package-holds?q=t3-held") != 0 || listTotal(t, admin.Portal, "/api/v1/managed-files?q=paddock-t3") != 1 {
		t.Fatal("apply --yes did not apply the document")
	}
	if listTotal(t, admin.Portal, "/api/v1/change-sets?source=api_token") != 1 {
		t.Fatal("the apply is not a change set of source api_token")
	}
}
