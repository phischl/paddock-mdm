package cmd_test

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/phischl/paddock-mdm/cli/internal/cmd"
)

const secret = "pdk_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// planSHA is the plan_sha256 the fake API answers every dry run with.
const planSHA = "abababababababababababababababababababababababababababababababab"

// fakeAPI is the part of the admin API paddockctl uses; plan is the plan it answers to PUT /api/v1/config.
type fakeAPI struct {
	mu       sync.Mutex
	plan     string
	puts     []string // query of every PUT /api/v1/config
	lastBody []byte
	headers  http.Header
	// changed makes an apply with expected_plan fail as if the configuration changed after the dry run.
	changed bool
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.headers = r.Header.Clone()
	w.Header().Set("X-Request-Id", "req-1")
	if r.Header.Get("Authorization") != "Bearer "+secret {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"status":401,"code":"unauthenticated"}`)
		return
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /api/v1/me":
		_, _ = io.WriteString(w, `{"id":"t","role":"org_admin","organization":{"slug":"acme","name":"Acme"},`+
			`"api_token":{"name":"ci","expires_at":"2027-01-01T00:00:00Z"}}`)
	case "GET /api/v1/config":
		_, _ = io.WriteString(w, `{"api_version":"paddock/v1","kind":"OrganizationConfig","device_groups":[{"name":"g","description":""}]}`)
	case "PUT /api/v1/config":
		if r.Header.Get("X-Paddock-CSRF") != "1" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		f.puts = append(f.puts, r.URL.RawQuery)
		f.lastBody, _ = io.ReadAll(r.Body)
		dry := r.URL.Query().Get("dry_run") == "true"
		if !dry && f.changed && r.URL.Query().Get("expected_plan") != "" {
			w.WriteHeader(http.StatusPreconditionFailed)
			_, _ = io.WriteString(w, `{"status":412,"code":"plan_changed","detail":"the plan differs"}`)
			return
		}
		id := `"0193f7a2-6c1e-7cc1-9d1e-6a4f0f6e8a10"`
		if dry || strings.Contains(f.plan, `"changes":[]`) {
			id = "null"
		}
		_, _ = io.WriteString(w, `{"dry_run":`+map[bool]string{true: "true", false: "false"}[dry]+`,"change_set_id":`+id+`,"plan":`+f.plan+
			`,"plan_sha256":"`+planSHA+`"}`)
	case "GET /api/v1/devices":
		_, _ = io.WriteString(w, `{"items":[{"hostname":"h1","state":"active","last_contact_at":null,"agent_version":"1.0.0",`+
			`"applied_bundle_version":3}],"page":1,"page_size":10,"total":1,"total_capped":false,"sort":"hostname","q":"`+r.URL.RawQuery+`"}`)
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"status":404,"code":"not_found"}`)
	}
}

type run struct {
	code           int
	stdout, stderr string
}

func setup(t *testing.T, plan string) (*fakeAPI, func(stdin string, args ...string) run) {
	t.Helper()
	api := &fakeAPI{plan: plan}
	srv := httptest.NewTLSServer(api)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(token, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"PADDOCK_URL": srv.URL, "PADDOCK_TOKEN_FILE": token, "PADDOCK_CA_FILE": ca, "HOME": dir}
	return api, func(stdin string, args ...string) run {
		var out, errOut bytes.Buffer
		code := cmd.Main(context.Background(), cmd.Env{Args: args, Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errOut,
			Getenv: func(k string) string { return env[k] }, Version: "1.2.3"})
		return run{code, out.String(), errOut.String()}
	}
}

const (
	emptyPlan  = `{"changes":[],"created":0,"updated":0,"deleted":0}`
	createPlan = `{"changes":[{"section":"managed_files","key":"/etc/motd","action":"create","fields":[]}],"created":1,"updated":0,"deleted":0}`
	deletePlan = `{"changes":[{"section":"package_holds","key":"firefox","action":"delete","fields":[]},` +
		`{"section":"settings.login","key":"","action":"update","fields":[{"name":"hello_enabled","before":false,"after":true}]}],"created":0,"updated":1,"deleted":1}`
)

func TestVersionSchemaAndUsage(t *testing.T) {
	_, pc := setup(t, emptyPlan)
	if r := pc("", "version"); r.code != 0 || r.stdout != "paddockctl 1.2.3\n" {
		t.Fatalf("version: %+v", r)
	}
	if r := pc("", "schema"); r.code != 0 || !strings.Contains(r.stdout, `"$id": "https://paddock-mdm.invalid/schema/paddock.v1.json"`) {
		t.Fatalf("schema: %d", r.code)
	}
	for _, args := range [][]string{{}, {"nope"}, {"get"}, {"get", "devices"}, {"apply"}, {"devices"}, {"whoami", "-o", "yaml"},
		{"get", "config", "--bogus"}, {"version", "x"}} {
		if r := pc("", args...); r.code != cmd.ExitUsage || !strings.Contains(r.stderr, "usage: paddockctl") {
			t.Errorf("%q: %+v", args, r)
		}
	}
}

func TestWhoamiAndHeaders(t *testing.T) {
	api, pc := setup(t, emptyPlan)
	r := pc("", "whoami")
	if r.code != 0 || r.stdout != "organization: acme\nrole: org_admin\ntoken: ci\nexpires_at: 2027-01-01T00:00:00Z\n" {
		t.Fatalf("whoami: %+v", r)
	}
	if api.headers.Get("User-Agent") != "paddockctl/1.2.3" || api.headers.Get("Accept") != "application/json" ||
		api.headers.Get("X-Paddock-CSRF") != "" {
		t.Fatalf("headers %v", api.headers)
	}
	r = pc("", "whoami", "-o", "json")
	var out map[string]string
	if err := json.Unmarshal([]byte(r.stdout), &out); err != nil || out["token"] != "ci" || out["organization"] != "acme" ||
		strings.Contains(r.stdout, secret) {
		t.Fatalf("whoami json: %+v", r)
	}
}

func TestGetConfig(t *testing.T) {
	_, pc := setup(t, emptyPlan)
	r := pc("", "get", "config")
	want := "api_version: \"paddock/v1\"\nkind: \"OrganizationConfig\"\ndevice_groups:\n  - name: \"g\"\n    description: \"\"\n"
	if r.code != 0 || r.stdout != want {
		t.Fatalf("get config:\n%s\n%+v", r.stdout, r)
	}
	if r := pc("", "get", "config", "--output", "json"); r.code != 0 || !strings.HasPrefix(r.stdout, `{"api_version"`) {
		t.Fatalf("get config json: %+v", r)
	}
}

func TestApply(t *testing.T) {
	doc := "api_version: paddock/v1\nkind: OrganizationConfig\n"
	dir := t.TempDir()
	file := filepath.Join(dir, "paddock.yml")
	if err := os.WriteFile(file, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}

	api, pc := setup(t, createPlan)
	r := pc("", "apply", "-f", file, "--dry-run")
	if r.code != 0 || r.stdout != "+ managed_files /etc/motd\nPlan: 1 to create, 0 to update, 0 to delete\n" || len(api.puts) != 1 || api.puts[0] != "dry_run=true" {
		t.Fatalf("dry run: %+v puts %v", r, api.puts)
	}
	if string(api.lastBody) != `{"api_version":"paddock/v1","kind":"OrganizationConfig"}` {
		t.Fatalf("the YAML was not sent as JSON: %s", api.lastBody)
	}
	r = pc(doc, "apply", "-f", "-")
	if r.code != 0 || !strings.HasSuffix(r.stdout, "Applied change set 0193f7a2-6c1e-7cc1-9d1e-6a4f0f6e8a10\n") || len(api.puts) != 3 ||
		api.puts[2] != "expected_plan="+planSHA {
		t.Fatalf("apply: %+v puts %v", r, api.puts)
	}

	api, pc = setup(t, deletePlan)
	r = pc("", "apply", "-f", file)
	if r.code != cmd.ExitRefused || !strings.Contains(r.stderr, "plan deletes 1 resources; re-run with --yes") || len(api.puts) != 1 ||
		!strings.Contains(r.stdout, "- package_holds firefox\n~ settings.login hello_enabled: false -> true\n") {
		t.Fatalf("deletion without --yes: %+v puts %v", r, api.puts)
	}
	if r = pc("", "apply", "-f", file, "--yes", "-o", "json"); r.code != 0 || len(api.puts) != 3 || !strings.Contains(r.stdout, `"change_set_id"`) {
		t.Fatalf("deletion with --yes: %+v", r)
	}

	// The configuration changed between the dry run and the apply: nothing is applied, exit 3 (PDK-013).
	api, pc = setup(t, createPlan)
	api.changed = true
	if r = pc("", "apply", "-f", file); r.code != cmd.ExitRefused || !strings.Contains(r.stderr, "the configuration changed") ||
		strings.Contains(r.stdout, "Applied change set") {
		t.Fatalf("changed plan: %+v", r)
	}

	_, pc = setup(t, emptyPlan)
	if r = pc("", "apply", "-f", file); r.code != 0 || !strings.HasSuffix(r.stdout, "No changes\n") {
		t.Fatalf("empty plan: %+v", r)
	}
	if r = pc("", "apply", "-f", filepath.Join(dir, "missing.yml")); r.code != cmd.ExitUsage {
		t.Fatalf("missing file: %+v", r)
	}
	if r = pc("a: [unclosed", "apply", "-f", "-"); r.code != cmd.ExitUsage {
		t.Fatalf("bad YAML: %+v", r)
	}
}

func TestErrorsAndExitCodes(t *testing.T) {
	_, pc := setup(t, emptyPlan)
	dir := t.TempDir()
	wrong := filepath.Join(dir, "wrong")
	if err := os.WriteFile(wrong, []byte("pdk_wrong"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := pc("", "whoami", "--token-file", wrong)
	if r.code != cmd.ExitError || r.stderr != "error: unauthenticated (request req-1)\n" {
		t.Fatalf("wrong secret: %+v", r)
	}
	open := filepath.Join(dir, "open")
	if err := os.WriteFile(open, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o644); err != nil {
		t.Fatal(err)
	}
	if r := pc("", "whoami", "--token-file", open); r.code != cmd.ExitUsage || !strings.Contains(r.stderr, "readable by others") ||
		strings.Contains(r.stderr, secret) {
		t.Fatalf("0644 token file: %+v", r)
	}
	if r := pc("", "whoami", "--url", "http://127.0.0.1:8443"); r.code != cmd.ExitUsage ||
		!strings.Contains(r.stderr, "must start with https://") {
		t.Fatalf("http URL: %+v", r)
	}
	if r := pc("", "whoami", "--url", "https://127.0.0.1:1"); r.code != cmd.ExitError {
		t.Fatalf("unreachable server: %+v", r)
	}
	if r := pc("", "whoami", "--config", filepath.Join(dir, "none.yaml")); r.code != cmd.ExitUsage {
		t.Fatalf("missing --config: %+v", r)
	}
}

func TestDevicesList(t *testing.T) {
	_, pc := setup(t, emptyPlan)
	r := pc("", "devices", "list", "--page-size", "10", "--sort", "-hostname", "-q", "h", "--state", "active", "--state", "pending", "-o", "json")
	var page map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &page); err != nil || r.code != 0 || page["page_size"] != float64(10) {
		t.Fatalf("devices json: %+v", r)
	}
	if q := page["q"].(string); q != "page_size=10&q=h&sort=-hostname&state=active&state=pending" {
		t.Fatalf("query %s", q)
	}
	r = pc("", "devices", "list")
	if r.code != 0 || !strings.Contains(r.stdout, "h1") || !strings.HasSuffix(r.stdout, "page 1 of 1 (total 1)\n") {
		t.Fatalf("devices table: %+v", r)
	}
}
