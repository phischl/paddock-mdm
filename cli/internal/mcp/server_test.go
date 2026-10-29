package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/phischl/paddock-mdm/cli/internal/client"
	"github.com/phischl/paddock-mdm/cli/internal/mcp/mcptest"
	"github.com/phischl/paddock-mdm/pkg/mcpcatalog"
)

// syncBuffer is the server's stderr; the SDK may log from several goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type harness struct {
	f    *mcptest.Fake
	srv  *Server
	cs   *sdk.ClientSession
	path string
	errw *syncBuffer
}

// start signs a session in at the fake (expiring after ttl), registers the tools and connects an SDK client over the
// in-memory transports.
func start(t *testing.T, f *mcptest.Fake, ttl time.Duration) *harness {
	t.Helper()
	ctx := t.Context()
	c, err := client.New(f.Srv.URL, "", f.CAFile, "1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	acc, ref := f.Issue()
	s := SessionFile{APIURL: f.Srv.URL, Issuer: f.Srv.URL + "/idp/", ClientID: "paddock-mcp", Role: RoleOrganization,
		AccessToken: acc, RefreshToken: ref, ExpiresAt: time.Now().Add(ttl)}
	path := filepath.Join(t.TempDir(), "state", "paddockctl", "mcp-session.json")
	if err := SaveSession(path, s); err != nil {
		t.Fatal(err)
	}
	h := &harness{f: f, path: path, errw: &syncBuffer{}}
	h.srv = New(c, s, path, "1.2.3", h.errw)
	if err := h.srv.Register(ctx); err != nil {
		t.Fatalf("register: %v", err)
	}
	st, ct := sdk.NewInMemoryTransports()
	ss, err := h.srv.srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	h.cs, err = sdk.NewClient(&sdk.Implementation{Name: "test-client", Version: "9.9"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.cs.Close() })
	t.Cleanup(func() { assertNoTokens(t, "stderr", h.errw.String()) })
	return h
}

func assertNoTokens(t *testing.T, where, s string) {
	t.Helper()
	for _, p := range []string{mcptest.AccessPrefix, mcptest.RefreshPrefix, mcptest.IDPrefix} {
		if strings.Contains(s, p) {
			t.Errorf("%s contains a token (%s…): %s", where, p, s)
		}
	}
}

// call invokes a tool and decodes the wrapper.
func (h *harness) call(t *testing.T, name string, args any) (*sdk.CallToolResult, map[string]any) {
	t.Helper()
	res, err := h.cs.CallTool(t.Context(), &sdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var w map[string]any
	raw, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatalf("structured content: %v", err)
	}
	var text map[string]any
	if len(res.Content) != 1 || json.Unmarshal([]byte(res.Content[0].(*sdk.TextContent).Text), &text) != nil ||
		!reflect.DeepEqual(text, w) {
		t.Fatalf("the text block differs from the structured content: %+v", res.Content)
	}
	assertNoTokens(t, "result", string(raw))
	if w["notice"] != mcpcatalog.Notice {
		t.Fatalf("notice %v", w["notice"])
	}
	return res, w
}

func errCode(w map[string]any) string {
	e, _ := w["error"].(map[string]any)
	s, _ := e["code"].(string)
	return s
}

func TestInitialize(t *testing.T) {
	h := start(t, mcptest.New(t), 30*time.Minute)
	init := h.cs.InitializeResult()
	if init.ServerInfo.Name != "paddockctl" || init.ServerInfo.Version != "1.2.3" || init.Instructions != mcpcatalog.Instructions {
		t.Fatalf("initialize %+v", init)
	}
	caps, _ := json.Marshal(init.Capabilities)
	var m map[string]any
	_ = json.Unmarshal(caps, &m)
	if len(m) != 1 || m["tools"] == nil {
		t.Fatalf("capabilities %s, want tools only", caps)
	}
}

func TestToolsListFollowsAccess(t *testing.T) {
	f := mcptest.New(t)
	f.Allowed = []string{"listDevices", "deleteDeviceGroup", "lockDevice", "noSuchTool"}
	h := start(t, f, 30*time.Minute)
	res, err := h.cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
		if tool.Title == "" || tool.Description == "" || tool.InputSchema == nil || tool.Annotations == nil ||
			tool.Annotations.OpenWorldHint == nil || *tool.Annotations.OpenWorldHint {
			t.Errorf("%s incomplete: %+v", tool.Name, tool)
		}
		a := tool.Annotations
		switch tool.Name {
		case "listDevices":
			if !a.ReadOnlyHint || *a.DestructiveHint || !a.IdempotentHint || tool.Title != "List devices" {
				t.Errorf("listDevices %+v %q", a, tool.Title)
			}
		case "deleteDeviceGroup":
			if a.ReadOnlyHint || !*a.DestructiveHint || !a.IdempotentHint {
				t.Errorf("deleteDeviceGroup %+v", a)
			}
		}
	}
	// lockDevice needs a step-up and is never exposed, even if the api listed it.
	if !slices.Equal(names, []string{"deleteDeviceGroup", "listDevices"}) {
		t.Fatalf("tools %v", names)
	}
}

func TestCallSuccessAndHeaders(t *testing.T) {
	h := start(t, mcptest.New(t), 30*time.Minute)
	res, w := h.call(t, "listDevices", map[string]any{"page_size": 10, "state": []string{"active", "pending"}})
	data, _ := w["data"].(map[string]any)
	if res.IsError || w["status"] != float64(200) || data["items"] == nil {
		t.Fatalf("listDevices %+v", w)
	}
	if data["query"] != "page_size=10&state=active&state=pending" {
		t.Fatalf("query %v", data["query"])
	}
	hdr := h.f.Header("GET /api/v1/devices")
	if hdr.Get("Authorization") != "Bearer "+h.srv.Session().AccessToken || hdr.Get("X-Paddock-MCP-Client") != "test-client/9.9" ||
		hdr.Get("X-Paddock-CSRF") != "" {
		t.Fatalf("headers %v", hdr)
	}
}

func TestCallProblems(t *testing.T) {
	h := start(t, mcptest.New(t), 30*time.Minute)
	res, w := h.call(t, "getDevice", map[string]any{"id": "0193f7a2-6c1e-7cc1-9d1e-6a4f0f6e8a10"})
	e, _ := w["error"].(map[string]any)
	if !res.IsError || e["code"] != "not_found" || e["request_id"] != "req-not_found" || e["portal_path"] != nil {
		t.Fatalf("getDevice %+v", w)
	}
	res, w = h.call(t, "createPermissionProfile", map[string]any{"body": map[string]any{"name": "root", "class": "full"}})
	e, _ = w["error"].(map[string]any)
	if !res.IsError || e["code"] != "step_up_required" || e["portal_path"] != "/permission-profiles" || w["status"] != float64(403) {
		t.Fatalf("createPermissionProfile %+v", w)
	}
}

func TestProtocolRefusals(t *testing.T) {
	h := start(t, mcptest.New(t), 30*time.Minute)
	for _, c := range []struct {
		name string
		args any
	}{
		{"lockDevice", map[string]any{"id": "x"}},
		{"listDevices", map[string]any{"page_size": "ten"}},
		{"getDevice", map[string]any{}},
		{"createPermissionProfile", map[string]any{"body": map[string]any{"name": "x", "class": "full", "extra": 1}}},
		{"listDevices", map[string]any{"page_size": 10, "not_in_schema": "x"}},
		{"getDevice", map[string]any{"id": ".."}},
		{"getDevice", map[string]any{"id": "."}},
		{"getDevice", map[string]any{"id": ""}},
	} {
		_, err := h.cs.CallTool(t.Context(), &sdk.CallToolParams{Name: c.name, Arguments: c.args})
		var we *jsonrpc.Error
		if !errors.As(err, &we) || we.Code != jsonrpc.CodeInvalidParams {
			t.Errorf("%s %v: %v, want -32602", c.name, c.args, err)
		}
	}
	if calls := h.f.CallList(); slices.Contains(calls, "GET /api/v1/devices") || slices.ContainsFunc(calls, func(c string) bool {
		return strings.HasPrefix(c, "GET /api/v1/devices/") || strings.HasPrefix(c, "GET /api/v1/approve")
	}) || slices.Contains(calls, "POST /api/v1/permission-profiles") {
		t.Fatalf("a refused call reached the api: %v", calls)
	}
}

func TestRefreshOn401AndBeforeExpiry(t *testing.T) {
	f := mcptest.New(t)
	h := start(t, f, 30*time.Minute)
	old := h.srv.Session()
	f.Set(func(f *mcptest.Fake) { f.Reject401, f.Calls = 1, nil })
	if res, _ := h.call(t, "listDevices", nil); res.IsError {
		t.Fatal("the retry after the refresh failed")
	}
	want := []string{"GET /api/v1/devices", "GET /api/auth/mcp/config", "POST /idp/token", "POST /api/auth/mcp/session", "GET /api/v1/devices"}
	if calls := f.CallList(); !slices.Equal(calls, want) {
		t.Fatalf("calls %v, want %v", calls, want)
	}
	saved, err := LoadSession(h.path)
	if err != nil || saved.AccessToken == old.AccessToken || saved.RefreshToken == old.RefreshToken || saved.Role != RoleOrganization {
		t.Fatalf("session file not renewed: %v", err)
	}
	if last := f.Sessions[len(f.Sessions)-1]; last["role"] != RoleOrganization || last["id_token"] == "" {
		t.Fatalf("renewal body %v", last)
	}

	f.Set(func(f *mcptest.Fake) { f.Reject401 = 2 })
	if res, w := h.call(t, "listDevices", nil); !res.IsError || errCode(w) != codeLoginRequired || w["status"] != float64(401) {
		t.Fatalf("second 401: %+v", w)
	}
}

func TestRefreshBeforeExpiry(t *testing.T) {
	f := mcptest.New(t)
	h := start(t, f, 90*time.Second)
	if !slices.Contains(f.CallList(), "POST /idp/token") {
		t.Fatalf("a token expiring within 2 minutes was not renewed before the first call: %v", f.CallList())
	}
	if res, _ := h.call(t, "listDevices", nil); res.IsError {
		t.Fatal("call after the renewal failed")
	}
}

func TestRefreshRefusedKeepsServing(t *testing.T) {
	f := mcptest.New(t)
	h := start(t, f, 30*time.Minute)
	f.Revoke(h.srv.Session().AccessToken)
	f.Set(func(f *mcptest.Fake) { f.RefuseRefresh = true })
	for range 2 {
		if res, w := h.call(t, "listDevices", nil); !res.IsError || errCode(w) != codeLoginRequired {
			t.Fatalf("refused refresh: %+v", w)
		}
	}
	if n := strings.Count(strings.Join(f.CallList(), "\n"), "POST /idp/token"); n != 1 {
		t.Fatalf("the refused refresh was retried %d times", n)
	}
	if _, err := h.cs.ListTools(t.Context(), nil); err != nil {
		t.Fatalf("the server stopped: %v", err)
	}
	// A new login written by paddockctl mcp login heals the running server.
	acc, ref := f.Issue()
	s := h.srv.Session()
	s.AccessToken, s.RefreshToken, s.ExpiresAt = acc, ref, time.Now().Add(30*time.Minute)
	if err := SaveSession(h.path, s); err != nil {
		t.Fatal(err)
	}
	if res, _ := h.call(t, "listDevices", nil); res.IsError {
		t.Fatal("the new login was not picked up")
	}
}

func TestSessionRenewalRefused(t *testing.T) {
	f := mcptest.New(t)
	h := start(t, f, 30*time.Minute)
	f.Revoke(h.srv.Session().AccessToken)
	f.Set(func(f *mcptest.Fake) { f.SessionStatus, f.SessionProblem = 401, "mcp_login_required" })
	if res, w := h.call(t, "listDevices", nil); !res.IsError || errCode(w) != codeLoginRequired {
		t.Fatalf("renewal refused: %+v", w)
	}
	saved, _ := LoadSession(h.path)
	if saved.RefreshToken == "" || saved.AccessToken != "" {
		t.Fatalf("the rotated refresh token must be kept without an unaccepted access token")
	}
}

func TestOversizedUnreachableAndRemovedTool(t *testing.T) {
	f := mcptest.New(t)
	h := start(t, f, 30*time.Minute)
	f.Set(func(f *mcptest.Fake) { f.BigBody = maxToolResponse + 10 })
	if res, w := h.call(t, "listAuditEvents", nil); !res.IsError || errCode(w) != codeTooLarge {
		t.Fatalf("oversized: %+v", w)
	}

	f.Set(func(f *mcptest.Fake) { f.Allowed = []string{"listDevices"} })
	h.srv.mu.Lock()
	h.srv.now = func() time.Time { return time.Now().Add(accessTTL + time.Second) }
	h.srv.mu.Unlock()
	if res, w := h.call(t, "getDevice", map[string]any{"id": "x"}); !res.IsError || errCode(w) != codeToolNotAllowed {
		t.Fatalf("removed tool: %+v", w)
	}

	f.Srv.Close()
	if res, w := h.call(t, "listDevices", nil); !res.IsError || errCode(w) != codeUnreachable || w["status"] != nil {
		t.Fatalf("unreachable: %+v", w)
	}
}

func TestEveryExposedToolMaps(t *testing.T) {
	for _, ct := range mcpcatalog.Exposed() {
		t.Run(ct.Name, func(t *testing.T) {
			var schema jsonschema.Schema
			if err := json.Unmarshal(ct.InputSchema, &schema); err != nil {
				t.Fatalf("schema: %v", err)
			}
			tool, err := toolFor(ct)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := resolve(tool); err != nil {
				t.Fatal(err)
			}
			if tool.Title == "" || tool.Annotations.ReadOnlyHint != (ct.Class == mcpcatalog.ClassRead) || ct.StepUp {
				t.Fatalf("tool %+v", tool)
			}
		})
	}
}

func TestPortalPath(t *testing.T) {
	for _, c := range []struct{ method, path, want string }{
		{"POST", "/api/v1/devices/{id}/lock", "/devices/{id}"},
		{"POST", "/api/platform/v1/agent-releases/1.2.3/rollout", "/platform/agent-releases/1.2.3"},
		{"POST", "/api/v1/permission-profiles", "/permission-profiles"},
		{"PUT", "/api/v1/settings/mcp", "/settings/mcp"},
		{"DELETE", "/api/v1/device-groups/7", "/device-groups/7"},
		{"GET", "/healthz", ""},
	} {
		if got := portalPath(c.method, c.path); got != c.want {
			t.Errorf("portalPath(%s %s) = %q, want %q", c.method, c.path, got, c.want)
		}
	}
}

func TestSaveSessionModesAndReplace(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "paddockctl")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "mcp-session.json")
	for i, tok := range []string{"one", "two"} {
		s := SessionFile{APIURL: "https://a", RefreshToken: tok, ExpiresAt: time.Unix(int64(i), 0).UTC()}
		if err := SaveSession(path, s); err != nil {
			t.Fatal(err)
		}
		got, err := LoadSession(path)
		if err != nil || got != s {
			t.Fatalf("load %+v %v", got, err)
		}
	}
	fi, _ := os.Stat(path)
	di, _ := os.Stat(dir)
	if fi.Mode().Perm() != 0o600 || di.Mode().Perm() != 0o700 {
		t.Fatalf("modes file %v dir %v", fi.Mode(), di.Mode())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("temporary files left: %v", entries)
	}
	if _, err := LoadSession(filepath.Join(dir, "none.json")); !errors.Is(err, ErrNoSession) {
		t.Fatalf("missing: %v", err)
	}
}

func TestClientHeader(t *testing.T) {
	if got := clientHeader(nil); got != "unknown/0" {
		t.Fatal(got)
	}
	if got := clientHeader(&sdk.Implementation{Name: "claude\ncode", Version: strings.Repeat("9", 80)}); len(got) != 64 ||
		strings.ContainsAny(got, "\n") {
		t.Fatalf("%q", got)
	}
}

func TestRefreshOutageIsTransient(t *testing.T) {
	for _, status := range []int{503, 502, 429} {
		f := mcptest.New(t)
		h := start(t, f, 30*time.Minute)
		f.Revoke(h.srv.Session().AccessToken)
		f.Set(func(f *mcptest.Fake) { f.RefreshOutages = []int{status} })
		if res, w := h.call(t, "listDevices", nil); !res.IsError || errCode(w) != codeUnreachable {
			t.Fatalf("%d from the token endpoint: %+v", status, w)
		}
		if res, w := h.call(t, "listDevices", nil); res.IsError {
			t.Fatalf("the renewal after a %d outage failed: %+v", status, w)
		}
	}
}

func TestLogoutWhileServing(t *testing.T) {
	f := mcptest.New(t)
	h := start(t, f, 30*time.Minute)
	f.Revoke(h.srv.Session().AccessToken)
	if err := RemoveSession(h.path); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if res, w := h.call(t, "listDevices", nil); !res.IsError || errCode(w) != codeLoginRequired {
			t.Fatalf("after logout: %+v", w)
		}
	}
	if _, err := os.Stat(h.path); !os.IsNotExist(err) {
		t.Fatal("the running server wrote the session file back after logout")
	}
	if slices.Contains(f.CallList(), "POST /idp/token") {
		t.Fatal("a signed-out server renewed its session")
	}
}

func TestRenewalWaitsForLockAndKeepsNewerLogin(t *testing.T) {
	f := mcptest.New(t)
	h := start(t, f, 30*time.Minute)
	login := h.srv.Session()
	f.Revoke(login.AccessToken)
	unlock, err := LockSession(t.Context(), h.path)
	if err != nil {
		t.Fatal(err)
	}
	type answer struct {
		res *sdk.CallToolResult
		err error
	}
	done := make(chan answer, 1)
	go func() {
		res, err := h.cs.CallTool(t.Context(), &sdk.CallToolParams{Name: "listDevices"})
		done <- answer{res, err}
	}()
	select {
	case a := <-done:
		t.Fatalf("the renewal did not wait for the session lock: %+v", a)
	case <-time.After(300 * time.Millisecond):
	}
	// Another process logs in (for example with --platform) while the renewal waits.
	acc, ref := f.Issue()
	login.AccessToken, login.RefreshToken, login.Role, login.ExpiresAt = acc, ref, RolePlatform, time.Now().Add(30*time.Minute)
	if err := SaveSession(h.path, login); err != nil {
		t.Fatal(err)
	}
	unlock()
	a := <-done
	if a.err != nil || a.res.IsError {
		t.Fatalf("call after the lock: %+v", a)
	}
	if slices.Contains(f.CallList(), "POST /idp/token") {
		t.Fatal("the old refresh token was spent although a newer login was on disk")
	}
	if saved, _ := LoadSession(h.path); saved.RefreshToken != ref || saved.Role != RolePlatform {
		t.Fatalf("the newer login was overwritten: %+v", saved.Role)
	}
}

func TestForeignLoginOnDiskIsNeverOverwritten(t *testing.T) {
	for name, change := range map[string]func(*SessionFile){
		"api_url":   func(s *SessionFile) { s.APIURL = "https://other.example" },
		"issuer":    func(s *SessionFile) { s.Issuer = "https://auth.other.example/application/o/paddock-mcp/" },
		"client_id": func(s *SessionFile) { s.ClientID = "other-client" },
	} {
		t.Run(name, func(t *testing.T) {
			f := mcptest.New(t)
			h := start(t, f, 30*time.Minute)
			f.Revoke(h.srv.Session().AccessToken)
			foreign := SessionFile{APIURL: f.Srv.URL, Issuer: f.Srv.URL + "/idp/", ClientID: "paddock-mcp", Role: RoleOrganization,
				AccessToken: "foreign-access", RefreshToken: "foreign-refresh", ExpiresAt: time.Now().Add(30 * time.Minute).UTC().Truncate(time.Second)}
			change(&foreign)
			if err := SaveSession(h.path, foreign); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if res, w := h.call(t, "listDevices", nil); !res.IsError || errCode(w) != codeLoginRequired {
					t.Fatalf("foreign login: %+v", w)
				}
			}
			if saved, err := LoadSession(h.path); err != nil || saved != foreign {
				t.Fatalf("the foreign login was overwritten: %+v %v", saved, err)
			}
			if slices.Contains(f.CallList(), "POST /idp/token") {
				t.Fatal("the server renewed after a foreign login appeared")
			}
		})
	}
}

func TestLockWaitHonoursCancellation(t *testing.T) {
	f := mcptest.New(t)
	h := start(t, f, 30*time.Minute)
	unlock, err := LockSession(t.Context(), h.path)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := h.srv.token(ctx, "", "test/1")
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, errUnreachable) {
			t.Fatalf("cancelled lock wait: %v, want unreachable", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the lock wait ignored the cancelled context")
	}
}

func TestFailedSaveDoesNotReadoptSpentToken(t *testing.T) {
	f := mcptest.New(t)
	h := start(t, f, 30*time.Minute)
	f.Revoke(h.srv.Session().AccessToken)
	failed := false
	h.srv.mu.Lock()
	h.srv.save = func(path string, s SessionFile) error {
		if !failed {
			failed = true
			return errors.New("disk full")
		}
		return SaveSession(path, s)
	}
	h.srv.mu.Unlock()
	if res, w := h.call(t, "listDevices", nil); res.IsError {
		t.Fatalf("renewal with a failed save: %+v", w)
	}
	// The file still holds the spent refresh token; the next renewal must use the one in memory.
	f.Revoke(h.srv.Session().AccessToken)
	if res, w := h.call(t, "listDevices", nil); res.IsError {
		t.Fatalf("the spent refresh token on disk was adopted again: %+v", w)
	}
	if saved, _ := LoadSession(h.path); saved.RefreshToken != h.srv.Session().RefreshToken {
		t.Fatal("the second renewal was not saved")
	}
}
