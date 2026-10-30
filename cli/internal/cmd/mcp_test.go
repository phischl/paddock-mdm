package cmd_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/cli/internal/cmd"
	"github.com/phischl/paddock-mdm/cli/internal/mcp"
	"github.com/phischl/paddock-mdm/cli/internal/mcp/mcptest"
)

type mcpEnv struct {
	f     *mcptest.Fake
	state string
	path  string
}

func newMCPEnv(t *testing.T) *mcpEnv {
	t.Helper()
	state := t.TempDir()
	return &mcpEnv{f: mcptest.New(t), state: state, path: filepath.Join(state, "paddockctl", "mcp-session.json")}
}

func (m *mcpEnv) run(t *testing.T, stdin string, args ...string) run {
	t.Helper()
	env := map[string]string{"PADDOCK_URL": m.f.Srv.URL, "PADDOCK_CA_FILE": m.f.CAFile, "XDG_STATE_HOME": m.state,
		"HOME": m.state, "PADDOCK_TOKEN_FILE": filepath.Join(m.state, "no-such-token")}
	var out, errOut bytes.Buffer
	code := cmd.Main(context.Background(), cmd.Env{Args: args, Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errOut,
		Getenv: func(k string) string { return env[k] }, Version: "1.2.3"})
	r := run{code, out.String(), errOut.String()}
	for _, p := range []string{mcptest.AccessPrefix, mcptest.RefreshPrefix, mcptest.IDPrefix} {
		if strings.Contains(r.stdout+r.stderr, p) {
			t.Errorf("%q printed a token: %+v", args, r)
		}
	}
	return r
}

// signIn writes a session file for a pair the fake accepts, expiring after ttl.
func (m *mcpEnv) signIn(t *testing.T, ttl time.Duration) mcp.SessionFile {
	t.Helper()
	acc, ref := m.f.Issue()
	s := mcp.SessionFile{APIURL: m.f.Srv.URL, Issuer: m.f.Srv.URL + "/idp/", ClientID: "paddock-mcp", Role: mcp.RoleOrganization,
		AccessToken: acc, RefreshToken: ref, ExpiresAt: time.Now().Add(ttl)}
	if err := mcp.SaveSession(m.path, s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestMCPLogin(t *testing.T) {
	m := newMCPEnv(t)
	m.f.DeviceAnswers = []string{"authorization_pending", "slow_down"}
	r := m.run(t, "", "mcp", "login", "--no-browser")
	if r.code != 0 || r.stdout != "Signed in as alice (org_admin, acme)\n" ||
		!strings.Contains(r.stderr, "Open "+m.f.Srv.URL+"/device?code=ABCD-EFGH and confirm the code ABCD-EFGH") {
		t.Fatalf("login: %+v", r)
	}
	if polls := strings.Count(strings.Join(m.f.CallList(), "\n"), "POST /idp/token"); polls != 3 {
		t.Fatalf("polled %d times, want 3 (pending, slow_down, success)", polls)
	}
	if body := m.f.Sessions[0]; body["role"] != "organization" || !strings.HasPrefix(body["id_token"], mcptest.IDPrefix) ||
		!strings.HasPrefix(body["access_token"], mcptest.AccessPrefix) {
		t.Fatalf("session body %v", body)
	}
	if h := m.f.Header("POST /api/auth/mcp/session"); h.Get("X-Paddock-MCP-Client") != "paddockctl/1.2.3" {
		t.Fatalf("session headers %v", h)
	}
	s, err := mcp.LoadSession(m.path)
	if err != nil || s.Role != "organization" || s.ClientID != "paddock-mcp" || s.APIURL != m.f.Srv.URL ||
		time.Until(s.ExpiresAt) < 29*time.Minute {
		t.Fatalf("session file %+v %v", s, err)
	}
	fi, _ := os.Stat(m.path)
	di, _ := os.Stat(filepath.Dir(m.path))
	if fi.Mode().Perm() != 0o600 || di.Mode().Perm() != 0o700 {
		t.Fatalf("modes file %v dir %v", fi.Mode(), di.Mode())
	}
}

func TestMCPLoginRoleAndRefusals(t *testing.T) {
	m := newMCPEnv(t)
	m.f.Platform = true
	if r := m.run(t, "", "mcp", "login", "--no-browser", "--platform"); r.code != 0 ||
		r.stdout != "Signed in as Platform Admin (platform_admin, platform)\n" || m.f.Sessions[0]["role"] != "platform" {
		t.Fatalf("platform login: %+v", r)
	}
	if s, _ := mcp.LoadSession(m.path); s.Role != "platform" {
		t.Fatalf("role not stored: %+v", s.Role)
	}

	m = newMCPEnv(t)
	if r := m.run(t, "", "mcp", "login", "--no-browser", "--platform"); r.code != cmd.ExitError ||
		!strings.Contains(r.stderr, "role_not_granted") {
		t.Fatalf("platform for an organization identity: %+v", r)
	}
	if _, err := os.Stat(m.path); !os.IsNotExist(err) {
		t.Fatal("a refused login wrote a session file")
	}

	m = newMCPEnv(t)
	m.f.SessionStatus, m.f.SessionProblem = 403, "no_role"
	if r := m.run(t, "", "mcp", "login", "--no-browser"); r.code != cmd.ExitError || !strings.Contains(r.stderr, "sign-in refused: no_role") {
		t.Fatalf("denied session: %+v", r)
	}

	m = newMCPEnv(t)
	m.f.DeviceExpiresIn = 2
	m.f.DeviceAnswers = slices.Repeat([]string{"authorization_pending"}, 10)
	if r := m.run(t, "", "mcp", "login", "--no-browser"); r.code != cmd.ExitError || !strings.HasSuffix(r.stderr, "\nerror: login timed out\n") {
		t.Fatalf("expired device code: %+v", r)
	}
}

func TestMCPTools(t *testing.T) {
	m := newMCPEnv(t)
	if r := m.run(t, "", "mcp", "tools"); r.code != cmd.ExitUsage || !strings.Contains(r.stderr, "not signed in: run paddockctl mcp login") {
		t.Fatalf("no session: %+v", r)
	}
	if r := m.run(t, "", "mcp"); r.code != cmd.ExitUsage || !strings.Contains(r.stderr, "not signed in: run paddockctl mcp login") {
		t.Fatalf("no session (server): %+v", r)
	}

	// The session's tokens are never sent to another api than the one they were issued for.
	if err := mcp.SaveSession(m.path, mcp.SessionFile{APIURL: "https://other.example", RefreshToken: "r"}); err != nil {
		t.Fatal(err)
	}
	if r := m.run(t, "", "mcp", "tools"); r.code != cmd.ExitUsage || !strings.Contains(r.stderr, "belongs to https://other.example") ||
		len(m.f.CallList()) != 0 {
		t.Fatalf("foreign session: %+v", r)
	}

	old := m.signIn(t, time.Minute)
	m.f.Allowed = []string{"listDevices", "deleteDeviceGroup"}
	r := m.run(t, "", "mcp", "tools")
	if r.code != 0 || !strings.Contains(r.stdout, "deleteDeviceGroup  write  true") || !strings.Contains(r.stdout, "listDevices        read   false") {
		t.Fatalf("tools: %+v", r)
	}
	calls := m.f.CallList()
	if i, j := slices.Index(calls, "POST /api/auth/mcp/session"), slices.Index(calls, "GET /api/v1/mcp/access"); i < 0 || j < i {
		t.Fatalf("the session was not renewed before the access call: %v", calls)
	}
	if s, _ := mcp.LoadSession(m.path); s.RefreshToken == old.RefreshToken || time.Until(s.ExpiresAt) < 29*time.Minute {
		t.Fatal("the renewed session was not saved")
	}
	r = m.run(t, "", "mcp", "tools", "-o", "json")
	var list []map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &list); err != nil || len(list) != 2 || list[0]["destructive"] != true {
		t.Fatalf("tools json: %+v", r)
	}

	m.signIn(t, time.Minute)
	m.f.RefuseRefresh = true
	if r := m.run(t, "", "mcp", "tools"); r.code != cmd.ExitError || !strings.Contains(r.stderr, "login required") {
		t.Fatalf("unrefreshable: %+v", r)
	}
}

func TestMCPLogout(t *testing.T) {
	m := newMCPEnv(t)
	s := m.signIn(t, 30*time.Minute)
	if r := m.run(t, "", "mcp", "logout"); r.code != 0 || r.stdout != "Signed out\n" || r.stderr != "" {
		t.Fatalf("logout: %+v", r)
	}
	calls := m.f.CallList()
	if !slices.Contains(calls, "POST /api/auth/mcp/logout") || !slices.Contains(calls, "POST /idp/revoke") {
		t.Fatalf("calls %v", calls)
	}
	if form := m.f.Forms["POST /idp/revoke"]; len(form) != 1 || !strings.Contains(form[0], "token="+s.RefreshToken) ||
		!strings.Contains(form[0], "token_type_hint=refresh_token") || !strings.Contains(form[0], "client_id=paddock-mcp") {
		t.Fatalf("revocation form %v", form)
	}
	if _, err := os.Stat(m.path); !os.IsNotExist(err) {
		t.Fatal("the session file is still there")
	}

	expired := m.signIn(t, 30*time.Minute)
	m.f.Revoke(expired.AccessToken)
	if r := m.run(t, "", "mcp", "logout"); r.code != 0 || !strings.Contains(r.stderr, "access token had expired") ||
		len(m.f.Forms["POST /idp/revoke"]) != 2 {
		t.Fatalf("logout with an expired access token: %+v", r)
	}

	m.signIn(t, 30*time.Minute)
	m.f.Srv.Close()
	if r := m.run(t, "", "mcp", "logout"); r.code != 0 || !strings.Contains(r.stderr, "warning:") {
		t.Fatalf("logout with the api down: %+v", r)
	}
	if _, err := os.Stat(m.path); !os.IsNotExist(err) {
		t.Fatal("the session file is still there")
	}
}

func TestMCPServeExitsOnStdinClose(t *testing.T) {
	m := newMCPEnv(t)
	m.signIn(t, 30*time.Minute)
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	env := map[string]string{"PADDOCK_URL": m.f.Srv.URL, "PADDOCK_CA_FILE": m.f.CAFile, "XDG_STATE_HOME": m.state}
	var errOut bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- cmd.Main(context.Background(), cmd.Env{Args: []string{"mcp"}, Stdin: inR, Stdout: outW, Stderr: &errOut,
			Getenv: func(k string) string { return env[k] }, Version: "1.2.3"})
	}()
	_, _ = io.WriteString(inW, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18",`+
		`"capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`+"\n")
	line, err := bufio.NewReader(outR).ReadString('\n')
	if err != nil || !strings.Contains(line, `"serverInfo":{"name":"paddockctl","version":"1.2.3"}`) ||
		!strings.Contains(line, `"capabilities":{"tools":{}}`) {
		t.Fatalf("initialize answer %q %v", line, err)
	}
	_ = inW.Close()
	go func() { _, _ = io.Copy(io.Discard, outR) }()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit %d: %s", code, errOut.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the server did not exit when stdin closed")
	}
}

func TestMCPLogoutRevokesTheCurrentTokens(t *testing.T) {
	m := newMCPEnv(t)
	old := m.signIn(t, 30*time.Minute)
	unlock, err := mcp.LockSession(t.Context(), m.path)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan run, 1)
	go func() { done <- m.run(t, "", "mcp", "logout") }()
	time.Sleep(200 * time.Millisecond)
	// A running paddockctl mcp renews while logout waits for the lock.
	rotated := m.signIn(t, 30*time.Minute)
	unlock()
	r := <-done
	if r.code != 0 {
		t.Fatalf("logout: %+v", r)
	}
	revoked := m.f.RevokedTokens()
	if !slices.Equal(revoked, []string{rotated.RefreshToken}) || slices.Contains(revoked, old.RefreshToken) {
		t.Fatalf("revoked %v, want the rotated refresh token only", revoked)
	}
	if h := m.f.Header("POST /api/auth/mcp/logout"); h.Get("Authorization") != "Bearer "+rotated.AccessToken {
		t.Fatal("the api logout did not carry the current access token")
	}
	if _, err := os.Stat(m.path); !os.IsNotExist(err) {
		t.Fatal("the session file is still there")
	}
}
