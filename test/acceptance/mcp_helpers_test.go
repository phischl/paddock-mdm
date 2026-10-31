package acceptance

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/authflow"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// mcpClientID is the public Authentik client of the MCP login (ADR 0044).
const mcpClientID = "paddock-mcp"

// mcpDeviceTokens runs the device authorization grant of `paddockctl mcp login` for a dev user and returns the tokens.
func mcpDeviceTokens(t *testing.T, user string) authflow.Tokens {
	t.Helper()
	ctx := testContext(t, 3*time.Minute)
	hc := authHTTP(t)
	da, err := authflow.StartDeviceScopes(ctx, hc, stack.AuthURL(), mcpClientID, authflow.MCPScopes)
	if err != nil {
		t.Fatalf("device authorization: %v", err)
	}
	secrets, err := stack.SecretsDir()
	if err != nil {
		t.Fatal(err)
	}
	password, err := env.Password(user)
	if err != nil {
		t.Fatal(err)
	}
	totp, err := env.TOTP(user)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authflow.ApproveDevice(ctx, filepath.Join(secrets, "caddy-root.crt"), da, user, password, totp); err != nil {
		t.Fatalf("approve device login of %s: %v", user, err)
	}
	tokens, err := authflow.PollDeviceToken(ctx, hc, stack.AuthURL(), mcpClientID, da, time.Minute)
	if err != nil {
		t.Fatalf("device token of %s: %v", user, err)
	}
	return tokens
}

// mcpSession presents an ID and access token pair to the MCP session call.
func mcpSession(t *testing.T, idToken, accessToken string) env.Response {
	t.Helper()
	res, err := env.Call(testContext(t, time.Minute), authHTTP(t), http.MethodPost, stack.AdminURL()+"/api/auth/mcp/session",
		map[string]string{"id_token": idToken, "access_token": accessToken}, false)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// mcpLogout ends the MCP session of an access token when the case ends.
func mcpLogout(t *testing.T, accessToken string) {
	t.Cleanup(func() {
		req, err := http.NewRequest(http.MethodPost, stack.AdminURL()+"/api/auth/mcp/logout", nil)
		if err != nil {
			return
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)
		if res, err := authHTTP(t).Do(req); err == nil {
			_ = res.Body.Close()
		}
	})
}

// forgedJWT is a canonical compact JWT whose signature no issuer made.
func forgedJWT() string {
	seg := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	return seg(`{"alg":"RS256","typ":"JWT","kid":"a3"}`) + "." + seg(`{"sub":"a3","aud":"paddock-mcp"}`) + "." + seg("a3-signature")
}

// The clientInfo the gates' stdio driver announces; the events of its tool calls carry it as actor.client.
const (
	mcpGateClientName    = "paddock-gate"
	mcpGateClientVersion = "1.0"
	mcpGateClient        = mcpGateClientName + "/" + mcpGateClientVersion
)

// mcpTokenMargin is the lifetime an access token must have left for a direct API call; below it the gate renews the
// session first. The development overlay gives paddock-mcp one-minute access tokens.
const mcpTokenMargin = 20 * time.Second

// mcpLoginPrompt is the line `paddockctl mcp login` prints on stderr before it polls (plan M14 §3.5 item 25).
var mcpLoginPrompt = regexp.MustCompile(`^Open (\S+) and confirm the code (\S+)$`)

// mcpIdentity is an Authentik identity that signs in with `paddockctl mcp login`.
type mcpIdentity struct {
	username, password string
	totp               *authflow.TOTP
	// platform signs in with the platform role (--platform).
	platform bool
}

// mcpDevIdentity is a dev user of the stack (env.Alice, env.PlatformAdmin, …). Its TOTP generator is shared with
// every other sign-in of the user in this run, so its device logins queue for a fresh 30 s step.
func mcpDevIdentity(t *testing.T, user string, platform bool) mcpIdentity {
	t.Helper()
	password, err := env.Password(user)
	if err != nil {
		t.Fatal(err)
	}
	totp, err := env.TOTP(user)
	if err != nil {
		t.Fatal(err)
	}
	return mcpIdentity{username: user, password: password, totp: totp, platform: platform}
}

// mcpTempIdentity is a temporary user of mfaTempUser with its own TOTP authenticator.
func mcpTempIdentity(u *mfaUser) mcpIdentity {
	return mcpIdentity{username: u.username, password: u.password, totp: u.totp}
}

// mcpSessionFile is the session file of `paddockctl mcp login` (plan M14 §6.2).
type mcpSessionFile struct {
	APIURL       string    `json:"api_url"`
	Role         string    `json:"role"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// mcpCLI is one administrator workstation running `paddockctl mcp`: its state directory holds the session file. The
// session is signed out when the test that created the workstation ends.
type mcpCLI struct {
	ctl   paddockctl
	state string
	mu    sync.Mutex
}

func newMCPCLI(t *testing.T) *mcpCLI {
	t.Helper()
	c := &mcpCLI{ctl: newPaddockctl(t), state: t.TempDir()}
	t.Cleanup(func() {
		if _, err := os.Stat(c.sessionPath()); err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, _ = c.exec(ctx, nil, "mcp", "logout")
	})
	return c
}

func (c *mcpCLI) sessionPath() string {
	return filepath.Join(c.state, "paddockctl", "mcp-session.json")
}

// environ is the environment of every paddockctl process of the workstation; extra adds variables.
func (c *mcpCLI) environ(extra []string) []string {
	return append([]string{"PADDOCK_URL=" + stack.AdminURL(), "PADDOCK_CA_FILE=" + c.ctl.caFile, "HOME=" + c.state,
		"XDG_STATE_HOME=" + c.state}, extra...)
}

func (c *mcpCLI) exec(ctx context.Context, extra []string, args ...string) (ctlResult, error) {
	cmd := exec.CommandContext(ctx, c.ctl.bin, args...) //nolint:gosec // the gate's own binary
	cmd.Env = c.environ(extra)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		return ctlResult{code: exit.ExitCode(), stdout: out.String(), stderr: errOut.String()}, nil
	case err != nil:
		return ctlResult{}, fmt.Errorf("paddockctl %s: %w", strings.Join(args, " "), err)
	}
	return ctlResult{stdout: out.String(), stderr: errOut.String()}, nil
}

// run runs paddockctl with the workstation's environment plus extra.
func (c *mcpCLI) run(t *testing.T, extra []string, args ...string) ctlResult {
	t.Helper()
	r, err := c.exec(testContext(t, 2*time.Minute), extra, args...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// login runs `paddockctl mcp login --no-browser` headlessly: it reads the verification URL and the user code from
// stderr, approves them in a browser session of its own as id (password and TOTP) and waits for the command to end.
func (c *mcpCLI) login(t *testing.T, id mcpIdentity) ctlResult {
	t.Helper()
	ctx := testContext(t, 5*time.Minute)
	args := []string{"mcp", "login", "--no-browser"}
	if id.platform {
		args = append(args, "--platform")
	}
	cmd := exec.CommandContext(ctx, c.ctl.bin, args...) //nolint:gosec // the gate's own binary
	cmd.Env = c.environ(nil)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	prompt := make(chan authflow.DeviceAuthorization, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			errOut.WriteString(sc.Text() + "\n")
			if m := mcpLoginPrompt.FindStringSubmatch(sc.Text()); m != nil {
				select {
				case prompt <- authflow.DeviceAuthorization{VerificationURIComplete: m[1], UserCode: m[2]}:
				default:
				}
			}
		}
	}()
	select {
	case da := <-prompt:
		if _, err := authflow.ApproveDevice(ctx, c.ctl.caFile, da, id.username, id.password, id.totp); err != nil {
			_ = cmd.Process.Kill()
			<-done
			_ = cmd.Wait()
			t.Fatalf("approve the MCP login of %s: %v (paddockctl stderr: %s)", id.username, err, errOut.String())
		}
	case <-done:
	}
	<-done
	err = cmd.Wait()
	r := ctlResult{stdout: out.String(), stderr: errOut.String()}
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		r.code = exit.ExitCode()
	case err != nil:
		t.Fatalf("paddockctl mcp login: %v", err)
	}
	return r
}

// signIn is login that must succeed; it returns the line paddockctl printed.
func (c *mcpCLI) signIn(t *testing.T, id mcpIdentity) string {
	t.Helper()
	r := c.login(t, id)
	if r.code != 0 || !strings.HasPrefix(r.stdout, "Signed in as ") {
		t.Fatalf("paddockctl mcp login as %s: %+v", id.username, r)
	}
	s := c.session(t)
	if strings.Contains(r.stdout+r.stderr, s.AccessToken) || strings.Contains(r.stdout+r.stderr, s.RefreshToken) {
		t.Fatal("paddockctl mcp login printed a token")
	}
	return strings.TrimSpace(r.stdout)
}

func (c *mcpCLI) readSession() (mcpSessionFile, error) {
	raw, err := os.ReadFile(c.sessionPath())
	if err != nil {
		return mcpSessionFile{}, err
	}
	var s mcpSessionFile
	if err := json.Unmarshal(raw, &s); err != nil {
		return mcpSessionFile{}, fmt.Errorf("session file: %w", err)
	}
	return s, nil
}

// session is the session file as it is now.
func (c *mcpCLI) session(t *testing.T) mcpSessionFile {
	t.Helper()
	s, err := c.readSession()
	if err != nil {
		t.Fatalf("MCP session file: %v", err)
	}
	return s
}

// signedOut fails unless the workstation has no session file.
func (c *mcpCLI) signedOut(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(c.sessionPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("session file %s still exists (%v)", c.sessionPath(), err)
	}
}

// freshToken returns an access token with at least mcpTokenMargin left. A shorter one is renewed the way an
// administrator's client renews it: `paddockctl mcp tools` refreshes at Authentik, opens the renewed session at the
// api and saves the file. The renewal counts even when the tool listing after it fails (a rate-limited read).
func (c *mcpCLI) freshToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, err := c.readSession()
	if err != nil {
		return "", err
	}
	if time.Until(s.ExpiresAt) > mcpTokenMargin {
		return s.AccessToken, nil
	}
	r, err := c.exec(ctx, nil, "mcp", "tools", "-o", "json")
	if err != nil {
		return "", err
	}
	if s, err = c.readSession(); err != nil {
		return "", err
	}
	if time.Until(s.ExpiresAt) <= mcpTokenMargin {
		return "", fmt.Errorf("MCP session not renewed (paddockctl mcp tools exit %d: %s)", r.code, strings.TrimSpace(r.stderr))
	}
	return s.AccessToken, nil
}

// token is freshToken for a test.
func (c *mcpCLI) token(t *testing.T) string {
	t.Helper()
	tok, err := c.freshToken(testContext(t, 2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// mcpBearer sends every request with the workstation's current MCP access token and the gate's client name, like
// `paddockctl mcp` does.
type mcpBearer struct {
	base http.RoundTripper
	cli  *mcpCLI
}

func (b mcpBearer) RoundTrip(r *http.Request) (*http.Response, error) {
	tok, err := b.cli.freshToken(r.Context())
	if err != nil {
		return nil, err
	}
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Header.Set("X-Paddock-MCP-Client", mcpGateClient)
	return b.base.RoundTrip(r)
}

// portal is an admin API client of the MCP session: direct calls with its access token (plan M14 §9.3).
func (c *mcpCLI) portal(t *testing.T) *env.Portal {
	t.Helper()
	client, err := env.NewHTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	client.Transport = mcpBearer{base: base, cli: c}
	return &env.Portal{User: "mcp session", Client: client}
}

// mcpStdio drives `paddockctl mcp` over stdio as an MCP client named paddock-gate/1.0 (newline-delimited JSON-RPC).
type mcpStdio struct {
	cmd    *exec.Cmd
	in     io.WriteCloser
	lines  chan []byte
	stderr bytes.Buffer
	next   int
	closed bool
}

// serve starts `paddockctl mcp` and initializes the MCP session; it is closed when the test ends.
func (c *mcpCLI) serve(t *testing.T) *mcpStdio {
	t.Helper()
	cmd := exec.Command(c.ctl.bin, "mcp") //nolint:gosec // the gate's own binary
	cmd.Env = c.environ(nil)
	s := &mcpStdio{cmd: cmd, lines: make(chan []byte, 16)}
	cmd.Stderr = &s.stderr
	var err error
	if s.in, err = cmd.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(s.lines)
		sc := bufio.NewScanner(out)
		sc.Buffer(make([]byte, 0, 64<<10), 8<<20)
		for sc.Scan() {
			s.lines <- append([]byte(nil), sc.Bytes()...)
		}
	}()
	t.Cleanup(func() { s.close(t) })
	var init struct {
		ServerInfo struct {
			Name string `json:"name"`
		} `json:"serverInfo"`
	}
	s.request(t, "initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]string{"name": mcpGateClientName, "version": mcpGateClientVersion},
	}, &init)
	if init.ServerInfo.Name != "paddockctl" {
		t.Fatalf("initialize: serverInfo %+v", init.ServerInfo)
	}
	s.send(t, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	return s
}

func (s *mcpStdio) send(t *testing.T, msg any) {
	t.Helper()
	raw, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.in.Write(append(raw, '\n')); err != nil {
		t.Fatalf("write to paddockctl mcp: %v (stderr: %s)", err, s.stderr.String())
	}
}

// request sends one JSON-RPC request and decodes its result into out; a JSON-RPC error fails the test.
func (s *mcpStdio) request(t *testing.T, method string, params, out any) {
	t.Helper()
	s.next++
	id := s.next
	s.send(t, map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	timeout := time.After(2 * time.Minute)
	for {
		select {
		case line, ok := <-s.lines:
			if !ok {
				t.Fatalf("%s: paddockctl mcp closed its output (stderr: %s)", method, s.stderr.String())
			}
			var msg struct {
				ID     *int            `json:"id"`
				Result json.RawMessage `json:"result"`
				Error  *struct {
					Code    int    `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(line, &msg); err != nil {
				t.Fatalf("%s: not JSON-RPC on stdout: %s", method, line)
			}
			if msg.ID == nil || *msg.ID != id {
				continue
			}
			if msg.Error != nil {
				t.Fatalf("%s: JSON-RPC error %d %s", method, msg.Error.Code, msg.Error.Message)
			}
			if err := json.Unmarshal(msg.Result, out); err != nil {
				t.Fatalf("%s: result %s: %v", method, msg.Result, err)
			}
			return
		case <-timeout:
			t.Fatalf("%s: no answer from paddockctl mcp within 2 minutes (stderr: %s)", method, s.stderr.String())
		}
	}
}

// mcpListedTool is a tools/list entry.
type mcpListedTool struct {
	Name        string `json:"name"`
	Annotations struct {
		ReadOnlyHint    bool  `json:"readOnlyHint"`
		DestructiveHint *bool `json:"destructiveHint"`
	} `json:"annotations"`
}

// tools returns the tools/list answer, all pages.
func (s *mcpStdio) tools(t *testing.T) []mcpListedTool {
	t.Helper()
	var all []mcpListedTool
	cursor := ""
	for {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		var page struct {
			Tools      []mcpListedTool `json:"tools"`
			NextCursor string          `json:"nextCursor"`
		}
		s.request(t, "tools/list", params, &page)
		all = append(all, page.Tools...)
		if page.NextCursor == "" {
			return all
		}
		cursor = page.NextCursor
	}
}

// toolNames is tools as a list of names.
func (s *mcpStdio) toolNames(t *testing.T) []string {
	t.Helper()
	var names []string
	for _, tool := range s.tools(t) {
		names = append(names, tool.Name)
	}
	return names
}

// mcpToolResult is a tools/call result of `paddockctl mcp` (plan M14 §6.2).
type mcpToolResult struct {
	IsError bool `json:"isError"`
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Structured struct {
		Notice string          `json:"notice"`
		Status int             `json:"status"`
		Data   json.RawMessage `json:"data"`
		Error  *struct {
			Code       string `json:"code"`
			Detail     string `json:"detail"`
			RequestID  string `json:"request_id"`
			PortalPath string `json:"portal_path"`
		} `json:"error"`
	} `json:"structuredContent"`
}

// call runs tools/call.
func (s *mcpStdio) call(t *testing.T, name string, args map[string]any) mcpToolResult {
	t.Helper()
	if args == nil {
		args = map[string]any{}
	}
	var r mcpToolResult
	s.request(t, "tools/call", map[string]any{"name": name, "arguments": args}, &r)
	return r
}

// close ends the session (EOF on stdin), waits for the process and returns its stderr.
func (s *mcpStdio) close(t *testing.T) string {
	t.Helper()
	if s.closed {
		return s.stderr.String()
	}
	s.closed = true
	_ = s.in.Close()
	for range s.lines {
	}
	done := make(chan error, 1)
	go func() { done <- s.cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("paddockctl mcp after EOF on stdin: %v (stderr: %s)", err, s.stderr.String())
		}
	case <-time.After(30 * time.Second):
		_ = s.cmd.Process.Kill()
		t.Errorf("paddockctl mcp did not exit within 30 s of EOF on stdin")
	}
	return s.stderr.String()
}

// mcpPolicy is an McpSettingsInput with mode all, or mode selected with ops.
func mcpPolicy(enabled, writeEnabled bool, ops ...string) map[string]any {
	mode := "all"
	if len(ops) > 0 {
		mode = "selected"
	}
	if ops == nil {
		ops = []string{}
	}
	return map[string]any{"enabled": enabled, "write_enabled": writeEnabled, "mode": mode, "allowed_operations": ops}
}

// putMCPPolicy saves an MCP policy at path (organization or platform) as user's portal session p, after a step-up.
func putMCPPolicy(t *testing.T, p *env.Portal, user, path string, policy map[string]any) env.Response {
	t.Helper()
	freshStepUp(t, p, user)
	res := call(t, p, http.MethodPut, path, policy)
	expectStatus(t, res, http.StatusOK, "")
	return res
}

// restoreMCPState snapshots the MCP policy of org and of the platform and the MCP write opt-in of accounts
// (admin_account or platform_admin ids), and writes them back as they were when the test ends: the gates change them through the API,
// which cannot delete a policy (the MCP is off until a policy is saved).
func restoreMCPState(t *testing.T, org uuid.UUID, accounts ...string) {
	t.Helper()
	db := ownerDB(t)
	ctx := testContext(t, time.Minute)
	type policyRow struct {
		enabled, writeEnabled bool
		mode                  string
		ops                   []string
		updatedAt             time.Time
		updatedBy             *string
	}
	read := func(query string, args ...any) *policyRow {
		var r policyRow
		err := db.QueryRow(ctx, query, args...).Scan(&r.enabled, &r.writeEnabled, &r.mode, &r.ops, &r.updatedAt, &r.updatedBy)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			t.Fatalf("snapshot MCP policy: %v", err)
		}
		return &r
	}
	orgRow := read(`SELECT enabled, write_enabled, mode, allowed_operations, updated_at, updated_by::text
		FROM organization_mcp_settings WHERE organization_id = $1`, org)
	platformRow := read(`SELECT enabled, write_enabled, mode, allowed_operations, updated_at, updated_by::text
		FROM platform_mcp_settings`)
	optIns := map[string]*time.Time{}
	for _, id := range accounts {
		var at *time.Time
		if err := db.QueryRow(ctx, `SELECT mcp_write_enabled_at FROM admin_account WHERE id = $1::uuid
			UNION ALL SELECT mcp_write_enabled_at FROM platform_admin WHERE id = $1::uuid`, id).Scan(&at); err != nil {
			t.Fatalf("snapshot MCP write opt-in of %s: %v", id, err)
		}
		optIns[id] = at
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		write := func(query string, args ...any) {
			if _, err := db.Exec(ctx, query, args...); err != nil {
				t.Errorf("restore MCP state: %v", err)
			}
		}
		write("DELETE FROM organization_mcp_settings WHERE organization_id = $1", org)
		if r := orgRow; r != nil {
			write(`INSERT INTO organization_mcp_settings (organization_id, enabled, write_enabled, mode, allowed_operations,
				updated_at, updated_by) VALUES ($1, $2, $3, $4, $5, $6, $7::uuid)`,
				org, r.enabled, r.writeEnabled, r.mode, r.ops, r.updatedAt, r.updatedBy)
		}
		write("DELETE FROM platform_mcp_settings")
		if r := platformRow; r != nil {
			write(`INSERT INTO platform_mcp_settings (enabled, write_enabled, mode, allowed_operations, updated_at, updated_by)
				VALUES ($1, $2, $3, $4, $5, $6::uuid)`, r.enabled, r.writeEnabled, r.mode, r.ops, r.updatedAt, r.updatedBy)
		}
		for id, at := range optIns {
			write("UPDATE admin_account SET mcp_write_enabled_at = $2 WHERE id = $1::uuid", id, at)
			write("UPDATE platform_admin SET mcp_write_enabled_at = $2 WHERE id = $1::uuid", id, at)
		}
	})
}

// clearMCPPolicies deletes the MCP policy of org and of the platform: the state of an installation in which no
// administrator saved one yet. restoreMCPState puts the previous rows back.
func clearMCPPolicies(t *testing.T, org uuid.UUID) {
	t.Helper()
	db := ownerDB(t)
	ctx := testContext(t, time.Minute)
	for _, q := range []string{"DELETE FROM organization_mcp_settings WHERE organization_id = $1", "DELETE FROM platform_mcp_settings"} {
		var args []any
		if strings.Contains(q, "$1") {
			args = []any{org}
		}
		if _, err := db.Exec(ctx, q, args...); err != nil {
			t.Fatalf("clear MCP policies: %v", err)
		}
	}
}

// expectMCPRefusal is expectRefusal for a request of an MCP session: the denied event is also recorded with source
// mcp and the administrator as actor.
func expectMCPRefusal(t *testing.T, viewer *env.Portal, res env.Response, status int, problemCode, code string) env.AuditEvent {
	t.Helper()
	expectStatus(t, res, status, problemCode)
	ev := expectOneEvent(t, viewer, res.RequestID, code, "denied")
	if ev.ErrorCode != problemCode || ev.Source != "mcp" || ev.Actor.Type != "admin" {
		t.Fatalf("event %s/%s: error code %q, source %q, actor type %q; want %q, mcp, admin", ev.Code, ev.Outcome,
			ev.ErrorCode, ev.Source, ev.Actor.Type, problemCode)
	}
	return ev
}

// expectOneTargetEvent waits for the events of code about target id visible to viewer and requires exactly one with
// outcome, also after the audit pipeline settled. Tool results carry no request id on success, so the gate finds the
// event of a tool call by the object it created or deleted.
func expectOneTargetEvent(t *testing.T, viewer *env.Portal, code, id, outcome string) env.AuditEvent {
	t.Helper()
	ctx := testContext(t, 2*time.Minute)
	find := func() []env.AuditEvent {
		events, err := viewer.AuditEvents(ctx, code)
		if err != nil {
			t.Fatal(err)
		}
		var found []env.AuditEvent
		for _, e := range events {
			if e.Target != nil && e.Target.ID == id {
				found = append(found, e)
			}
		}
		return found
	}
	var found []env.AuditEvent
	start := time.Now()
	// Deadline against the poll's start and a load-dependent settle, as in expectOneEvent (PDK-551, PDK-561).
	for deadline := start.Add(auditPollTimeout); ; time.Sleep(500 * time.Millisecond) {
		polled := time.Now()
		if found = find(); len(found) > 0 || polled.After(deadline) {
			break
		}
	}
	time.Sleep(auditSettle(time.Since(start)))
	found = find()
	if len(found) != 1 || found[0].Outcome != outcome {
		t.Fatalf("%s events of target %s: %+v, want exactly one with outcome %s", code, id, found, outcome)
	}
	return found[0]
}

// mcpCallRetrying sends a request of an MCP session and waits out its rate limit (429 rate_limited, Retry-After):
// gates that walk many operations exceed the per-account budget on purpose-free grounds.
func mcpCallRetrying(t *testing.T, p *env.Portal, method, path string, body any) env.Response {
	t.Helper()
	for attempt := 0; ; attempt++ {
		res := call(t, p, method, path, body)
		if res.Status != http.StatusTooManyRequests || attempt == 5 {
			return res
		}
		wait, err := strconv.Atoi(res.Header.Get("Retry-After"))
		if err != nil || wait < 1 || wait > 60 {
			t.Fatalf("%s %s: 429 with Retry-After %q", method, path, res.Header.Get("Retry-After"))
		}
		time.Sleep(time.Duration(wait)*time.Second + 500*time.Millisecond)
	}
}

// hasTool reports whether tools contains name.
func hasTool(tools []string, name string) bool { return slices.Contains(tools, name) }
