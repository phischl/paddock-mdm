package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/phischl/paddock-mdm/cli/internal/client"
	"github.com/phischl/paddock-mdm/pkg/mcpcatalog"
)

const (
	// refreshAhead renews the access token this long before it expires.
	refreshAhead = 2 * time.Minute
	// accessTTL is how long an answer of GET /api/v1/mcp/access is reused.
	accessTTL = 30 * time.Second
	// maxToolResponse bounds a tool's response body; a larger one is refused instead of filling the context.
	maxToolResponse = 1 << 20
)

// errUnreachable marks a failure without an HTTP answer from the admin API.
var errUnreachable = errors.New(detailUnreachable)

// access is GET /api/v1/mcp/access.
type access struct {
	Enabled           bool     `json:"enabled"`
	WriteEffective    bool     `json:"write_effective"`
	AllowedOperations []string `json:"allowed_operations"`
}

// registered is a tool the server offers.
type registered struct {
	tool   mcpcatalog.Tool
	schema *jsonschema.Resolved
}

// Server is the stdio MCP server of paddockctl mcp: it offers the catalog's exposed tools the api allows the session
// and calls the admin API with the session's access token, renewing it on the way.
type Server struct {
	c       *client.Client
	path    string
	version string
	errw    io.Writer
	now     func() time.Time

	mu      sync.Mutex
	session SessionFile
	stuck   error // ErrLoginRequired once a renewal was refused; cleared when a new login appears on disk
	// onDisk is the refresh token this process last read from or wrote to the session file; only a different one on
	// disk is a login or renewal by another process.
	onDisk   string
	save     func(path string, s SessionFile) error
	access   access
	accessAt time.Time

	srv   *mcp.Server
	tools map[string]registered
}

// New creates the server for the signed-in session s, saved at path. Log lines go to errw (stderr), never a token.
func New(c *client.Client, s SessionFile, path, version string, errw io.Writer) *Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "paddockctl", Version: version}, &mcp.ServerOptions{
		Instructions: mcpcatalog.Instructions,
		// Only tools: no logging capability (the SDK's default) and no list_changed, as the tool set is fixed per run.
		Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{ListChanged: false}},
	})
	return &Server{c: c, path: path, version: version, errw: errw, now: time.Now, session: s, srv: srv,
		tools: map[string]registered{}, onDisk: s.RefreshToken, save: SaveSession}
}

// Session returns the current session (after renewals).
func (s *Server) Session() SessionFile {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.session
}

// Register adds one tool per exposed catalog entry the api allows the session (plan M14 §3.5 item 26).
func (s *Server) Register(ctx context.Context) error {
	acc, err := s.fetchAccess(ctx, s.selfClient())
	if err != nil {
		return err
	}
	if !acc.Enabled {
		_, _ = fmt.Fprintln(s.errw, "paddockctl mcp: the MCP is switched off for this scope; an administrator enables it in the portal")
	}
	for _, t := range mcpcatalog.Exposed() {
		if !slices.Contains(acc.AllowedOperations, t.Name) {
			continue
		}
		tool, err := toolFor(t)
		if err != nil {
			return err
		}
		rs, err := resolve(tool)
		if err != nil {
			return err
		}
		s.tools[t.Name] = registered{tool: t, schema: rs}
		s.srv.AddTool(tool, s.handle)
	}
	return nil
}

// Run serves MCP on t until the client closes it; the command passes the process's stdin and stdout.
func (s *Server) Run(ctx context.Context, t mcp.Transport) error {
	return s.srv.Run(ctx, t)
}

// Tools lists the exposed catalog entries in allowed_operations, for paddockctl mcp tools.
func (s *Server) Tools(ctx context.Context) ([]ToolListEntry, error) {
	acc, err := s.fetchAccess(ctx, s.selfClient())
	if err != nil {
		return nil, err
	}
	out := []ToolListEntry{}
	for _, t := range mcpcatalog.Exposed() {
		if slices.Contains(acc.AllowedOperations, t.Name) {
			out = append(out, ToolListEntry{Name: t.Name, Title: titleOf(t), Class: t.Class, Destructive: t.Destructive})
		}
	}
	return out, nil
}

func (s *Server) selfClient() string { return "paddockctl/" + s.version }

// allowed answers from the access cache, fetched again when older than accessTTL.
func (s *Server) allowed(ctx context.Context, name, mcpClient string) (bool, error) {
	s.mu.Lock()
	acc, fresh := s.access, s.now().Sub(s.accessAt) < accessTTL
	s.mu.Unlock()
	if !fresh {
		var err error
		if acc, err = s.fetchAccess(ctx, mcpClient); err != nil {
			return false, err
		}
	}
	return slices.Contains(acc.AllowedOperations, name), nil
}

func (s *Server) fetchAccess(ctx context.Context, mcpClient string) (access, error) {
	resp, err := s.send(ctx, client.Request{Method: http.MethodGet, Path: "/api/v1/mcp/access"}, mcpClient)
	if err != nil {
		return access{}, err
	}
	if p := resp.Problem(); p != nil {
		return access{}, fmt.Errorf("MCP access: %w", p)
	}
	var acc access
	if err := json.Unmarshal(resp.Body, &acc); err != nil {
		return access{}, fmt.Errorf("MCP access: %w", err)
	}
	s.mu.Lock()
	s.access, s.accessAt = acc, s.now()
	s.mu.Unlock()
	return acc, nil
}

// send calls the admin API with the session's access token; a 401 renews the session once and retries, a second
// 401 is ErrLoginRequired. A transport failure is errUnreachable.
func (s *Server) send(ctx context.Context, r client.Request, mcpClient string) (*client.Response, error) {
	if r.Header == nil {
		r.Header = http.Header{}
	}
	r.Header.Set("X-Paddock-Mcp-Client", mcpClient)
	token, err := s.token(ctx, "", mcpClient)
	if err != nil {
		return nil, err
	}
	r.Bearer = token
	resp, err := s.c.Send(ctx, r)
	if err != nil {
		s.logf("admin API request failed: %v", transportError(err))
		return nil, errUnreachable
	}
	if resp.Status != http.StatusUnauthorized {
		return resp, nil
	}
	if r.Bearer, err = s.token(ctx, token, mcpClient); err != nil {
		return nil, err
	}
	if resp, err = s.c.Send(ctx, r); err != nil {
		s.logf("admin API request failed: %v", transportError(err))
		return nil, errUnreachable
	}
	if resp.Status == http.StatusUnauthorized {
		return nil, ErrLoginRequired
	}
	return resp, nil
}

// token returns an access token that lives at least refreshAhead, renewing the session when needed. rejected is a
// token the api just answered 401 for: it is renewed even if it has not expired.
func (s *Server) token(ctx context.Context, rejected, mcpClient string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	usable := func(f SessionFile) bool {
		return f.AccessToken != "" && f.AccessToken != rejected && f.ExpiresAt.Sub(s.now()) > refreshAhead
	}
	// The file lock spans re-read, refresh and save, so paddockctl processes sharing the session (mcp, mcp tools,
	// mcp login, mcp logout) never spend the same refresh token twice nor overwrite a newer login.
	unlock, err := LockSession(ctx, s.path)
	if err != nil {
		s.logf("%v", err)
		return "", errUnreachable
	}
	defer unlock()
	disk, derr := LoadSession(s.path)
	switch {
	case errors.Is(derr, ErrNoSession):
		// paddockctl mcp logout removed the file: this process is signed out too and never writes the tokens back.
		s.stuck = ErrLoginRequired
	case derr != nil || disk.RefreshToken == s.onDisk:
	case disk.APIURL != s.session.APIURL || disk.Issuer != s.session.Issuer || disk.ClientID != s.session.ClientID:
		// A login to another installation replaced ours: this process is signed out and must not overwrite it.
		s.stuck, s.onDisk = ErrLoginRequired, disk.RefreshToken
	default:
		s.session, s.stuck, s.onDisk = disk, nil, disk.RefreshToken
	}
	if s.stuck != nil {
		return "", s.stuck
	}
	if usable(s.session) {
		return s.session.AccessToken, nil
	}
	next, err := Refresh(ctx, s.c, s.session, mcpClient)
	if next.RefreshToken != s.session.RefreshToken || next.AccessToken != s.session.AccessToken {
		s.session = next
		if serr := s.save(s.path, next); serr != nil {
			s.logf("saving the session failed: %v", serr)
		} else {
			s.onDisk = next.RefreshToken
		}
	}
	switch {
	case errors.Is(err, ErrLoginRequired):
		s.stuck = ErrLoginRequired
		s.logf("the session cannot be renewed: %v", err)
		return "", ErrLoginRequired
	case err != nil:
		s.logf("renewing the session failed: %v", err)
		return "", errUnreachable
	}
	return s.session.AccessToken, nil
}

func (s *Server) logf(format string, a ...any) {
	_, _ = fmt.Fprintf(s.errw, "paddockctl mcp: "+format+"\n", a...)
}
