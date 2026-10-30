package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"text/tabwriter"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/phischl/paddock-mdm/cli/internal/cfg"
	"github.com/phischl/paddock-mdm/cli/internal/client"
	"github.com/phischl/paddock-mdm/cli/internal/mcp"
)

// runMCP dispatches paddockctl mcp [login|logout|tools] (plan M14 §3.5). The MCP never uses an API token: the
// token file of the other commands is ignored.
func runMCP(ctx context.Context, e Env, args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "login":
			return runMCPLogin(ctx, e, args[1:])
		case "logout":
			return runMCPLogout(ctx, e, args[1:])
		case "tools":
			return runMCPTools(ctx, e, args[1:])
		}
	}
	return runMCPServe(ctx, e, args)
}

// mcpConnect creates the client for the admin API of the MCP; fallbackURL is the URL of an existing session.
func (g *globals) mcpConnect(e Env, fallbackURL string) (*client.Client, error) {
	c, err := cfg.Resolve(cfg.Sources{URL: g.url, CAFile: g.caFile, ConfigFile: g.config, Getenv: e.Getenv, NoToken: true,
		DefaultURL: fallbackURL})
	if err != nil {
		return nil, err
	}
	if fallbackURL != "" && c.URL != strings.TrimRight(fallbackURL, "/") {
		return nil, cfg.Errorf("the MCP session belongs to %s, not %s; run paddockctl mcp login --url %s", fallbackURL, c.URL, c.URL)
	}
	cl, err := client.New(c.URL, "", c.CAFile, e.Version)
	if err != nil {
		return nil, cfg.Errorf("%v", err)
	}
	return cl, nil
}

func sessionPath(e Env) (string, error) {
	p := mcp.SessionPath(e.Getenv)
	if p == "" {
		return "", cfg.Errorf("no session location: set XDG_STATE_HOME or HOME")
	}
	return p, nil
}

// loadSession reads the session file; a missing one is a configuration error (exit 2).
func loadSession(e Env) (mcp.SessionFile, string, error) {
	path, err := sessionPath(e)
	if err != nil {
		return mcp.SessionFile{}, "", err
	}
	s, err := mcp.LoadSession(path)
	if errors.Is(err, mcp.ErrNoSession) {
		return mcp.SessionFile{}, "", cfg.Errorf("%v", err)
	}
	if err != nil {
		return mcp.SessionFile{}, "", cfg.Errorf("%v", err)
	}
	return s, path, nil
}

func runMCPLogin(ctx context.Context, e Env, args []string) error {
	var g globals
	fs := newFlags("mcp login")
	g.register(fs, "text")
	noBrowser := fs.Bool("no-browser", false, "")
	platform := fs.Bool("platform", false, "")
	if err := parse(fs, args); err != nil {
		return err
	}
	path, err := sessionPath(e)
	if err != nil {
		return err
	}
	c, err := g.mcpConnect(e, "")
	if err != nil {
		return err
	}
	o := mcp.LoginOptions{Role: mcp.RoleOrganization, Out: e.Stderr, Client: "paddockctl/" + e.Version}
	if *platform {
		o.Role = mcp.RolePlatform
	}
	if !*noBrowser && (e.Getenv("DISPLAY") != "" || e.Getenv("WAYLAND_DISPLAY") != "") {
		o.Browser = openBrowser
	}
	s, err := mcp.Login(ctx, c, o)
	if err != nil {
		return err
	}
	unlock, err := mcp.LockSession(ctx, path)
	if err != nil {
		return err
	}
	err = mcp.SaveSession(path, s)
	unlock()
	if err != nil {
		return err
	}
	summary, err := mcp.Summary(ctx, c, s)
	if err != nil {
		return fmt.Errorf("signed in, but reading the account failed: %w", err)
	}
	_, err = fmt.Fprintln(e.Stdout, summary)
	return err
}

// openBrowser starts xdg-open detached; its output never reaches paddockctl's streams.
func openBrowser(url string) error {
	return exec.Command("xdg-open", url).Start() //nolint:gosec // the verification URL of the configured provider
}

func runMCPLogout(ctx context.Context, e Env, args []string) error {
	var g globals
	fs := newFlags("mcp logout")
	g.register(fs, "text")
	if err := parse(fs, args); err != nil {
		return err
	}
	path, err := sessionPath(e)
	if err != nil {
		return err
	}
	// Read and remove under the lock: a renewal in flight finishes first, so the tokens revoked below are the
	// current ones, and a running paddockctl mcp then finds the file gone instead of writing it back.
	unlock, err := mcp.LockSession(ctx, path)
	if err != nil {
		return err
	}
	s, err := mcp.LoadSession(path)
	if errors.Is(err, mcp.ErrNoSession) {
		unlock()
		_, err = fmt.Fprintln(e.Stdout, "Not signed in")
		return err
	}
	// The local tokens go first: whatever the server answers, this workstation is signed out.
	rerr := mcp.RemoveSession(path)
	unlock()
	if rerr != nil {
		return rerr
	}
	if err == nil {
		if c, cerr := g.mcpConnect(e, s.APIURL); cerr != nil {
			_, _ = fmt.Fprintf(e.Stderr, "warning: %v\n", cerr)
		} else {
			mcp.Logout(ctx, c, s, e.Stderr)
		}
	}
	_, err = fmt.Fprintln(e.Stdout, "Signed out")
	return err
}

// mcpServer loads the session and creates the server; the session is renewed first when it expires soon.
func mcpServer(e Env, g *globals) (*mcp.Server, error) {
	s, path, err := loadSession(e)
	if err != nil {
		return nil, err
	}
	c, err := g.mcpConnect(e, s.APIURL)
	if err != nil {
		return nil, err
	}
	return mcp.New(c, s, path, e.Version, e.Stderr), nil
}

func runMCPTools(ctx context.Context, e Env, args []string) error {
	var g globals
	fs := newFlags("mcp tools")
	g.register(fs, "table")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := g.requireOutput("table", "json"); err != nil {
		return err
	}
	srv, err := mcpServer(e, &g)
	if err != nil {
		return err
	}
	tools, err := srv.Tools(ctx)
	if err != nil {
		return err
	}
	if g.output == "json" {
		return writeJSON(e.Stdout, tools)
	}
	tw := tabwriter.NewWriter(e.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tCLASS\tDESTRUCTIVE\tTITLE")
	for _, t := range tools {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%t\t%s\n", t.Name, t.Class, t.Destructive, t.Title)
	}
	return tw.Flush()
}

func runMCPServe(ctx context.Context, e Env, args []string) error {
	var g globals
	fs := newFlags("mcp")
	g.register(fs, "text")
	if err := parse(fs, args); err != nil {
		return err
	}
	srv, err := mcpServer(e, &g)
	if err != nil {
		return err
	}
	if err := srv.Register(ctx); err != nil {
		return err
	}
	err = srv.Run(ctx, &sdk.IOTransport{Reader: io.NopCloser(e.Stdin), Writer: nopWriteCloser{e.Stdout}})
	if err == nil || errors.Is(err, io.EOF) || ctx.Err() != nil {
		return nil
	}
	return err
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }
