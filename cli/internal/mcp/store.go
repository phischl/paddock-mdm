// Package mcp is paddockctl's MCP side (ADR 0044, plan M14 §3.5): the Authentik device login of an administrator, the
// local session file, and the stdio MCP server that offers the admin API operations the server allows as tools.
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Roles of an MCP session (ADR 0045 decision 7); the session endpoint defaults to organization.
const (
	RoleOrganization = "organization"
	RolePlatform     = "platform"
)

// SessionFile is the signed-in MCP session on the administrator's workstation. It holds the access and refresh
// tokens and is therefore written with mode 0600 in a 0700 directory.
type SessionFile struct {
	APIURL       string    `json:"api_url"`
	Issuer       string    `json:"issuer"`
	ClientID     string    `json:"client_id"`
	Role         string    `json:"role"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// ErrNoSession is returned by LoadSession when no session file exists.
var ErrNoSession = errors.New("not signed in: run paddockctl mcp login")

// SessionPath is $XDG_STATE_HOME/paddockctl/mcp-session.json, by default ~/.local/state/paddockctl/mcp-session.json;
// "" when neither variable is set.
func SessionPath(getenv func(string) string) string {
	if dir := getenv("XDG_STATE_HOME"); dir != "" {
		return filepath.Join(dir, "paddockctl", "mcp-session.json")
	}
	if home := getenv("HOME"); home != "" {
		return filepath.Join(home, ".local", "state", "paddockctl", "mcp-session.json")
	}
	return ""
}

// LoadSession reads the session file; ErrNoSession when it does not exist.
func LoadSession(path string) (SessionFile, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // the administrator's own session file
	if errors.Is(err, os.ErrNotExist) {
		return SessionFile{}, ErrNoSession
	}
	if err != nil {
		return SessionFile{}, fmt.Errorf("session file: %w", err)
	}
	var s SessionFile
	if err := json.Unmarshal(raw, &s); err != nil {
		return SessionFile{}, fmt.Errorf("session file %s is damaged; run paddockctl mcp login", path)
	}
	if s.RefreshToken == "" || s.APIURL == "" {
		return SessionFile{}, fmt.Errorf("session file %s is incomplete; run paddockctl mcp login", path)
	}
	return s, nil
}

// SaveSession writes the session file atomically: a temporary file (0600) in the 0700 directory, renamed over the
// old one, so a concurrent reader never sees a partial file.
func SaveSession(path string, s SessionFile) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("session directory: %w", err)
	}
	// MkdirAll keeps the mode of an existing directory; the tokens must not be listable by others either.
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // a directory needs the search bit; 0700 is owner-only
		return fmt.Errorf("session directory: %w", err)
	}
	raw, err := json.MarshalIndent(s, "", "  ") //nolint:gosec // the session file is where the tokens belong (mode 0600)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".mcp-session-*")
	if err != nil {
		return fmt.Errorf("session file: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("session file: %w", err)
	}
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("session file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("session file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("session file: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("session file: %w", err)
	}
	// Without the directory sync a crash could bring back the previous file and with it a spent refresh token.
	d, err := os.Open(dir) //nolint:gosec // the session directory
	if err != nil {
		return fmt.Errorf("session directory: %w", err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("session directory: %w", err)
	}
	return nil
}

// lockPoll is the interval at which LockSession retries a lock another process holds.
const lockPoll = 50 * time.Millisecond

// LockSession takes an exclusive advisory lock on <path>.lock, waiting while other paddockctl processes hold it, but
// never past ctx; the returned function releases it. Callers hold it around re-reading, renewing and writing or
// removing the session file.
func LockSession(ctx context.Context, path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("session lock: %w", err)
	}
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // the session directory
	if err != nil {
		return nil, fmt.Errorf("session lock: %w", err)
	}
	fd := int(f.Fd()) //nolint:gosec // Fd fits an int on Linux
	for {
		err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			_ = f.Close()
			return nil, fmt.Errorf("session lock: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, fmt.Errorf("session lock: %w", ctx.Err())
		case <-time.After(lockPoll):
		}
	}
	return func() {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

// RemoveSession deletes the session file; a missing file is not an error.
func RemoveSession(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("session file: %w", err)
	}
	return nil
}
