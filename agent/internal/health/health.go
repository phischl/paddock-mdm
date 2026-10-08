// Package health is the agent's health endpoint: GET /health on the unix socket /run/paddock/agent.sock (plan M2b
// decision 14).
package health

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// Status values.
const (
	StatusOK          = "ok"
	StatusDegraded    = "degraded"
	StatusNotEnrolled = "not_enrolled"
)

// Report is the body of GET /health.
type Report struct {
	Status            string     `json:"status"`
	Version           string     `json:"version"`
	LastCheckinAt     *time.Time `json:"last_checkin_at"`
	LastBundleVersion int64      `json:"last_bundle_version"`
	LastError         string     `json:"last_error"`
	// SudoFlavor is the active sudo implementation, classic or sudo-rs (empty until detected).
	SudoFlavor string `json:"sudo_flavor,omitempty"`
	// Disk is the disk encryption of the device (nil until the first inventory).
	Disk *protocol.DiskHealth `json:"disk,omitempty"`
	// RebootRequired is set while a package asks for a reboot (/var/run/reboot-required, plan M5b decision 8);
	// Paddock never reboots for updates.
	RebootRequired bool `json:"reboot_required"`
}

// State is the current health, shared between the run loop (writer) and the socket server (reader).
type State struct {
	mu sync.Mutex
	r  Report
}

// NewState creates the state for an agent version.
func NewState(version string) *State {
	return &State{r: Report{Status: StatusNotEnrolled, Version: version}}
}

// Update changes the report under the lock.
func (s *State) Update(fn func(r *Report)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.r)
}

// Report returns a copy of the current report.
func (s *State) Report() Report {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.r
}

// Serve answers GET /health on the unix socket path (mode 0600) until ctx ends.
func Serve(ctx context.Context, path string, s *State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // /run/paddock; the socket itself is 0600
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale health socket: %w", err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("health socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.Report())
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	case err := <-errCh:
		return err
	}
}

// Get reads the health report from the socket at path.
func Get(ctx context.Context, path string) (Report, error) {
	hc := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		},
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://agent/health", nil)
	if err != nil {
		return Report{}, err
	}
	res, err := hc.Do(req)
	if err != nil {
		return Report{}, err
	}
	defer func() { _ = res.Body.Close() }()
	var r Report
	return r, json.NewDecoder(res.Body).Decode(&r)
}
