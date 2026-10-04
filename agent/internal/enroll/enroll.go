// Package enroll is `paddockd enroll` (plan M2b decision 7): it stores the configuration from an enrollment
// configuration, creates the identity key, sends the enrollment request and polls until the device is active,
// pending or rejected. Re-running resumes with the same key and enrollment ID.
package enroll

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/paddock-mdm/paddock/agent/internal/buildinfo"
	"github.com/paddock-mdm/paddock/agent/internal/client"
	"github.com/paddock-mdm/paddock/agent/internal/config"
	"github.com/paddock-mdm/paddock/agent/internal/identity"
	"github.com/paddock-mdm/paddock/agent/internal/paths"
	"github.com/paddock-mdm/paddock/agent/internal/state"
	"github.com/paddock-mdm/paddock/pkg/protocol"
)

// Exit codes of `paddockd enroll`.
const (
	ExitActive   = 0
	ExitError    = 1
	ExitPending  = 2
	ExitRejected = 3
)

// Poll back-off (plan M2b decision 7).
const (
	FirstPoll = 10 * time.Second
	MaxPoll   = 5 * time.Minute
	MaxWait   = 24 * time.Hour
)

// Options of one enrollment run.
type Options struct {
	Layout paths.Layout
	// ConfigPath is the enrollment configuration; empty resumes an enrollment started earlier.
	ConfigPath   string
	RemoveConfig bool
	NoWait       bool
	Proxy        string
	// Sleep waits between polls; nil uses a timer (tests replace it).
	Sleep func(ctx context.Context, d time.Duration) error
	// NewClient builds the device API client; nil uses client.New.
	NewClient func(cfg config.Agent, key identity.Key) (*client.Client, error)
}

// Run enrolls the device and returns the exit code.
func Run(ctx context.Context, o Options) (int, error) {
	if o.Sleep == nil {
		o.Sleep = sleep
	}
	if o.NewClient == nil {
		o.NewClient = func(cfg config.Agent, key identity.Key) (*client.Client, error) {
			return client.New(cfg.ServerURL, cfg.Proxy, key)
		}
	}
	l := o.Layout
	st, err := state.Load(l.State())
	if err != nil {
		return ExitError, err
	}
	switch st.Status {
	case state.StatusActive:
		slog.InfoContext(ctx, "device is already enrolled", "device_id", st.DeviceID)
		return ExitActive, removeConfig(o)
	case state.StatusRejected:
		return ExitRejected, errors.New("the enrollment of this device was rejected")
	}
	var token string
	if o.ConfigPath != "" {
		if token, err = storeConfig(o); err != nil {
			return ExitError, err
		}
	} else if st.EnrollmentID == "" {
		return ExitError, errors.New("--config is required for a new enrollment")
	}
	cfg, err := config.LoadAgent(l.AgentConfig())
	if err != nil {
		return ExitError, err
	}
	key, err := identity.LoadOrCreate(l.IdentityKey())
	if err != nil {
		return ExitError, err
	}
	c, err := o.NewClient(cfg, key)
	if err != nil {
		return ExitError, err
	}
	if st.EnrollmentID == "" {
		id, err := c.Enroll(ctx, Request(l, token, key))
		if err != nil {
			return ExitError, fmt.Errorf("enrollment request: %w", err)
		}
		st.EnrollmentID = id
		if err := state.Save(l.State(), st); err != nil {
			return ExitError, err
		}
		slog.InfoContext(ctx, "enrollment requested", "enrollment_id", id, "key_id", key.KeyID)
	}
	code, err := poll(ctx, o, c, &st)
	if err != nil {
		return code, err
	}
	if code == ExitActive || code == ExitPending {
		return code, removeConfig(o)
	}
	return code, nil
}

// storeConfig validates the enrollment configuration and writes agent.yml and trust.json. It returns the token.
func storeConfig(o Options) (string, error) {
	data, err := os.ReadFile(o.ConfigPath)
	if err != nil {
		return "", fmt.Errorf("read enrollment configuration: %w", err)
	}
	ec, err := config.ParseEnrollment(data)
	if err != nil {
		return "", err
	}
	agent := config.Agent{ServerURL: ec.ServerURL, OrganizationID: ec.OrganizationID, Proxy: o.Proxy, DriftInterval: config.DefaultDriftInterval}
	if old, err := config.LoadAgent(o.Layout.AgentConfig()); err == nil {
		agent.DriftInterval = old.DriftInterval // keep a locally tuned interval
		if agent.Proxy == "" {
			agent.Proxy = old.Proxy
		}
	}
	if err := config.SaveAgent(o.Layout.AgentConfig(), agent); err != nil {
		return "", err
	}
	if err := config.SaveTrust(o.Layout.Trust(), ec.BundleKeys); err != nil {
		return "", err
	}
	return ec.Token, nil
}

func removeConfig(o Options) error {
	if !o.RemoveConfig || o.ConfigPath == "" {
		return nil
	}
	if err := os.Remove(o.ConfigPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove enrollment configuration: %w", err)
	}
	return nil
}

// poll waits for the enrollment outcome with back-off from FirstPoll to MaxPoll for at most MaxWait. With NoWait
// it returns ExitPending as soon as the enrollment is pending.
func poll(ctx context.Context, o Options, c *client.Client, st *state.State) (int, error) {
	delay, waited := time.Duration(0), time.Duration(0)
	for {
		if err := o.Sleep(ctx, delay); err != nil {
			return ExitError, fmt.Errorf("enrollment interrupted; run `paddockd enroll` again to resume: %w", err)
		}
		waited += delay
		delay = min(max(2*delay, FirstPoll), MaxPoll)
		s, err := c.EnrollStatus(ctx, st.EnrollmentID)
		switch {
		case client.Code(err) == protocol.CodeNotFound:
			return ExitError, fmt.Errorf("the server does not know enrollment %s; enroll again with a new enrollment configuration", st.EnrollmentID)
		case err != nil:
			slog.WarnContext(ctx, "enrollment status unavailable; retrying", "error", err, "retry_in", delay)
		default:
			if code, done, err := adopt(o.Layout, st, s); done || err != nil {
				return code, err
			}
			if s.Status == protocol.EnrollPending && o.NoWait {
				return ExitPending, nil
			}
		}
		if waited >= MaxWait {
			return ExitPending, errors.New("the enrollment is still not approved after 24 h; run `paddockd enroll` again to keep waiting")
		}
	}
}

// adopt stores an enrollment status and reports whether it is final.
func adopt(l paths.Layout, st *state.State, s protocol.EnrollStatus) (int, bool, error) {
	if s.DeviceID != "" {
		st.DeviceID = s.DeviceID
	}
	code, done := ExitPending, false
	switch s.Status {
	case protocol.EnrollActive:
		st.Status, code, done = state.StatusActive, ExitActive, true
	case protocol.EnrollRejected:
		st.Status, code, done = state.StatusRejected, ExitRejected, true
	case protocol.EnrollPending:
		st.Status = state.StatusPending
	default:
		return code, false, nil
	}
	if err := state.Save(l.State(), *st); err != nil {
		return ExitError, true, err
	}
	if done {
		slog.Info("enrollment finished", "status", s.Status, "device_id", st.DeviceID, "reason", s.Reason)
	}
	return code, done, nil
}

// Poll checks an enrollment started earlier once and stores the outcome (used by `paddockd run` for devices that
// are pending approval). It reports whether the device is active.
func Poll(ctx context.Context, l paths.Layout, c *client.Client, st *state.State) (bool, error) {
	s, err := c.EnrollStatus(ctx, st.EnrollmentID)
	if err != nil {
		return false, err
	}
	code, _, err := adopt(l, st, s)
	return code == ExitActive && err == nil, err
}

// Request describes this device for POST /v1/enroll.
func Request(l paths.Layout, token string, key identity.Key) protocol.EnrollRequest {
	host, _ := os.Hostname()
	return protocol.EnrollRequest{
		Token: token, PublicKey: base64.StdEncoding.EncodeToString(key.SPKI), KeyProtection: protocol.KeyProtectionFile,
		Hostname: host, HardwareUUID: firstLine(l.Join("/sys/class/dmi/id/product_uuid")),
		MachineID: firstLine(l.Join("/etc/machine-id")), OSRelease: osRelease(l.Join("/etc/os-release")),
		AgentVersion: buildinfo.Version,
	}
}

func firstLine(path string) string {
	data, err := os.ReadFile(path) //nolint:gosec // fixed system files below the layout root
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(string(data), "\n")
	line = strings.ToLower(strings.TrimSpace(line))
	if len(line) > 128 {
		return ""
	}
	return line
}

// osReleaseKeys are the os-release fields reported (lowercase keys).
var osReleaseKeys = []string{"ID", "VERSION_ID", "VERSION_CODENAME", "PRETTY_NAME"}

func osRelease(path string) map[string]string {
	data, err := os.ReadFile(path) //nolint:gosec // fixed system file below the layout root
	if err != nil {
		return nil
	}
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		for _, want := range osReleaseKeys {
			if k == want {
				out[strings.ToLower(k)] = strings.Trim(v, `"'`)
			}
		}
	}
	return out
}

func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
