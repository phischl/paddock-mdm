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
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/buildinfo"
	"github.com/phischl/paddock-mdm/agent/internal/client"
	"github.com/phischl/paddock-mdm/agent/internal/config"
	"github.com/phischl/paddock-mdm/agent/internal/identity"
	"github.com/phischl/paddock-mdm/agent/internal/paths"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/pkg/protocol"
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

// A brand-new token may not have reached the gateway yet, which then answers invalid_token: the request is retried
// TokenRetries times, TokenRetryDelay apart (30 s in total).
const (
	TokenRetries    = 3
	TokenRetryDelay = 10 * time.Second
)

// Options of one enrollment run.
type Options struct {
	Layout paths.Layout
	// ConfigPath is the enrollment configuration; empty resumes an enrollment started earlier.
	ConfigPath   string
	RemoveConfig bool
	NoWait       bool
	Proxy        string
	// SkipWhenBusy returns ErrBusy instead of waiting while another enrollment holds the enrollment lock.
	SkipWhenBusy bool
	// BusyLogged is kept by the caller of Autoinstalled across attempts, so a skip because of a held lock is logged
	// once and not at every retry; nil logs every skip.
	BusyLogged *bool
	// Method is the enrollment method the request sends: paddockd enroll adopts an installed device, Autoinstalled
	// sets Method(Layout) itself.
	Method string
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
	release, err := lock(ctx, o)
	if err != nil {
		return ExitError, err
	}
	defer release()
	// Loaded under the lock: an enrollment that finished or started meanwhile is resumed, never requested again.
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
	switch {
	case o.ConfigPath != "" && st.EnrollmentID != "" && configGone(o.ConfigPath):
		// The other side of the enrollment lock started this enrollment and removed the configuration meanwhile: resume
		// with what it stored instead of failing on the missing file.
		slog.InfoContext(ctx, "resuming the enrollment started meanwhile", "enrollment_id", st.EnrollmentID)
	case o.ConfigPath != "":
		if token, err = storeConfig(o); err != nil {
			return ExitError, err
		}
	case st.EnrollmentID == "":
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
		id, err := requestEnrollment(ctx, o, c, Request(l, token, key, o.Method))
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

// Autoinstalled enrolls the device with the enrollment configuration the Paddock autoinstall left at
// o.ConfigPath (plan M4b decision 7) and removes it once the enrollment is active or pending; the agent runs this
// at its start, before anything else. It reports false while the configuration is there and the enrollment could
// not be sent or decided (the caller tries again later), true otherwise — also without a configuration and for a
// rejected enrollment.
func Autoinstalled(ctx context.Context, o Options) bool {
	if _, err := os.Stat(o.ConfigPath); errors.Is(err, os.ErrNotExist) {
		return true
	}
	o.RemoveConfig, o.NoWait, o.SkipWhenBusy, o.Method = true, true, true, Method(o.Layout)
	code, err := Run(ctx, o)
	if errors.Is(err, ErrBusy) {
		// A deliberate skip while `paddockd enroll` runs, possibly for hours waiting for approval: no warning.
		if o.BusyLogged == nil || !*o.BusyLogged {
			slog.InfoContext(ctx, "paddockd enroll is enrolling this device; the autoinstall enrollment waits for it")
			if o.BusyLogged != nil {
				*o.BusyLogged = true
			}
		}
		return false
	}
	switch code {
	case ExitActive, ExitPending:
		slog.InfoContext(ctx, "device enrolled with the configuration of the autoinstall", "pending", code == ExitPending)
		return true
	case ExitRejected:
		slog.WarnContext(ctx, "the enrollment of this device was rejected", "error", err)
		return true
	}
	slog.WarnContext(ctx, "enrollment with the configuration of the autoinstall failed; retrying", "error", err)
	return false
}

// Method is the enrollment method of the agent's own enrollment (plan M11 amendment R6.5): autoinstall only with the
// marker that only the Paddock autoinstall writes, adopted otherwise — a configuration file alone proves nothing,
// and report-only is the safe default.
func Method(l paths.Layout) string {
	if _, err := os.Stat(l.AutoinstallMarker()); err == nil {
		return protocol.EnrollmentAutoinstall
	}
	return protocol.EnrollmentAdopted
}

// ErrBusy reports that another enrollment of this device holds the enrollment lock.
var ErrBusy = errors.New("another enrollment of this device is running")

// LockRetry is the interval at which `paddockd enroll` retries a held enrollment lock.
const LockRetry = 2 * time.Second

// lock takes the enrollment lock shared by `paddockd enroll` and the agent's autoinstall loop, so a device never sends
// two concurrent enrollment requests (plan M11 amendment R6.5). A held lock is ErrBusy with o.SkipWhenBusy; otherwise
// lock says once that it waits and retries every LockRetry through o.Sleep, so cancelling ctx (Ctrl-C) ends the wait
// — a blocking flock would ignore the signal. The lock is released when the returned function closes the file, or
// when the process exits.
func lock(ctx context.Context, o Options) (func(), error) {
	path := o.Layout.EnrollLock()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("enrollment lock: %w", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // fixed path below the state directory
	if err != nil {
		return nil, fmt.Errorf("enrollment lock: %w", err)
	}
	for waiting := false; ; waiting = true {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) //nolint:gosec // a file descriptor fits an int
		switch {
		case err == nil:
			return func() { _ = f.Close() }, nil
		case !errors.Is(err, syscall.EWOULDBLOCK):
			_ = f.Close()
			return nil, fmt.Errorf("enrollment lock: %w", err)
		case o.SkipWhenBusy:
			_ = f.Close()
			return nil, ErrBusy
		}
		if !waiting {
			slog.InfoContext(ctx, "another enrollment of this device is running; waiting")
		}
		if err := o.Sleep(ctx, LockRetry); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("waiting for another enrollment of this device: %w", err)
		}
	}
}

// requestEnrollment sends the enrollment request and retries invalid_token answers.
func requestEnrollment(ctx context.Context, o Options, c *client.Client, req protocol.EnrollRequest) (string, error) {
	for attempt := 0; ; attempt++ {
		id, err := c.Enroll(ctx, req)
		if err == nil || client.Code(err) != protocol.CodeInvalidToken || attempt == TokenRetries {
			return id, err
		}
		slog.WarnContext(ctx, "enrollment token not accepted yet; retrying", "retry_in", TokenRetryDelay)
		if err := o.Sleep(ctx, TokenRetryDelay); err != nil {
			return "", err
		}
	}
}

// storeConfig validates the enrollment configuration and writes agent.yml, trust.json and revoke-trust.json. It
// returns the token.
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
	// The revocation trust anchor comes only from here, never from a bundle; a re-enrollment replaces a key pinned
	// on first use (plan M4c decision 3). A configuration created before M4c has none.
	if len(ec.RevocationKeys) > 0 {
		if err := config.SaveRevokeTrust(o.Layout.RevokeTrust(), ec.RevocationKeys); err != nil {
			return "", err
		}
	}
	return ec.Token, nil
}

// configGone reports whether the enrollment configuration at path no longer exists.
func configGone(path string) bool {
	_, err := os.Stat(path)
	return errors.Is(err, os.ErrNotExist)
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

// Request describes this device for POST /v1/enroll; method is the enrollment method ("" for none).
func Request(l paths.Layout, token string, key identity.Key, method string) protocol.EnrollRequest {
	host, _ := os.Hostname()
	return protocol.EnrollRequest{
		Token: token, PublicKey: base64.StdEncoding.EncodeToString(key.SPKI), KeyProtection: protocol.KeyProtectionFile,
		Hostname: host, HardwareUUID: firstLine(l.Join("/sys/class/dmi/id/product_uuid")),
		MachineID: firstLine(l.Join("/etc/machine-id")), OSRelease: osRelease(l.Join("/etc/os-release")),
		AgentVersion: buildinfo.Version, EnrollmentMethod: method,
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
