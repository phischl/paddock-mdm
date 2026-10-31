package enroll_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/client"
	"github.com/phischl/paddock-mdm/agent/internal/config"
	"github.com/phischl/paddock-mdm/agent/internal/enroll"
	"github.com/phischl/paddock-mdm/agent/internal/identity"
	"github.com/phischl/paddock-mdm/agent/internal/paths"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/agent/internal/testgw"
	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/pkg/revocation"
)

type fixture struct {
	g       *testgw.Gateway
	layout  paths.Layout
	cfgPath string
	sleeps  []time.Duration
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{g: testgw.New(t), layout: paths.Layout{Root: t.TempDir()}}
	f.cfgPath = filepath.Join(t.TempDir(), "enroll.json")
	data, _ := json.Marshal(f.g.EnrollmentConfig())
	if err := os.WriteFile(f.cfgPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) options(configPath string) enroll.Options {
	return enroll.Options{
		Layout: f.layout, ConfigPath: configPath, RemoveConfig: true,
		Sleep: func(ctx context.Context, d time.Duration) error {
			f.sleeps = append(f.sleeps, d)
			return ctx.Err()
		},
		NewClient: func(_ config.Agent, key identity.Key) (*client.Client, error) { return f.g.Client(key), nil },
	}
}

func (f *fixture) setStatus(s protocol.EnrollStatus) {
	f.g.Mu.Lock()
	f.g.EnrollStatus = s
	f.g.Mu.Unlock()
}

func TestEnrollPendingThenResume(t *testing.T) {
	f := newFixture(t)
	f.setStatus(protocol.EnrollStatus{Status: protocol.EnrollPending, DeviceID: testgw.DeviceID})
	o := f.options(f.cfgPath)
	o.NoWait = true
	code, err := enroll.Run(context.Background(), o)
	if err != nil || code != enroll.ExitPending {
		t.Fatalf("first run: %d, %v; want pending", code, err)
	}
	if _, err := os.Stat(f.cfgPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("--remove-config left the enrollment configuration in place")
	}
	keyBefore, _ := identity.Load(f.layout.IdentityKey())

	// The administrator approves; re-running without --config resumes with the same key and enrollment ID.
	f.setStatus(protocol.EnrollStatus{Status: protocol.EnrollActive, DeviceID: testgw.DeviceID})
	code, err = enroll.Run(context.Background(), f.options(""))
	if err != nil || code != enroll.ExitActive {
		t.Fatalf("resume: %d, %v; want active", code, err)
	}
	keyAfter, _ := identity.Load(f.layout.IdentityKey())
	if len(f.g.Enrolls) != 1 || keyBefore.KeyID != keyAfter.KeyID {
		t.Fatalf("resume sent %d enrollment requests, key %s → %s", len(f.g.Enrolls), keyBefore.KeyID, keyAfter.KeyID)
	}
	st, _ := state.Load(f.layout.State())
	if st.Status != state.StatusActive || st.DeviceID != testgw.DeviceID {
		t.Fatalf("state %+v", st)
	}
	cfg, err := config.LoadAgent(f.layout.AgentConfig())
	if err != nil || cfg.ServerURL != f.g.URL || cfg.OrganizationID != testgw.OrgID {
		t.Fatalf("agent.yml: %+v, %v", cfg, err)
	}
	if _, err := config.LoadTrust(f.layout.Trust()); err != nil {
		t.Fatalf("trust.json: %v", err)
	}
	if data, err := os.ReadFile(f.layout.RevokeTrust()); err != nil {
		t.Fatalf("revoke-trust.json: %v", err)
	} else if tr, err := revocation.ParseTrust(data); err != nil || tr.Keys["revocation-signing:v1"] == nil {
		t.Fatalf("revoke-trust.json: %v %v", tr, err)
	}
	req := f.g.Enrolls[0]
	if req.Token != "secret-token" || req.KeyProtection != protocol.KeyProtectionFile || req.Hostname == "" {
		t.Fatalf("enroll request %+v", req)
	}
	// Already active: a third run succeeds without contacting the server.
	if code, err := enroll.Run(context.Background(), f.options("")); code != enroll.ExitActive || err != nil {
		t.Fatalf("third run: %d, %v", code, err)
	}
}

func TestEnrollBackoff(t *testing.T) {
	f := newFixture(t)
	f.setStatus(protocol.EnrollStatus{Status: protocol.EnrollPending})
	o := f.options(f.cfgPath)
	polls := 0
	o.Sleep = func(ctx context.Context, d time.Duration) error {
		f.sleeps = append(f.sleeps, d)
		if polls++; polls == 9 {
			f.setStatus(protocol.EnrollStatus{Status: protocol.EnrollActive, DeviceID: testgw.DeviceID})
		}
		return nil
	}
	if code, err := enroll.Run(context.Background(), o); code != enroll.ExitActive || err != nil {
		t.Fatalf("%d, %v", code, err)
	}
	want := []time.Duration{0, 10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second, 160 * time.Second, 5 * time.Minute, 5 * time.Minute, 5 * time.Minute}
	if len(f.sleeps) != len(want) {
		t.Fatalf("sleeps %v", f.sleeps)
	}
	for i := range want {
		if f.sleeps[i] != want[i] {
			t.Fatalf("sleeps %v, want %v", f.sleeps, want)
		}
	}
}

func TestEnrollRejected(t *testing.T) {
	f := newFixture(t)
	f.setStatus(protocol.EnrollStatus{Status: protocol.EnrollRejected, Reason: "token_exhausted"})
	code, err := enroll.Run(context.Background(), f.options(f.cfgPath))
	if code != enroll.ExitRejected || err != nil {
		t.Fatalf("%d, %v; want rejected", code, err)
	}
	if _, err := os.Stat(f.cfgPath); err != nil {
		t.Fatal("a rejected enrollment must keep the configuration file")
	}
	if code, _ := enroll.Run(context.Background(), f.options(f.cfgPath)); code != enroll.ExitRejected {
		t.Fatalf("re-run after rejection: %d", code)
	}
}

func TestEnrollInterrupted(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	o := f.options(f.cfgPath)
	o.Sleep = func(ctx context.Context, d time.Duration) error {
		if d > 0 {
			cancel()
		}
		return ctx.Err()
	}
	if code, err := enroll.Run(ctx, o); code != enroll.ExitError || err == nil {
		t.Fatalf("%d, %v; want error", code, err)
	}
	st, _ := state.Load(f.layout.State())
	if st.EnrollmentID == "" {
		t.Fatal("enrollment ID not persisted before polling")
	}
}

func TestEnrollErrors(t *testing.T) {
	f := newFixture(t)
	if code, err := enroll.Run(context.Background(), f.options("")); code != enroll.ExitError || err == nil {
		t.Fatalf("no config: %d, %v", code, err)
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	_ = os.WriteFile(bad, []byte(`{"server_url":"http://x"}`), 0o600)
	if code, err := enroll.Run(context.Background(), f.options(bad)); code != enroll.ExitError || !errors.Is(err, config.ErrEnrollmentConfig) {
		t.Fatalf("invalid config: %d, %v", code, err)
	}
	// An enrollment the server does not know any more (404) is an error, not an endless wait.
	_ = state.Save(f.layout.State(), state.State{EnrollmentID: "0190f000-0000-7000-8000-0000000000ff"})
	if code, err := enroll.Run(context.Background(), f.options(f.cfgPath)); code != enroll.ExitError || err == nil {
		t.Fatalf("unknown enrollment: %d, %v", code, err)
	}
}

// TestEnrollRetriesNewToken: a token the gateway does not know yet (invalid_token) is retried TokenRetries times,
// TokenRetryDelay apart; after that the enrollment fails.
func TestEnrollRetriesNewToken(t *testing.T) {
	f := newFixture(t)
	f.g.EnrollFail = enroll.TokenRetries
	f.setStatus(protocol.EnrollStatus{Status: protocol.EnrollActive, DeviceID: testgw.DeviceID})
	if code, err := enroll.Run(context.Background(), f.options(f.cfgPath)); code != enroll.ExitActive || err != nil {
		t.Fatalf("%d, %v", code, err)
	}
	if len(f.g.Enrolls) != 1 || len(f.sleeps) < enroll.TokenRetries {
		t.Fatalf("enrolls %d, sleeps %v", len(f.g.Enrolls), f.sleeps)
	}
	for _, d := range f.sleeps[:enroll.TokenRetries] {
		if d != enroll.TokenRetryDelay {
			t.Fatalf("sleeps %v", f.sleeps)
		}
	}

	f = newFixture(t)
	f.g.EnrollFail = enroll.TokenRetries + 1
	code, err := enroll.Run(context.Background(), f.options(f.cfgPath))
	if code != enroll.ExitError || client.Code(err) != protocol.CodeInvalidToken || len(f.sleeps) != enroll.TokenRetries {
		t.Fatalf("%d, %v, sleeps %v", code, err, f.sleeps)
	}
	if st, _ := state.Load(f.layout.State()); st.EnrollmentID != "" {
		t.Fatalf("state %+v after a refused token", st)
	}
}

func TestAutoinstalled(t *testing.T) {
	f := newFixture(t)
	o := f.options(f.layout.EnrollConfig())
	if !enroll.Autoinstalled(context.Background(), o) || len(f.g.Enrolls) != 0 {
		t.Fatal("without a configuration there is nothing to do")
	}
	data, err := os.ReadFile(f.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(o.ConfigPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(o.ConfigPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	// The server refuses the request: the configuration stays for the next attempt.
	f.g.EnrollFail = enroll.TokenRetries + 1
	if enroll.Autoinstalled(context.Background(), o) {
		t.Fatal("a failed enrollment reported done")
	}
	if _, err := os.Stat(o.ConfigPath); err != nil {
		t.Fatalf("configuration removed after a failure: %v", err)
	}
	f.setStatus(protocol.EnrollStatus{Status: protocol.EnrollActive, DeviceID: testgw.DeviceID})
	if !enroll.Autoinstalled(context.Background(), o) {
		t.Fatal("enrollment not done")
	}
	if _, err := os.Stat(o.ConfigPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("configuration kept after the enrollment: %v", err)
	}
	if st, _ := state.Load(f.layout.State()); st.Status != state.StatusActive {
		t.Fatalf("state %+v", st)
	}
}

// TestEnrollmentMethod (plan M11 decision 10, amendment R6.5): the request carries the method of Options —
// paddockd enroll adopts an installed device — and without a method the field is left out, as by an agent of an
// earlier release.
func TestEnrollmentMethod(t *testing.T) {
	f := newFixture(t)
	f.setStatus(protocol.EnrollStatus{Status: protocol.EnrollActive, DeviceID: testgw.DeviceID})
	o := f.options(f.cfgPath)
	o.Method = protocol.EnrollmentAdopted
	if code, err := enroll.Run(context.Background(), o); err != nil || code != enroll.ExitActive {
		t.Fatalf("enroll: %d, %v", code, err)
	}
	if len(f.g.Enrolls) != 1 || f.g.Enrolls[0].EnrollmentMethod != protocol.EnrollmentAdopted {
		t.Fatalf("enroll requests %+v", f.g.Enrolls)
	}

	key, err := identity.LoadOrCreate(filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(enroll.Request(f.layout, "secret", key, ""))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "enrollment_method") {
		t.Fatalf("request without a method: %s", raw)
	}
}

// TestAutoinstalledMethod (plan M11 amendment R6.5): the agent's own enrollment sends autoinstall only on a device
// with the marker of the autoinstall; a configuration at the daemon's path alone gives adopted (fail safe), also next
// to a disk setup configuration, which the disk conversion writes on adopted devices too, and whatever the caller
// asked for.
func TestAutoinstalledMethod(t *testing.T) {
	for _, tc := range []struct {
		name   string
		marker bool
		want   string
	}{
		{"configuration without the autoinstall marker", false, protocol.EnrollmentAdopted},
		{"autoinstalled device", true, protocol.EnrollmentAutoinstall},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.setStatus(protocol.EnrollStatus{Status: protocol.EnrollActive, DeviceID: testgw.DeviceID})
			o := f.options(f.layout.EnrollConfig())
			o.Method = protocol.EnrollmentAutoinstall
			data, err := os.ReadFile(f.cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(o.ConfigPath), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(o.ConfigPath, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f.layout.DiskSetupConfig(), []byte("{\"boot_pin_min_length\":8}\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if tc.marker {
				if err := os.WriteFile(f.layout.AutoinstallMarker(), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if !enroll.Autoinstalled(context.Background(), o) || len(f.g.Enrolls) != 1 || f.g.Enrolls[0].EnrollmentMethod != tc.want {
				t.Fatalf("enroll requests %+v, want %s", f.g.Enrolls, tc.want)
			}
		})
	}
}

// holdLock takes the enrollment lock like a second process would (flock locks belong to the open file, so a second
// open of the same file conflicts even within this process).
func holdLock(t *testing.T, l paths.Layout) func() {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(l.EnrollLock()), 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(l.EnrollLock(), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	return func() { _ = f.Close() }
}

// TestEnrollmentLock (plan M11 amendment R6.5): while another enrollment holds the lock, the agent's autoinstall
// loop skips without a request and keeps the configuration, and `paddockd enroll` waits; after the lock, both re-read
// the state, so an enrollment the other one started is resumed and never requested a second time.
func TestEnrollmentLock(t *testing.T) {
	f := newFixture(t)
	f.setStatus(protocol.EnrollStatus{Status: protocol.EnrollPending, DeviceID: testgw.DeviceID})
	o := f.options(f.layout.EnrollConfig())
	data, err := os.ReadFile(f.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(o.ConfigPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(o.ConfigPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	release := holdLock(t, f.layout)
	var busyLogged bool
	o.BusyLogged = &busyLogged
	if enroll.Autoinstalled(context.Background(), o) || len(f.g.Enrolls) != 0 || !busyLogged {
		t.Fatalf("autoinstall loop while the lock was held: %d requests, busy logged %v", len(f.g.Enrolls), busyLogged)
	}
	if _, err := os.Stat(o.ConfigPath); err != nil {
		t.Fatalf("configuration removed while busy: %v", err)
	}
	cli := f.options(f.cfgPath)
	cli.NoWait, cli.Sleep = true, shortSleep
	done := make(chan int, 1)
	go func() {
		code, _ := enroll.Run(context.Background(), cli)
		done <- code
	}()
	select {
	case code := <-done:
		t.Fatalf("paddockd enroll did not wait for the lock: exit %d", code)
	case <-time.After(200 * time.Millisecond):
	}
	release()
	if code := <-done; code != enroll.ExitPending || len(f.g.Enrolls) != 1 {
		t.Fatalf("paddockd enroll after the lock: exit %d, %d requests", code, len(f.g.Enrolls))
	}

	// The autoinstall loop now finds the pending enrollment of paddockd enroll and resumes it.
	f.setStatus(protocol.EnrollStatus{Status: protocol.EnrollActive, DeviceID: testgw.DeviceID})
	if !enroll.Autoinstalled(context.Background(), o) || len(f.g.Enrolls) != 1 {
		t.Fatalf("autoinstall loop after paddockd enroll: %d requests", len(f.g.Enrolls))
	}
}

// shortSleep waits briefly instead of the given duration, so a lock wait retries quickly in tests.
func shortSleep(ctx context.Context, _ time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Millisecond):
		return nil
	}
}

// TestEnrollmentLockWaitIsInterruptible: `paddockd enroll` waiting for a held lock ends with a clear error when its
// context is cancelled (Ctrl-C), without a request.
func TestEnrollmentLockWaitIsInterruptible(t *testing.T) {
	f := newFixture(t)
	release := holdLock(t, f.layout)
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	cli := f.options(f.cfgPath)
	waits := 0
	cli.Sleep = func(ctx context.Context, d time.Duration) error {
		if d != enroll.LockRetry {
			t.Errorf("lock retry after %v", d)
		}
		if waits++; waits == 3 {
			cancel()
		}
		return ctx.Err()
	}
	code, err := enroll.Run(ctx, cli)
	if code != enroll.ExitError || !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "another enrollment") || waits != 3 {
		t.Fatalf("cancelled wait: exit %d, %v after %d waits", code, err, waits)
	}
	if len(f.g.Enrolls) != 0 {
		t.Fatalf("%d enrollment requests", len(f.g.Enrolls))
	}
}

// pendingEnrollment starts an enrollment that waits for approval and removes its configuration.
func pendingEnrollment(t *testing.T, f *fixture) {
	t.Helper()
	f.setStatus(protocol.EnrollStatus{Status: protocol.EnrollPending, DeviceID: testgw.DeviceID})
	o := f.options(f.cfgPath)
	o.NoWait = true
	if code, err := enroll.Run(context.Background(), o); code != enroll.ExitPending || err != nil {
		t.Fatalf("first run: %d, %v", code, err)
	}
	if _, err := os.Stat(f.cfgPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("configuration not removed")
	}
	f.setStatus(protocol.EnrollStatus{Status: protocol.EnrollActive, DeviceID: testgw.DeviceID})
}

// TestResumeWithoutConfiguration: when the configuration is gone because the other side of the lock started the
// enrollment and removed it — on the agent's own path, or while `paddockd enroll` waited for the lock — the
// enrollment is resumed instead of failing on the file.
func TestResumeWithoutConfiguration(t *testing.T) {
	t.Run("agent's own path", func(t *testing.T) {
		f := newFixture(t)
		pendingEnrollment(t, f)
		o := f.options(f.cfgPath)
		o.SkipWhenBusy = true
		if code, err := enroll.Run(context.Background(), o); code != enroll.ExitActive || err != nil || len(f.g.Enrolls) != 1 {
			t.Fatalf("resume: %d, %v, %d requests", code, err, len(f.g.Enrolls))
		}
	})
	t.Run("removed while paddockd enroll waited", func(t *testing.T) {
		f := newFixture(t)
		data, err := os.ReadFile(f.cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		pendingEnrollment(t, f)
		if err := os.WriteFile(f.cfgPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
		release := holdLock(t, f.layout)
		cli := f.options(f.cfgPath)
		cli.Sleep = func(ctx context.Context, _ time.Duration) error {
			if err := os.Remove(f.cfgPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Error(err)
			}
			release()
			return ctx.Err()
		}
		if code, err := enroll.Run(context.Background(), cli); code != enroll.ExitActive || err != nil || len(f.g.Enrolls) != 1 {
			t.Fatalf("resume: %d, %v, %d requests", code, err, len(f.g.Enrolls))
		}
	})
}

// TestMissingConfigurationFailsWhilePending: a mistyped or missing --config fails with the file error, also while an
// enrollment is pending; it is never taken as a resume.
func TestMissingConfigurationFailsWhilePending(t *testing.T) {
	f := newFixture(t)
	pendingEnrollment(t, f)
	code, err := enroll.Run(context.Background(), f.options(f.cfgPath))
	if code != enroll.ExitError || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing --config: %d, %v", code, err)
	}
	if st, _ := state.Load(f.layout.State()); st.Status == state.StatusActive {
		t.Fatal("resumed with a missing configuration")
	}
}
