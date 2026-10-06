package enroll_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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
