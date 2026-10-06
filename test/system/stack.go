package system

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/test/acceptance/portal"
)

// guestHosts are the stack's hostnames, which the guest reaches on the host as 10.0.2.2.
const guestHosts = "10.0.2.2 device.paddock.localhost bundles.paddock.localhost admin.paddock.localhost auth.paddock.localhost"

// Stack is the development stack as the system tests use it.
type Stack struct {
	t     *testing.T
	root  string // repository root
	alice *portal.Session
}

func newStack(t *testing.T) *Stack {
	t.Helper()
	root, err := portal.RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	s := &Stack{t: t, root: root}
	s.Login()
	return s
}

// Login (re)signs in alice, e.g. after the stack was restarted.
func (s *Stack) Login() {
	s.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var err error
	if s.alice, err = portal.Login(ctx, portal.Alice); err != nil {
		s.t.Fatalf("login alice (run make dev-seed): %v", err)
	}
}

// StepUp runs a step-up authentication of alice's session (plan M4a decision 6), e.g. before assigning a full
// profile.
func (s *Stack) StepUp() {
	s.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	final, err := s.alice.StepUp(ctx, portal.Alice, "/")
	if err != nil || strings.Contains(final, "stepup=failed") {
		s.t.Fatalf("step-up of alice: %v (returned to %s)", err, final)
	}
}

// Call sends an admin API request as alice and expects status.
func (s *Stack) Call(method, path string, body any, status int) portal.Response {
	s.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	res, err := s.alice.Do(ctx, method, path, body)
	if err != nil || res.Status != status {
		s.t.Fatalf("%s %s: HTTP %d (want %d) %v %s", method, path, res.Status, status, err, res.Body)
	}
	return res
}

// DeleteOnCleanup deletes the device group, managed file or unit at path when the test ends; a resource the test
// deleted itself is fine (plan M2.2 decision 7).
func (s *Stack) DeleteOnCleanup(path string) {
	s.t.Cleanup(func() { s.cleanupCall(http.MethodDelete, path, http.StatusNoContent, http.StatusNotFound) })
}

// RevokeOnCleanup revokes an enrollment token when the test ends (tokens cannot be deleted; revoking is
// idempotent).
func (s *Stack) RevokeOnCleanup(tokenID string) {
	s.t.Cleanup(func() {
		s.cleanupCall(http.MethodPost, "/api/v1/enrollment-tokens/"+tokenID+"/revoke", http.StatusOK)
	})
}

// cleanupCall sends a cleanup request as alice and reports, without stopping, a status other than ok. It signs in
// again once if the session ended, e.g. after a gate restarted the stack.
func (s *Stack) cleanupCall(method, path string, ok ...int) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	res, err := s.alice.Do(ctx, method, path, nil)
	if err == nil && res.Status == http.StatusUnauthorized {
		s.Login()
		res, err = s.alice.Do(ctx, method, path, nil)
	}
	if err != nil || !slices.Contains(ok, res.Status) {
		s.t.Errorf("cleanup: %s %s: HTTP %d %v %s", method, path, res.Status, err, res.Body)
	}
}

// ID decodes the id of a created resource.
func (s *Stack) ID(res portal.Response) string {
	s.t.Helper()
	var v struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(res.Body, &v); err != nil || v.ID == "" {
		s.t.Fatalf("no id in %s", res.Body)
	}
	return v.ID
}

// Events returns the audit events of code whose target is the device, oldest first.
func (s *Stack) Events(code, deviceID string) []portal.AuditEvent {
	s.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	all, err := s.alice.AuditEvents(ctx, code)
	if err != nil {
		s.t.Fatal(err)
	}
	var out []portal.AuditEvent
	for i := len(all) - 1; i >= 0; i-- {
		if e := all[i]; e.Target != nil && e.Target.ID == deviceID {
			out = append(out, e)
		}
	}
	return out
}

// Until polls cond every interval until it holds; tick runs before each poll (e.g. to trigger a check-in).
func Until(t *testing.T, what string, timeout, interval time.Duration, tick func(), cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if tick != nil {
			tick()
		}
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: not reached within %s", what, timeout)
		}
		time.Sleep(interval)
	}
}

// Make runs a make target in the repository root.
func (s *Stack) Make(args ...string) {
	s.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "make", args...)
	cmd.Dir = s.root
	if out, err := cmd.CombinedOutput(); err != nil {
		s.t.Fatalf("make %s: %v\n%s", strings.Join(args, " "), err, tail(out))
	}
}

func tail(b []byte) string {
	if len(b) > 4000 {
		b = b[len(b)-4000:]
	}
	return string(b)
}

// Release builds paddockd version with the paddock_dev tag (plus extra tags), uploads it signed with the
// development release key and starts a rollout to all devices with the given extra agentrelease flags; running
// rollouts are halted first.
func (s *Stack) Release(version string, tags []string, flags ...string) string {
	s.t.Helper()
	bin := s.BuildAgent(version, tags)
	args := append([]string{"--version", version, "--artifact", "amd64=" + bin, "--rollout", "--halt-running",
		"--waves", "100", "--min-wave-minutes", "1"}, flags...)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, agentRelease(s.root), args...)
	cmd.Dir = s.root
	if out, err := cmd.CombinedOutput(); err != nil {
		s.t.Fatalf("agentrelease %s: %v\n%s", version, err, out)
	}
	return bin
}

// BuildAgent builds a static linux/amd64 paddockd with the paddock_dev tag and returns its path.
func (s *Stack) BuildAgent(version string, tags []string) string {
	s.t.Helper()
	bin := filepath.Join(s.t.TempDir(), "paddockd-"+version)
	cmd := exec.Command("go", "build", "-trimpath", "-tags", strings.Join(append([]string{"paddock_dev"}, tags...), ","),
		"-ldflags", "-s -w -X github.com/phischl/paddock-mdm/agent/internal/buildinfo.Version="+version,
		"-o", bin, "./agent/cmd/paddockd")
	cmd.Dir = s.root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if out, err := cmd.CombinedOutput(); err != nil {
		s.t.Fatalf("build paddockd %s: %v\n%s", version, err, out)
	}
	return bin
}

func agentRelease(root string) string {
	if p := os.Getenv("PADDOCK_SYSTEM_AGENTRELEASE"); p != "" {
		return p
	}
	return filepath.Join(root, "bin", "agentrelease")
}

// Rollout reads the rollout of version as the platform administrator.
func (s *Stack) Rollout(version string) (status string) {
	s.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	root, err := portal.Login(ctx, portal.PlatformAdmin)
	if err != nil {
		s.t.Fatal(err)
	}
	res, err := root.Do(ctx, http.MethodGet, "/api/platform/v1/agent-releases/"+version, nil)
	if err != nil || res.Status != http.StatusOK {
		s.t.Fatalf("release %s: %v %s", version, err, res.Body)
	}
	var d struct {
		Rollout *struct {
			Status string `json:"status"`
		} `json:"rollout"`
	}
	_ = json.Unmarshal(res.Body, &d)
	if d.Rollout == nil {
		return ""
	}
	return d.Rollout.Status
}

// unique returns a short unique suffix for names of this run.
func unique() string { return uuid.NewString()[:8] }

// version returns a release version unique to this run.
func version(minor int, label string) string {
	return fmt.Sprintf("0.%d.%d-%s", minor, time.Now().Unix(), label)
}
