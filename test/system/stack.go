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
const guestHosts = "10.0.2.2 device.paddock.localhost bundles.paddock.localhost admin.paddock.localhost auth.paddock.localhost fleet.paddock.localhost"

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

// stepUpRetryAfter is longer than the development stack's maximum auth age of a step-up (PADDOCK_STEPUP_MAX_AUTH_AGE,
// 15 s).
const stepUpRetryAfter = 20 * time.Second

// StepUp runs a step-up authentication of alice's session (plan M4a decision 6), e.g. before assigning a full
// profile. Authentik re-authenticates only a login older than the maximum auth age: a step-up within that age of the
// previous one gets the previous login's auth_time, which the server may find a second too old by the time of the
// callback. A refused step-up is therefore repeated once, after that age.
func (s *Stack) StepUp() {
	s.t.Helper()
	for attempt := 1; ; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		final, err := s.alice.StepUp(ctx, portal.Alice, "/")
		cancel()
		if err == nil && !strings.Contains(final, "stepup=failed") {
			return
		}
		if attempt == 2 {
			s.t.Fatalf("step-up of alice: %v (returned to %s)", err, final)
		}
		s.t.Logf("step-up of alice refused (%v, returned to %s); repeating after %s", err, final, stepUpRetryAfter)
		time.Sleep(stepUpRetryAfter)
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

// Make runs a make target in the repository root. A restart of the stack (down, up) keeps the backup overlay of a
// stack that runs with it (PDK-018).
func (s *Stack) Make(args ...string) {
	s.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	if slices.Contains(args, "down") || slices.Contains(args, "up") {
		args = withBackup(args, os.Getenv, runningComposeFiles(ctx))
	}
	cmd := exec.CommandContext(ctx, "make", args...)
	cmd.Dir = s.root
	if out, err := cmd.CombinedOutput(); err != nil {
		s.t.Fatalf("make %s: %v\n%s", strings.Join(args, " "), err, tail(out))
	}
}

// withBackup adds BACKUP=1 to make arguments when the running stack uses the backup overlay (compose.backup.yaml in
// configFiles) and neither the arguments, the environment nor MAKEFLAGS (make system-test BACKUP=…) set BACKUP:
// `make down` and `make up` without it would drop the overlay, and with it PostgreSQL's archive_command.
func withBackup(args []string, getenv func(string) string, configFiles []string) []string {
	if slices.ContainsFunc(args, func(a string) bool { return strings.HasPrefix(a, "BACKUP=") }) || getenv("BACKUP") != "" ||
		slices.ContainsFunc(strings.Fields(getenv("MAKEFLAGS")), func(f string) bool { return strings.HasPrefix(f, "BACKUP=") }) {
		return args
	}
	if !slices.ContainsFunc(configFiles, func(f string) bool { return filepath.Base(f) == "compose.backup.yaml" }) {
		return args
	}
	return append(slices.Clone(args), "BACKUP=1")
}

// runningComposeFiles are the Compose files of the running project paddock (empty when it is not running).
func runningComposeFiles(ctx context.Context) []string {
	out, err := exec.CommandContext(ctx, "docker", "ps", "-a", "--filter", "label=com.docker.compose.project=paddock",
		"--format", `{{.Label "com.docker.compose.project.config_files"}}`).Output()
	if err != nil {
		return nil
	}
	return strings.FieldsFunc(string(out), func(r rune) bool { return r == ',' || r == '\n' })
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

// InstallRelease builds the packages and paddockd of this tree as a new release (paddock_dev), uploads both and
// rolls the release out to all devices, so that the Paddock autoinstall installs it and no other release replaces
// it; it returns the version. Running rollouts are halted first, and this one when the test ends; bin/deb is rebuilt
// as version 0.1.0 for the other system tests.
func (s *Stack) InstallRelease(t *testing.T) string {
	t.Helper()
	v := version(9, "ai")
	s.Make("deb", "VERSION="+v, "TAGS=paddock_dev", "REVOKE_TAGS=paddock_revoke_testtarget")
	t.Cleanup(func() { s.Make("deb", "VERSION=0.1.0", "TAGS=paddock_dev", "REVOKE_TAGS=paddock_revoke_testtarget") })
	debs, err := filepath.Glob(filepath.Join(s.root, "bin", "deb", "*.deb"))
	if err != nil || len(debs) != 3 {
		t.Fatalf("packages %v: %v", debs, err)
	}
	args := []string{"--version", v, "--artifact", "amd64=" + filepath.Join(s.root, "bin", "agent", "amd64", "paddockd"),
		"--rollout", "--halt-running", "--waves", "100", "--min-wave-minutes", "1"}
	for _, deb := range debs {
		args = append(args, "--deb", deb)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, agentRelease(s.root), args...)
	cmd.Dir = s.root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("agentrelease %s: %v\n%s", v, err, out)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		halt := exec.CommandContext(ctx, agentRelease(s.root), "--version", v, "--halt-running")
		halt.Dir = s.root
		if out, err := halt.CombinedOutput(); err != nil {
			t.Errorf("halt the rollout of %s: %v\n%s", v, err, out)
		}
	})
	return v
}
