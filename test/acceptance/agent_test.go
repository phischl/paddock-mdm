package acceptance

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/paddock-mdm/paddock/test/acceptance/internal/env"
	"github.com/paddock-mdm/paddock/test/acceptance/internal/stack"
)

// paddockd builds the agent once per test into a temporary directory.
func paddockd(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "paddockd")
	out, err := exec.Command("go", "build", "-o", bin, "github.com/paddock-mdm/paddock/agent/cmd/paddockd").CombinedOutput()
	if err != nil {
		t.Fatalf("build paddockd: %v\n%s", err, out)
	}
	return bin
}

// agentCmd runs paddockd with a temporary root against the dev stack (the agent trusts the Caddy CA through
// SSL_CERT_FILE, as a device trusts it through its system store).
func agentCmd(t *testing.T, ctx context.Context, bin, root string, args ...string) *exec.Cmd {
	t.Helper()
	dir, err := stack.SecretsDir()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, bin, append([]string{"--root", root}, args...)...)
	cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+filepath.Join(dir, "caddy-root.crt"))
	return cmd
}

func writeEnrollmentConfig(t *testing.T, tok createdToken) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "enroll.json")
	data, _ := json.Marshal(tok.EnrollmentConfig)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func exitCode(err error) int {
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	if err != nil {
		return -1
	}
	return 0
}

type agentState struct {
	DeviceID string `json:"device_id"`
	Status   string `json:"status"`
	Seq      int64  `json:"seq"`
}

func readAgentState(t *testing.T, root string) agentState {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "var/lib/paddock/state/state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var s agentState
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// TestAgentEnrollmentAndCheckin is the integration test of plan M2b step 1: paddockd enrolls against the running
// stack (pending, approval, resume with the same key), then `paddockd run` checks in and serves its health socket.
func TestAgentEnrollmentAndCheckin(t *testing.T) {
	alice := login(t, env.Alice)
	bin := paddockd(t)
	root := t.TempDir()
	cfg := writeEnrollmentConfig(t, createToken(t, alice, tokenOptions{}))
	ctx := testContext(t, 5*time.Minute)

	out, err := agentCmd(t, ctx, bin, root, "enroll", "--config", cfg, "--remove-config", "--no-wait").CombinedOutput()
	if code := exitCode(err); code != 2 {
		t.Fatalf("enroll without approval: exit %d, want 2 (pending)\n%s", code, out)
	}
	if _, err := os.Stat(cfg); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("--remove-config left the enrollment configuration in place")
	}
	pending := readAgentState(t, root)
	if pending.Status != "pending" || pending.DeviceID == "" {
		t.Fatalf("state after pending enrollment: %+v", pending)
	}
	expectStatus(t, call(t, alice, http.MethodPost, "/api/v1/devices/"+pending.DeviceID+"/approve", nil), http.StatusOK, "")

	// Resume without the configuration file: same key, same enrollment.
	out, err = agentCmd(t, ctx, bin, root, "enroll").CombinedOutput()
	if code := exitCode(err); code != 0 {
		t.Fatalf("resumed enrollment: exit %d\n%s", code, out)
	}
	if s := readAgentState(t, root); s.Status != "active" || s.DeviceID != pending.DeviceID {
		t.Fatalf("state after approval: %+v", s)
	}

	run := agentCmd(t, ctx, bin, root, "run")
	logs, err := os.Create(filepath.Join(t.TempDir(), "run.log"))
	if err != nil {
		t.Fatal(err)
	}
	run.Stdout, run.Stderr = logs, logs
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = run.Process.Kill() })
	waitDevice(t, alice, pending.DeviceID, time.Minute, func(d deviceState) bool { return d.LastContactAt != nil })
	if s := readAgentState(t, root); s.Seq < 1 {
		t.Fatalf("sequence number not persisted: %+v", s)
	}
	health := agentHealth(t, filepath.Join(root, "run/paddock/agent.sock"))
	if health["status"] != "ok" || health["last_checkin_at"] == nil {
		t.Fatalf("health %v", health)
	}
	if err := run.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := run.Wait(); err != nil {
		data, _ := os.ReadFile(logs.Name())
		t.Fatalf("paddockd run did not stop cleanly: %v\n%s", err, data)
	}
}

func agentHealth(t *testing.T, socket string) map[string]any {
	t.Helper()
	hc := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}}
	var out map[string]any
	for range 50 {
		res, err := hc.Get("http://agent/health")
		if err == nil {
			defer func() { _ = res.Body.Close() }()
			if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
				t.Fatal(err)
			}
			return out
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("health socket %s not reachable", socket)
	return nil
}
