package acceptance

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// hostRolloutActor is the system actor of the host commands (plan M7b decision 31).
const hostRolloutActor = "paddock-server admin"

// hostRollout runs paddock-server admin <args> in a one-off paddock-api container, as ./paddock agent-rollout and
// ./paddock agent-rollout-halt do. It returns the combined output and whether the command succeeded.
func hostRollout(t *testing.T, args ...string) (string, bool) {
	t.Helper()
	out, err := stack.Compose(testContext(t, 5*time.Minute), nil,
		append([]string{"run", "--rm", "--no-deps", "-T", "paddock-api", "admin"}, args...)...)
	return out, err == nil
}

// hostRolloutJSON decodes the rollout the command printed on stdout (the JSON log lines on stderr are single lines).
func hostRolloutJSON(t *testing.T, out string) map[string]any {
	t.Helper()
	i := strings.Index(out, "{\n")
	if i < 0 {
		t.Fatalf("no rollout JSON in the output:\n%s", out)
	}
	var r map[string]any
	if err := json.NewDecoder(strings.NewReader(out[i:])).Decode(&r); err != nil {
		t.Fatalf("rollout JSON: %v\n%s", err, out)
	}
	return r
}

// expectHostRefusal expects the host command to fail with the API's problem code and one failed audit event of the
// host actor.
func expectHostRefusal(t *testing.T, idx *env.AuditIndex, code, problemCode, version string, args ...string) {
	t.Helper()
	out, ok := hostRollout(t, args...)
	if ok || !strings.Contains(out, "refused: problem "+problemCode+":") {
		t.Fatalf("paddock-server admin %s: succeeded=%v, want the problem %s:\n%s", strings.Join(args, " "), ok, problemCode, out)
	}
	ev := expectOneIndexEvent(t, idx, platformOrg, "code = '"+code+"' AND outcome = 'failure' AND params->>'version' = $1",
		version, code, "failure", auditPollTimeout)
	if ev.ActorDisplay != hostRolloutActor {
		t.Fatalf("%s failure event of %s: actor %q, want %q", code, version, ev.ActorDisplay, hostRolloutActor)
	}
}

// TestAgentRolloutFromHost is the gate of the ADR 0034 amendment 2026-10-26 (PDK-449): the host commands start a
// rollout of a published release with the default waves and halt it, each with exactly one audit event of the system
// actor; an unpublished release, a release whose rollout runs, another running rollout and invalid waves are refused
// with the API's problem codes.
func TestAgentRolloutFromHost(t *testing.T) {
	root, idx := login(t, env.PlatformAdmin), auditIndex(t)
	haltRunningRollouts(t, root)
	t.Cleanup(func() { haltRunningRollouts(t, root) })

	// 1. An unpublished release is refused.
	draft := gateRelease(t, root, true, false)
	expectHostRefusal(t, idx, "agent_rollout.started", "invalid_state", draft, "agent-rollout", "--version", draft)

	// 2. Invalid waves are refused by the use case, as the API refuses them (a release of its own: the audit queries
	// tell the refusals apart by version).
	invalid := gateRelease(t, root, true, true)
	expectHostRefusal(t, idx, "agent_rollout.started", "invalid_request", invalid, "agent-rollout", "--version", invalid, "--waves", "50,10")

	// 3. The rollout starts with the default waves; the portal shows it as running.
	v := gateRelease(t, root, true, true)
	out, ok := hostRollout(t, "agent-rollout", "--version", v)
	if !ok {
		t.Fatalf("agent-rollout %s:\n%s", v, out)
	}
	r := hostRolloutJSON(t, out)
	waves, _ := json.Marshal(r["waves"])
	if r["version"] != v || r["status"] != "running" || string(waves) != "[1,10,50,100]" || r["started_by"] != hostRolloutActor {
		t.Fatalf("started rollout: %v", r)
	}
	ev := expectOneIndexEvent(t, idx, platformOrg, "code = 'agent_rollout.started' AND outcome = 'success' AND params->>'version' = $1",
		v, "agent_rollout.started", "success", auditPollTimeout)
	if ev.ActorDisplay != hostRolloutActor {
		t.Fatalf("agent_rollout.started actor %q, want %q", ev.ActorDisplay, hostRolloutActor)
	}
	var detail struct {
		Rollout *struct {
			Status string `json:"status"`
			Waves  []int  `json:"waves"`
		} `json:"rollout"`
	}
	res := call(t, root, http.MethodGet, "/api/platform/v1/agent-releases/"+v, nil)
	expectStatus(t, res, http.StatusOK, "")
	if err := res.JSON(&detail); err != nil || detail.Rollout == nil || detail.Rollout.Status != "running" ||
		!slices.Equal(detail.Rollout.Waves, []int{1, 10, 50, 100}) {
		t.Fatalf("the portal's release detail after the host start: %s", res.Body)
	}

	// 4. A release whose rollout runs, and another release while it runs, are refused.
	expectHostRefusal(t, idx, "agent_rollout.started", "already_exists", v, "agent-rollout", "--version", v)
	other := gateRelease(t, root, true, true)
	expectHostRefusal(t, idx, "agent_rollout.started", "invalid_state", other, "agent-rollout", "--version", other)

	// 5. The halt stops it with one audit event of the host actor; a second halt is refused.
	out, ok = hostRollout(t, "agent-rollout-halt", "--version", v)
	if !ok {
		t.Fatalf("agent-rollout-halt %s:\n%s", v, out)
	}
	if r := hostRolloutJSON(t, out); r["status"] != "halted" || r["halted_reason"] == nil {
		t.Fatalf("halted rollout: %v", r)
	}
	ev = expectOneIndexEvent(t, idx, platformOrg, "code = 'agent_rollout.halted' AND outcome = 'success' AND params->>'version' = $1",
		v, "agent_rollout.halted", "success", auditPollTimeout)
	if ev.ActorDisplay != hostRolloutActor {
		t.Fatalf("agent_rollout.halted actor %q, want %q", ev.ActorDisplay, hostRolloutActor)
	}
	expectHostRefusal(t, idx, "agent_rollout.halted", "invalid_state", v, "agent-rollout-halt", "--version", v)
}
