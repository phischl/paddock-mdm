package inventory

import (
	"bytes"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/ports"
)

func TestPolicies(t *testing.T) {
	ps, err := Policies()
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 2 || ps[0].Key != "disk_encrypted" || ps[1].Key != PolicyAgentRunning {
		t.Fatalf("policies %+v", ps)
	}
	agent := ps[1]
	if agent.Query != "SELECT 1 FROM processes WHERE name = 'paddockd' AND path LIKE '/opt/paddock/agent/%';" ||
		agent.Description == "" {
		t.Fatalf("agent policy %+v", agent)
	}
}

func TestSeverity(t *testing.T) {
	for score, want := range map[float64]string{9.8: "critical", 9: "critical", 7.5: "high", 4: "medium", 3.9: "low", 0: ""} {
		if got := Severity(&score); got != want {
			t.Errorf("Severity(%v) = %q, want %q", score, got, want)
		}
	}
	if Severity(nil) != "" {
		t.Error("unknown score rated")
	}
}

// TestAgentBinaryPolicy (plan M5a amendment 2026-11-16, A1): the hashes are sorted and deduplicated into the IN list;
// the key is fixed and the description promises pass or fail only.
func TestAgentBinaryPolicy(t *testing.T) {
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	p := AgentBinaryPolicy([]string{b, a, a})
	want := `SELECT 1 WHERE NOT EXISTS (
  SELECT 1 FROM processes p
  WHERE p.path != ''
    AND (p.name = 'paddockd' OR p.path LIKE '%/paddockd' OR p.path LIKE '%/paddockd (deleted)'
      OR p.path LIKE '/opt/paddock/agent/%'
      OR (p.parent IN (SELECT pid FROM processes
            WHERE path IN ('/usr/sbin/paddock-supervisor', '/usr/sbin/paddock-supervisor (deleted)'))
        AND p.path NOT IN ('/usr/sbin/paddock-supervisor', '/usr/sbin/paddock-supervisor (deleted)')))
    AND COALESCE((SELECT sha256 FROM hash WHERE path = '/proc/' || p.pid || '/exe'),
      (SELECT sha256 FROM hash WHERE path = p.path), '') NOT IN ('` + a + `', '` + b + `'));`
	if p.Query != want {
		t.Fatalf("query\n%s\nwant\n%s", p.Query, want)
	}
	if p.Key != "paddock_agent_binary_known" {
		t.Fatalf("key %q", p.Key)
	}
	if p.Description != "A running Paddock agent process runs a published agent release (plan M5a amendments 2026-11-16, ADR 0056). "+
		"The policy returns pass or fail only, never a hash." {
		t.Fatalf("description %q", p.Description)
	}
}

// TestAgentBinaryPolicyEmpty: with no published hash the policy always passes.
func TestAgentBinaryPolicyEmpty(t *testing.T) {
	for _, hashes := range [][]string{nil, {}} {
		if p := AgentBinaryPolicy(hashes); p.Query != "SELECT 1;" || p.Key != PolicyAgentBinaryKnown {
			t.Fatalf("policy %+v", p)
		}
	}
}

// TestAgentBinaryPolicyDropsInvalidHash: a value that is not 64 lowercase hex digits never reaches the SQL and is
// logged at Error once.
func TestAgentBinaryPolicyDropsInvalidHash(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	a := strings.Repeat("a", 64)
	p := AgentBinaryPolicy([]string{a, "x'; DROP"})
	if strings.Contains(p.Query, "DROP") || p.Query != AgentBinaryPolicy([]string{a}).Query {
		t.Fatalf("query %s", p.Query)
	}
	if n := strings.Count(logs.String(), "level=ERROR"); n != 1 {
		t.Fatalf("%d error logs: %s", n, logs.String())
	}
	if strings.Contains(logs.String(), "DROP") {
		t.Fatalf("the invalid value is logged: %s", logs.String())
	}
	for _, bad := range []string{strings.Repeat("A", 64), strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("g", 64)} {
		if got := KnownAgentHashes([]string{bad}); len(got) != 0 {
			t.Errorf("KnownAgentHashes(%q) = %v", bad, got)
		}
	}
	if got := AgentBinaryPolicy([]string{"x'; DROP"}); got.Query != "SELECT 1;" {
		t.Fatalf("only invalid hashes: %s", got.Query)
	}
}

// TestUnansweredAgentRunningAsFailing (plan M5a amendment 2026-11-16 d, F6): with the gate open the unanswered
// agent-running policy becomes a failing result; with the gate closed nothing changes; other keys never move.
func TestUnansweredAgentRunningAsFailing(t *testing.T) {
	in := ports.HostInventory{Policies: []ports.PolicyResult{{Key: "disk_encrypted", Passing: true}},
		UnansweredPolicies: []string{PolicyAgentBinaryKnown, PolicyAgentRunning, "disk_encrypted"}}
	out := UnansweredAgentRunningAsFailing(in, true)
	if want := []string{PolicyAgentBinaryKnown, "disk_encrypted"}; !slices.Equal(out.UnansweredPolicies, want) {
		t.Fatalf("unanswered %v, want %v", out.UnansweredPolicies, want)
	}
	if want := []ports.PolicyResult{{Key: "disk_encrypted", Passing: true}, {Key: PolicyAgentRunning}}; !slices.Equal(out.Policies, want) {
		t.Fatalf("policies %v, want %v", out.Policies, want)
	}
	if len(in.UnansweredPolicies) != 3 || len(in.Policies) != 1 {
		t.Fatalf("input changed: %+v", in)
	}
	if closed := UnansweredAgentRunningAsFailing(in, false); !slices.Equal(closed.UnansweredPolicies, in.UnansweredPolicies) ||
		!slices.Equal(closed.Policies, in.Policies) {
		t.Fatalf("gate closed: %+v", closed)
	}
	other := ports.HostInventory{UnansweredPolicies: []string{PolicyAgentBinaryKnown, "disk_encrypted"}}
	if got := UnansweredAgentRunningAsFailing(other, true); len(got.Policies) != 0 || len(got.UnansweredPolicies) != 2 {
		t.Fatalf("other keys moved: %+v", got)
	}
}
