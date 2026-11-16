package inventory

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
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
	want := "SELECT 1 WHERE NOT EXISTS (\n" +
		"  SELECT 1 FROM processes p LEFT JOIN hash h ON h.path = p.path\n" +
		"  WHERE p.name = 'paddockd' AND p.path LIKE '/opt/paddock/agent/%' AND p.on_disk = 1\n" +
		"    AND (h.sha256 IS NULL OR h.sha256 NOT IN ('" + a + "', '" + b + "')));"
	if p.Query != want {
		t.Fatalf("query\n%s\nwant\n%s", p.Query, want)
	}
	if p.Key != "paddock_agent_binary_known" {
		t.Fatalf("key %q", p.Key)
	}
	if !strings.Contains(p.Description, "never a hash") {
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
	if strings.Contains(p.Query, "DROP") || strings.Count(p.Query, "'") != 6 { // 'paddockd', the LIKE pattern, one hash
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
