package devicesim

import (
	"strings"
	"testing"
	"time"
)

// TestFleetHostAgentBinaryPolicy: with AgentBinarySHA256 set, the agent binary policy fails unless its query lists
// the hash; other policies, the always-passing SELECT 1; and a host without the hash pass.
func TestFleetHostAgentBinaryPolicy(t *testing.T) {
	known, other := strings.Repeat("a", 64), strings.Repeat("b", 64)
	binary := func(hash string) string {
		return "SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM processes p WHERE COALESCE((SELECT sha256 FROM hash WHERE " +
			"path = '/proc/' || p.pid || '/exe'), '') NOT IN ('" + hash + "'));"
	}
	for _, c := range []struct {
		name, hash, sql string
		pass            bool
	}{
		{"no hash set", "", binary(other), true},
		{"listed", known, binary(known), true},
		{"not listed", known, binary(other), false},
		{"no release", known, "SELECT 1;", true},
		{"another policy", known, "SELECT 1 FROM processes WHERE name = 'paddockd';", true},
	} {
		h := &FleetHost{AgentBinarySHA256: c.hash}
		if got := len(h.rows("fleet_policy_query_7", c.sql)) == 1; got != c.pass {
			t.Errorf("%s: pass %v, want %v", c.name, got, c.pass)
		}
	}
}

// TestFleetHostAgentNotRunning: with AgentNotRunning the agent-running policy fails; every other policy, including
// the agent binary policy, is answered as before, and without it the agent-running policy passes.
func TestFleetHostAgentNotRunning(t *testing.T) {
	known := strings.Repeat("a", 64)
	running := "SELECT 1 FROM processes WHERE name = 'paddockd' AND path LIKE '/opt/paddock/agent/%';"
	binary := "SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM processes p WHERE COALESCE((SELECT sha256 FROM hash WHERE " +
		"path = '/proc/' || p.pid || '/exe'), '') NOT IN ('" + known + "'));"
	for _, c := range []struct {
		name, sql  string
		notRunning bool
		pass       bool
	}{
		{"agent running", running, false, true},
		{"agent not running", running, true, false},
		{"binary policy while not running", binary, true, true},
		{"another policy while not running", "SELECT 1 FROM disk_encryption WHERE encrypted = 1;", true, true},
	} {
		h := &FleetHost{AgentBinarySHA256: known, AgentNotRunning: c.notRunning}
		if got := len(h.rows("fleet_policy_query_3", c.sql)) == 1; got != c.pass {
			t.Errorf("%s: pass %v, want %v", c.name, got, c.pass)
		}
	}
}

// TestFleetHostBinaryPolicyListedAt: a hash is noted the first time an agent binary policy lists it, never again and
// never from another query.
func TestFleetHostBinaryPolicyListedAt(t *testing.T) {
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	policy := func(hashes string) string {
		return "SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM processes p WHERE COALESCE((SELECT sha256 FROM hash WHERE " +
			"path = '/proc/' || p.pid || '/exe'), '') NOT IN (" + hashes + "));"
	}
	h := &FleetHost{}
	first := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	h.recordListed("SELECT '"+b+"';", first)
	h.recordListed(policy("'"+a+"'"), first)
	h.recordListed(policy("'"+a+"', '"+b+"'"), first.Add(time.Minute))
	if at, ok := h.BinaryPolicyListedAt(a); !ok || !at.Equal(first) {
		t.Fatalf("a listed at %v, %v; want the first time %v", at, ok, first)
	}
	if at, ok := h.BinaryPolicyListedAt(b); !ok || !at.Equal(first.Add(time.Minute)) {
		t.Fatalf("b listed at %v, %v; want when the policy first listed it", at, ok)
	}
	if _, ok := h.BinaryPolicyListedAt(strings.Repeat("c", 64)); ok {
		t.Fatal("a hash no policy listed is reported")
	}
}

// TestFleetHostAgentRunningQueryFails (plan M5a amendment 2026-11-16 d, F6): the agent-running query gets status 1
// and no rows; other queries are answered as before.
func TestFleetHostAgentRunningQueryFails(t *testing.T) {
	running := "SELECT 1 FROM processes WHERE name = 'paddockd' AND path LIKE '/opt/paddock/agent/%';"
	other := "SELECT 1 FROM disk_encryption WHERE encrypted = 1;"
	h := &FleetHost{AgentRunningQueryFails: true}
	if s, rows := h.status("fleet_policy_query_3", running), h.rows("fleet_policy_query_3", running); s != 1 || len(rows) != 0 {
		t.Fatalf("agent-running query: status %d, %d rows; want 1 and none", s, len(rows))
	}
	if s, rows := h.status("fleet_policy_query_4", other), h.rows("fleet_policy_query_4", other); s != 0 || len(rows) != 1 {
		t.Fatalf("another policy: status %d, %d rows", s, len(rows))
	}
	if s := h.status("fleet_detail_query_os_version", running); s != 0 {
		t.Fatalf("detail query status %d", s)
	}
	h.AgentRunningQueryFails = false
	if s, rows := h.status("fleet_policy_query_3", running), h.rows("fleet_policy_query_3", running); s != 0 || len(rows) != 1 {
		t.Fatalf("answering again: status %d, %d rows", s, len(rows))
	}
}
