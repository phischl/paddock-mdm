package devicesim

import (
	"strings"
	"testing"
)

// TestFleetHostAgentBinaryPolicy: with AgentBinarySHA256 set, the agent binary policy fails unless its query lists
// the hash; other policies, the always-passing SELECT 1; and a host without the hash pass.
func TestFleetHostAgentBinaryPolicy(t *testing.T) {
	known, other := strings.Repeat("a", 64), strings.Repeat("b", 64)
	binary := func(hash string) string {
		return "SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM processes p LEFT JOIN hash h ON h.path = p.path WHERE " +
			"h.sha256 NOT IN ('" + hash + "'));"
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
