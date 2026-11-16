// Package inventory holds Paddock's inventory policies (plan M5a decision 8) and the severity scale of
// vulnerability findings. Policies are osquery SQL that returns rows when a host passes; the inventory system turns
// the answer into pass or fail and never stores the rows. There is no NTP policy: osquery has no table for the time
// synchronization state on Linux.
package inventory

import (
	"embed"
	"io/fs"
	"log/slog"
	"path"
	"slices"
	"strings"

	"github.com/phischl/paddock-mdm/server/internal/ports"
)

//go:embed policies/*.sql
var policyFiles embed.FS

// PolicyAgentRunning is the key of the mutual watch policy: paddockd runs.
const PolicyAgentRunning = "paddock_agent_running"

// PolicyAgentBinaryKnown is the key of the agent binary hash policy (plan M5a amendment 2026-11-16, ADR 0056 part
// A): a running paddockd has the hash of a published agent release.
const PolicyAgentBinaryKnown = "paddock_agent_binary_known"

// isAgentHash reports whether h has the form of a published agent artifact hash, ^[0-9a-f]{64}$; only this form is
// ever interpolated into the policy.
func isAgentHash(h string) bool {
	if len(h) != 64 {
		return false
	}
	for _, c := range h {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// KnownAgentHashes returns the hashes the binary policy accepts: sorted, deduplicated, and only those of the form
// ^[0-9a-f]{64}$. Every other value is dropped and logged at Error, defense in depth before the values are put into
// SQL (the database already constrains agent_artifact.sha256).
func KnownAgentHashes(hashes []string) []string {
	out := make([]string, 0, len(hashes))
	for _, h := range hashes {
		if !isAgentHash(h) {
			slog.Error("dropping an invalid agent artifact hash from the binary policy", "length", len(h))
			continue
		}
		out = append(out, h)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// AgentBinaryPolicy builds the policy PolicyAgentBinaryKnown from the published agent artifact hashes: it fails
// only while a paddockd process runs from an A/B slot with its binary on disk and that binary's SHA-256 is none of
// the hashes. No paddockd running passes (that is paddock_agent_running's case), and so does a process whose binary
// was replaced by a rename (on_disk = 0; RR-149). With no valid hash the policy is SELECT 1;, which always passes.
func AgentBinaryPolicy(hashes []string) ports.PolicyDefinition {
	def := ports.PolicyDefinition{
		Key: PolicyAgentBinaryKnown,
		Description: "The running Paddock agent's binary matches a published agent release (plan M5a amendment " +
			"2026-11-16, ADR 0056). The policy returns pass or fail only, never a hash.",
		Query: "SELECT 1;",
	}
	known := KnownAgentHashes(hashes)
	if len(known) == 0 {
		return def
	}
	def.Query = "SELECT 1 WHERE NOT EXISTS (\n" +
		"  SELECT 1 FROM processes p LEFT JOIN hash h ON h.path = p.path\n" +
		"  WHERE p.name = 'paddockd' AND p.path LIKE '/opt/paddock/agent/%' AND p.on_disk = 1\n" +
		"    AND (h.sha256 IS NULL OR h.sha256 NOT IN ('" + strings.Join(known, "', '") + "')));"
	return def
}

// Policies returns Paddock's policies, sorted by key; the key is the file name, the description its leading comment.
func Policies() ([]ports.PolicyDefinition, error) {
	names, err := fs.Glob(policyFiles, "policies/*.sql")
	if err != nil {
		return nil, err
	}
	out := make([]ports.PolicyDefinition, 0, len(names))
	for _, name := range names {
		data, err := policyFiles.ReadFile(name)
		if err != nil {
			return nil, err
		}
		var comment, query []string
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if c, ok := strings.CutPrefix(line, "-- "); ok && len(query) == 0 {
				comment = append(comment, c)
				continue
			}
			query = append(query, line)
		}
		out = append(out, ports.PolicyDefinition{
			Key: strings.TrimSuffix(path.Base(name), ".sql"), Description: strings.Join(comment, " "),
			Query: strings.Join(query, "\n"),
		})
	}
	return out, nil
}

// Severities of vulnerability findings, from the CVSS v3 base score (NVD's qualitative rating).
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// Severity rates a CVSS v3 base score; "" for an unknown score (Fleet free reports none) or 0.
func Severity(score *float64) string {
	switch {
	case score == nil || *score <= 0:
		return ""
	case *score >= 9:
		return SeverityCritical
	case *score >= 7:
		return SeverityHigh
	case *score >= 4:
		return SeverityMedium
	default:
		return SeverityLow
	}
}
